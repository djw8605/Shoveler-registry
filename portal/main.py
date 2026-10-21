"""FastAPI application: browser portal + machine-facing token/JWKS endpoints."""

from __future__ import annotations

import json
import logging
import secrets
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import authz, db, health, registration, tokens
from .auth import OIDCClient, current_user, login_user, logout_user
from .config import Settings, get_settings
from .keys import (
    ensure_keys,
    load_external_key,
    load_keys,
    load_or_create_session_secret,
)

log = logging.getLogger("portal.main")

TEMPLATES_DIR = __file__.rsplit("/", 1)[0] + "/templates"
STATIC_DIR = __file__.rsplit("/", 1)[0] + "/static"


# --- CSRF helpers --------------------------------------------------------

def _csrf_token(session) -> str:
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def _check_csrf(session, submitted: Optional[str]) -> bool:
    expected = session.get("csrf")
    return bool(expected) and bool(submitted) and secrets.compare_digest(
        expected, submitted
    )


def _flash(session, message: str, level: str = "info") -> None:
    session.setdefault("_flash", []).append({"message": message, "level": level})


def _pop_flashes(session) -> list[dict]:
    msgs = session.pop("_flash", [])
    return msgs


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or get_settings()

    # Initialise persistent state before serving.
    db.init_db(settings.db_path)
    if settings.signing_key_file:
        keystore = load_external_key(
            settings.signing_key_file, settings.signing_key_id or None
        )
    else:
        ensure_keys(settings.signing_key_dir)
        keystore = load_keys(settings.signing_key_dir)

    app = FastAPI(title="Shoveler Auth Portal", docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.keystore = keystore
    app.state.oidc = OIDCClient(settings)
    app.state.rate_limiter = tokens.RateLimiter(
        settings.token_rate_limit, settings.token_rate_window
    )
    app.state.register_rate_limiter = tokens.RateLimiter(
        settings.register_rate_limit, settings.register_rate_window
    )
    app.state.report_rate_limiter = tokens.RateLimiter(
        settings.report_rate_limit, settings.report_rate_window
    )

    https_only = settings.portal_base_url.lower().startswith("https://")
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret
        or load_or_create_session_secret(settings.signing_key_dir),
        same_site="lax",
        https_only=https_only,
        session_cookie="portal_session",
    )

    templates = Jinja2Templates(directory=TEMPLATES_DIR)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    def render(request: Request, name: str, **ctx) -> HTMLResponse:
        user = ctx.setdefault("user", current_user(request.session))
        ctx.setdefault("csrf_token", _csrf_token(request.session))
        ctx.setdefault("flashes", _pop_flashes(request.session))
        ctx.setdefault("portal_name", "Shoveler Auth")
        return templates.TemplateResponse(request, name, ctx)

    def admin_user(request: Request):
        """The logged-in admin, or None if not logged in / not in ADMIN_GROUP."""
        user = current_user(request.session)
        if user and authz.is_admin(settings.admin_group, user.groups):
            return user
        return None

    def refuse(request: Request) -> RedirectResponse:
        """Response for a browser POST from anyone who isn't a logged-in admin."""
        if current_user(request.session):
            _flash(request.session, "Not authorized.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        return RedirectResponse("/", status_code=303)

    # --- Browser routes --------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        if current_user(request.session):
            return RedirectResponse("/dashboard", status_code=303)
        return render(request, "login.html")

    @app.get("/auth/login")
    def auth_login(request: Request):
        url, transient = app.state.oidc.authorization_url()
        request.session["oidc"] = transient
        return RedirectResponse(url, status_code=303)

    @app.get("/auth/callback")
    def auth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        transient = request.session.pop("oidc", None)
        if error:
            _flash(request.session, f"CILogon returned an error: {error}", "error")
            return RedirectResponse("/", status_code=303)
        if not transient or not code or not secrets.compare_digest(
            transient.get("state", ""), state
        ):
            _flash(request.session, "Login state mismatch; please try again.", "error")
            return RedirectResponse("/", status_code=303)
        try:
            user = app.state.oidc.exchange_code(
                code, transient["code_verifier"], transient["nonce"]
            )
        except Exception as exc:  # noqa: BLE001 - surface a friendly message
            log.warning("OIDC callback failed: %s", exc)
            _flash(request.session, "Login failed; please try again.", "error")
            return RedirectResponse("/", status_code=303)
        login_user(request.session, user)
        return RedirectResponse("/dashboard", status_code=303)

    @app.get("/auth/logout")
    def auth_logout(request: Request):
        logout_user(request.session)
        return RedirectResponse("/", status_code=303)

    # Everything below is for members of ADMIN_GROUP only. Each POST checks
    # admin, then CSRF, then acts, and redirects back to the dashboard.

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        if not admin_user(request):
            return render(
                request, "not_authorized.html", admin_contact=settings.admin_contact
            )
        now = datetime.now(timezone.utc)
        hours = settings.metrics_retention_hours
        conn = db.connect(settings.db_path)
        try:
            pending = [_pending_view(r) for r in db.list_pending_clients(conn)]
            reg_tokens = [_token_view(r) for r in db.list_registration_tokens(conn)]
            client_rows = db.list_all_clients(conn)
            known_sites = db.list_known_sites(conn)
            latest = db.latest_reports(conn)
            # The last hour is plenty for health and the current rate; the
            # trackers are bucketed in SQL.
            recent: dict[str, list] = {}
            for r in db.list_reports(conn, db.to_iso(now - timedelta(hours=1))):
                recent.setdefault(r["client_id"], []).append(r)
            blocks = health.trackers(conn, now, hours, latest)
            fleet = []
            for r in client_rows:
                if r["disabled"]:
                    continue
                cid = r["client_id"]
                rows = recent.get(cid, [])
                view = _health_view(r, latest.get(cid), rows, now, blocks.get(cid, []),
                                    settings.token_ttl_seconds)
                since = view["health"].since
                if view["health"].status in ("no-packets", "not-publishing") and rows \
                        and since <= db.parse_ts(rows[0]["received_at"]):
                    # The problem predates the last hour: date it from the window.
                    rows = db.list_reports(conn, db.to_iso(now - timedelta(hours=hours)), cid)
                    view = _health_view(r, latest.get(cid), rows, now, view["blocks"],
                                        settings.token_ttl_seconds)
                fleet.append(view)
        finally:
            conn.close()
        fleet.sort(key=lambda h: (HEALTH_ORDER[h["health"].status], h["site"], h["host"]))
        return render(
            request,
            "dashboard.html",
            pending=pending,
            reg_tokens=reg_tokens,
            clients=[_client_view(r, settings.idle_days) for r in client_rows],
            known_sites=known_sites,
            fleet=fleet,
            fleet_counts=Counter(h["health"].status for h in fleet),
            disabled_count=sum(1 for r in client_rows if r["disabled"]),
            labels=health.LABELS,
            hours=hours,
            updated=health.clock(now, now),
        )

    @app.get("/shovelers/{client_id}", response_class=HTMLResponse)
    def shoveler_detail(request: Request, client_id: str, hours: str = ""):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        if not admin_user(request):
            return render(
                request, "not_authorized.html", admin_contact=settings.admin_contact
            )
        now = datetime.now(timezone.utc)
        retention = settings.metrics_retention_hours
        # The charts can zoom to the last couple of hours; the tracker always
        # spans the whole retention window.
        ranges = sorted({min(CHART_ZOOM_HOURS, retention), retention})
        chart_hours = int(hours) if hours.isdigit() and int(hours) in ranges else retention
        conn = db.connect(settings.db_path)
        try:
            row = db.get_client(conn, client_id)
            if row is None or row["pending"]:
                _flash(request.session, "No such shoveler.", "error")
                return RedirectResponse("/dashboard", status_code=303)
            latest = db.latest_report(conn, client_id)
            rows = db.list_reports(
                conn, db.to_iso(now - timedelta(hours=retention)), client_id
            )
            blocks = health.trackers(
                conn, now, retention, {client_id: latest} if latest else {}, client_id
            )[client_id]
        finally:
            conn.close()
        start = now - timedelta(hours=chart_hours)
        chart_rows = [r for r in rows if db.parse_ts(r["received_at"]) >= start]
        return render(
            request,
            "shoveler.html",
            client=_client_view(row, settings.idle_days),
            shoveler=_health_view(row, latest, rows, now, blocks, settings.token_ttl_seconds),
            latest=latest,
            totals=health.totals(rows),
            restarts=health.restarts(rows),
            series=health.series(chart_rows, start, now),
            hourly=health.hourly(chart_rows, now, chart_hours),
            hours=retention,
            chart_hours=chart_hours,
            ranges=ranges,
            labels=health.LABELS,
            now=now,
            updated=health.clock(now, now),
        )

    @app.post("/pending/{client_id}/approve")
    def pending_approve(
        request: Request,
        client_id: str,
        site: str = Form(""),
        csrf_token: str = Form(...),
    ):
        user = admin_user(request)
        if not user:
            return refuse(request)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        site = _site_label(site)
        if not site:
            _flash(request.session, "Enter a site name to approve into.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            ok = db.approve_client(
                conn, client_id, site=site, owner_sub=user.sub, owner_email=user.email
            )
        finally:
            conn.close()
        if ok:
            _flash(request.session, f"Approved {client_id} for {site}.", "info")
        else:
            _flash(request.session, "That shoveler is no longer pending.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/pending/{client_id}/reject")
    def pending_reject(request: Request, client_id: str, csrf_token: str = Form(...)):
        if not admin_user(request):
            return refuse(request)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            ok = db.delete_pending_client(conn, client_id)
        finally:
            conn.close()
        if ok:
            _flash(request.session, f"Rejected {client_id}.", "info")
        else:
            _flash(request.session, "That shoveler is no longer pending.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/registration-tokens")
    def registration_token_create(
        request: Request, site: str = Form(""), csrf_token: str = Form(...)
    ):
        user = admin_user(request)
        if not user:
            return refuse(request)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        site = _site_label(site)
        if not site:
            _flash(request.session, "Enter a site name for the token.", "error")
            return RedirectResponse("/dashboard", status_code=303)

        token = tokens.generate_registration_token()
        expires_at = db.to_iso(
            datetime.now(timezone.utc)
            + timedelta(seconds=settings.registration_token_ttl_seconds)
        )
        conn = db.connect(settings.db_path)
        try:
            db.insert_registration_token(
                conn,
                token_hash=tokens.hash_registration_token(token),
                site=site,
                owner_sub=user.sub,
                owner_email=user.email,
                expires_at=expires_at,
            )
        finally:
            conn.close()
        return render(
            request,
            "registration_token.html",
            token=token,
            expires_at=expires_at,
            site=site,
            token_file=BOOTSTRAP_TOKEN_FILE,
            shoveler_user=SHOVELER_USER,
            snippet=_shoveler_snippet(settings),
        )

    @app.post("/registration-tokens/{token_hash}/revoke")
    def registration_token_revoke(
        request: Request, token_hash: str, csrf_token: str = Form(...)
    ):
        if not admin_user(request):
            return refuse(request)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            ok = db.revoke_registration_token(conn, token_hash)
        finally:
            conn.close()
        if ok:
            _flash(request.session, "Registration token revoked.", "info")
        else:
            _flash(request.session, "That token was already used or revoked.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    @app.post("/credentials/{client_id}/disable")
    def credentials_disable(
        request: Request, client_id: str, csrf_token: str = Form(...), next: str = Form("")
    ):
        if not admin_user(request):
            return refuse(request)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            row = db.get_client(conn, client_id)
            if row is None or row["pending"]:
                _flash(request.session, "No such shoveler.", "error")
                return RedirectResponse("/dashboard", status_code=303)
            db.disable_client(conn, client_id, DISABLED_BY_ADMIN)
        finally:
            conn.close()
        _flash(request.session, f"Shoveler {client_id} disabled.", "info")
        return RedirectResponse(_back(next, client_id), status_code=303)

    @app.post("/credentials/{client_id}/enable")
    def credentials_enable(
        request: Request, client_id: str, csrf_token: str = Form(...), next: str = Form("")
    ):
        if not admin_user(request):
            return refuse(request)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            row = db.get_client(conn, client_id)
            if row is None or row["pending"] or not row["disabled"]:
                _flash(request.session, "That shoveler isn't disabled.", "error")
                return RedirectResponse("/dashboard", status_code=303)
            db.enable_client(conn, client_id)
        finally:
            conn.close()
        _flash(request.session, f"Shoveler {client_id} re-enabled.", "info")
        return RedirectResponse(_back(next, client_id), status_code=303)

    # --- Machine-facing routes ------------------------------------------

    @app.post("/token")
    async def token_endpoint(request: Request):
        form = await request.form()
        assertion = form.get("client_assertion")
        if not isinstance(assertion, str):  # absent, or a multipart file part
            assertion = None
        # Unverified; only used to key the limiter (issue_token verifies).
        client_id = tokens.assertion_subject(assertion)

        if client_id and not app.state.rate_limiter.check(client_id):
            return JSONResponse(
                {"error": "invalid_client"},
                status_code=429,
                headers={"Retry-After": str(settings.token_rate_window)},
            )

        conn = db.connect(settings.db_path)
        try:
            try:
                result = tokens.issue_token(
                    conn,
                    settings,
                    app.state.keystore,
                    grant_type=form.get("grant_type"),
                    client_assertion_type=form.get("client_assertion_type"),
                    client_assertion=assertion,
                )
            except tokens.TokenError as exc:
                return JSONResponse({"error": exc.error}, status_code=exc.status)
        finally:
            conn.close()
        return JSONResponse(
            result.as_dict(), headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
        )

    @app.post("/register")
    async def register_endpoint(request: Request):
        # Keyed by client IP; behind the ingress, uvicorn's --proxy-headers
        # (FORWARDED_ALLOW_IPS) supplies the real client address here.
        ip = request.client.host if request.client else "unknown"
        if not app.state.register_rate_limiter.check(ip):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(settings.register_rate_window)},
            )
        try:
            body = await request.json()
        except ValueError:
            body = None
        conn = db.connect(settings.db_path)
        try:
            result = registration.register(
                conn,
                settings,
                authorization=request.headers.get("authorization"),
                body=body,
                registered_ip=ip,
            )
        except registration.RegistrationError as exc:
            headers = {"Cache-Control": "no-store"}
            if exc.status == 401:
                headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
            if exc.status == 503:
                headers["Retry-After"] = "300"
            return JSONResponse(exc.as_dict(), status_code=exc.status, headers=headers)
        finally:
            conn.close()
        return JSONResponse(
            result, status_code=201, headers={"Cache-Control": "no-store"}
        )

    @app.post("/report")
    async def report_endpoint(request: Request):
        """A shoveler's periodic health report, sent with its access token."""
        no_store = {"Cache-Control": "no-store"}
        bearer = registration.parse_bearer(request.headers.get("authorization"))
        conn = db.connect(settings.db_path)
        try:
            try:
                if not bearer:
                    raise tokens.TokenError(401, "invalid_token")
                client = tokens.verify_access_token(
                    conn, settings, app.state.keystore, bearer
                )
            except tokens.TokenError as exc:
                return JSONResponse(
                    {"error": exc.error},
                    status_code=exc.status,
                    headers={**no_store, "WWW-Authenticate": 'Bearer error="invalid_token"'},
                )
            client_id = client["client_id"]
            if not app.state.report_rate_limiter.check(client_id):
                return JSONResponse(
                    {"error": "invalid_request", "error_description": "rate limit exceeded"},
                    status_code=429,
                    headers={**no_store, "Retry-After": str(settings.report_rate_window)},
                )
            body = await _read_capped(request, MAX_REPORT_BYTES)
            try:
                if body is None:
                    raise health.ReportError("report too large")
                report = health.parse_report(json.loads(body))
            except ValueError:
                return JSONResponse(
                    health.ReportError("request body must be JSON").as_dict(),
                    status_code=400,
                    headers=no_store,
                )
            except health.ReportError as exc:
                return JSONResponse(exc.as_dict(), status_code=400, headers=no_store)
            now = datetime.now(timezone.utc)
            db.insert_report(
                conn,
                client_id=client_id,
                received_at=db.to_iso(now),
                started_at=report.started_at,
                interval_seconds=report.interval_seconds,
                version=report.version,
                metrics=report.metrics,
                purge_before=db.to_iso(
                    now - timedelta(hours=settings.metrics_retention_hours)
                ),
            )
        finally:
            conn.close()
        return Response(status_code=204, headers=no_store)

    @app.get("/.well-known/jwks.json")
    def jwks(request: Request):
        return JSONResponse(app.state.keystore.jwks())

    @app.get("/.well-known/openid-configuration")
    def discovery(request: Request):
        base = settings.token_issuer.rstrip("/")
        return JSONResponse(
            {
                # Minimal metadata so RabbitMQ can discover the JWKS from the
                # issuer. This service is a client-credentials token issuer, not
                # a full OIDC provider (no authorize endpoint, no ID tokens), so
                # we advertise only what applies.
                "issuer": settings.token_issuer,
                "jwks_uri": base + "/.well-known/jwks.json",
                "token_endpoint": base + "/token",
                "registration_endpoint": base + "/register",
                "grant_types_supported": ["client_credentials"],
                "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
            }
        )

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz():
        return "ok"

    return app


# Run with uvicorn in factory mode:  uvicorn --factory portal.main:create_app


# --- Module helpers ------------------------------------------------------

# disabled_reason written when an admin disables a shoveler ("idle" comes
# from the expire job). Admins may re-enable either.
DISABLED_BY_ADMIN = "disabled-by-admin"

# Where the one-time page tells operators to put the registration token (the
# shoveler's amqp.oauth.bootstrap_token_file): its state directory, which its
# packages create for the service user and where it keeps its key,
# registration state and access token.
SHOVELER_USER = "xrootd-monitoring-shoveler"
BOOTSTRAP_TOKEN_FILE = "/var/lib/xrootd-monitoring-shoveler/bootstrap.token"

# Longest site label an admin may enter.
SITE_MAX_LEN = 100

# A health report is a few hundred bytes; refuse anything far larger.
MAX_REPORT_BYTES = 16 * 1024


async def _read_capped(request: Request, limit: int) -> Optional[bytes]:
    """The request body, or None once it grows past ``limit`` bytes."""
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            return None
    return body


def _back(next_url: str, client_id: str) -> str:
    """Where a disable/re-enable returns to: the shoveler's page if it came
    from there, else the dashboard (never an arbitrary URL)."""
    page = f"/shovelers/{client_id}"
    return page if next_url == page else "/dashboard"


def _site_label(value: str) -> str:
    """A site is a display label typed by an admin; it grants no access."""
    value = (value or "").strip()
    return value if len(value) <= SITE_MAX_LEN else ""


def _pending_view(row) -> dict:
    return {
        "client_id": row["client_id"],
        "client_name": row["client_name"],
        "thumbprint": row["key_thumbprint"][:12],
        "registered_ip": row["registered_ip"],
        "created_at": row["created_at"],
    }


def _client_view(row, idle_days: int) -> dict:
    if row["disabled"]:
        status = "disabled"
    else:
        ref = row["last_used_at"] or row["created_at"]
        try:
            ref_dt = db.parse_ts(ref)
            age_days = (datetime.now(timezone.utc) - ref_dt).total_seconds() / 86400
            status = "idle" if age_days >= idle_days else "active"
        except (ValueError, TypeError):
            status = "active"
    return {
        "client_id": row["client_id"],
        "site": row["site"],
        "client_name": row["client_name"],
        "thumbprint": row["key_thumbprint"][:12],
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
        "status": status,
        "disabled_reason": row["disabled_reason"],
        "owner_email": row["owner_email"],
    }


# Health card order: what needs attention first.
HEALTH_ORDER = {status: i for i, status in enumerate(health.LABELS)}

# The shorter range a shoveler page's charts can zoom to.
CHART_ZOOM_HOURS = 2


def _health_view(client, latest, rows, now: datetime, blocks, token_ttl: int) -> dict:
    """A shoveler's health from its latest report, its recent reports
    (oldest first) and its tracker blocks."""
    status = health.assess(latest, rows, now)
    stale = status.status == "not-reporting"
    runs = health.pin_onset(health.runs(blocks), status)
    name = client["client_name"] or client["client_id"]
    # Without a current token a shoveler can neither publish nor report, and
    # only this registry knows when it last got one.
    token_hint = ""
    if status.status in ("not-publishing", "not-reporting") and client["last_used_at"]:
        expired = db.parse_ts(client["last_used_at"]) + timedelta(seconds=token_ttl)
        if expired < now:
            token_hint = (f"Its newest token from this registry expired at "
                          f"{health.clock(expired, now)}.")
    return {
        "client_id": client["client_id"],
        "site": client["site"],
        "name": name,
        # The shoveler names itself shoveler@<host>; the host is what tells
        # several shovelers at one site apart.
        "host": name.removeprefix("shoveler@"),
        "health": status,
        "token_hint": token_hint,
        # Not reporting: the last values it sent, shown as such.
        "stale": stale,
        "rates": health.current(rows),
        "queue": latest["queue_size"] if latest else None,
        "as_of": health.clock(db.parse_ts(latest["received_at"]), now) if latest else None,
        "last_report": health.ago(now - db.parse_ts(latest["received_at"])) if latest else None,
        "uptime": health.ago(now - db.parse_ts(latest["started_at"])) if latest and not stale else None,
        "blocks": blocks,
        "runs": runs,
        "described": health.describe(runs, now) if runs else "",
    }


def _token_view(row) -> dict:
    if row["revoked"]:
        status = "revoked"
    elif row["used_at"]:
        status = "used"
    elif db.parse_ts(row["expires_at"]) <= datetime.now(timezone.utc):
        status = "expired"
    else:
        status = "unused"
    return {
        "token_hash": row["token_hash"],
        "site": row["site"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "client_id": row["client_id"],
        "owner_email": row["owner_email"],
        "status": status,
    }


def _shoveler_snippet(settings: Settings) -> str:
    # No client_name: the shoveler's default (shoveler@<hostname>) tells
    # several shovelers at one site apart.
    base = settings.portal_base_url.rstrip("/")
    return (
        "# xrootd-monitoring-shoveler config.yaml (merge into your amqp: section)\n"
        "amqp:\n"
        "  oauth:\n"
        "    enabled: true\n"
        f"    token_url: {base}/token\n"
        f"    registration_url: {base}/register\n"
        f"    bootstrap_token_file: {BOOTSTRAP_TOKEN_FILE}\n"
    )
