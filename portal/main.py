"""FastAPI application: browser portal + machine-facing token/JWKS endpoints."""

from __future__ import annotations

import base64
import binascii
import logging
import secrets
from typing import Optional

from fastapi import FastAPI, Form, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import authz, db, tokens
from .auth import OIDCClient, current_user, login_user, logout_user
from .config import Settings, get_settings
from .keys import ensure_keys, load_keys

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
    ensure_keys(settings.signing_key_dir)
    keystore = load_keys(settings.signing_key_dir)

    app = FastAPI(title="Shoveler Auth Portal", docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.keystore = keystore
    app.state.oidc = OIDCClient(settings)
    app.state.rate_limiter = tokens.RateLimiter(
        settings.token_rate_limit, settings.token_rate_window
    )

    https_only = settings.portal_base_url.lower().startswith("https://")
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
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
        ctx.setdefault(
            "is_admin",
            authz.is_registry_admin(
                settings.registry_admin_group, user.groups if user else ()
            ),
        )
        return templates.TemplateResponse(request, name, ctx)

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

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard(request: Request):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        sites = authz.sites_for_groups(user.groups, settings.comanage_group_prefix)
        if not sites:
            return render(
                request,
                "not_authorized.html",
                admin_contact=settings.admin_contact,
            )
        conn = db.connect(settings.db_path)
        try:
            rows = db.list_clients_for_sites(conn, sites)
        finally:
            conn.close()
        by_site = {site: [] for site in sites}
        for row in rows:
            by_site[row["site"]].append(_client_view(row, settings.idle_days))
        return render(request, "dashboard.html", sites=sites, by_site=by_site)

    @app.get("/admin", response_class=HTMLResponse)
    def admin(request: Request):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        if not authz.is_registry_admin(settings.registry_admin_group, user.groups):
            _flash(request.session, "Not authorized for the admin view.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            rows = db.list_all_clients(conn)
        finally:
            conn.close()
        clients = [
            dict(_client_view(row, settings.idle_days), owner_email=row["owner_email"])
            for row in rows
        ]
        return render(request, "admin.html", clients=clients)

    @app.post("/admin/{client_id}/disable")
    def admin_disable(
        request: Request, client_id: str, csrf_token: str = Form(...)
    ):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        if not authz.is_registry_admin(settings.registry_admin_group, user.groups):
            _flash(request.session, "Not authorized for the admin view.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/admin", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            if db.get_client(conn, client_id) is None:
                _flash(request.session, "No such client.", "error")
                return RedirectResponse("/admin", status_code=303)
            db.disable_client(conn, client_id, "revoked-by-admin")
        finally:
            conn.close()
        _flash(request.session, f"Credential {client_id} disabled.", "info")
        return RedirectResponse("/admin", status_code=303)

    @app.post("/credentials/create")
    def credentials_create(
        request: Request, site: str = Form(...), csrf_token: str = Form(...)
    ):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        if not authz.may_manage_site(
            user.groups, settings.comanage_group_prefix, site
        ):
            _flash(request.session, "You may not manage that site.", "error")
            return RedirectResponse("/dashboard", status_code=303)

        client_id = tokens.generate_client_id()
        secret = tokens.generate_secret()
        conn = db.connect(settings.db_path)
        try:
            db.insert_client(
                conn,
                client_id=client_id,
                secret_hash=tokens.hash_secret(secret),
                site=site,
                owner_sub=user.sub,
                owner_email=user.email,
            )
        finally:
            conn.close()
        return render(
            request,
            "secret_once.html",
            client_id=client_id,
            secret=secret,
            site=site,
            snippet=_shoveler_snippet(settings, client_id, secret),
        )

    @app.post("/credentials/{client_id}/recreate")
    def credentials_recreate(
        request: Request, client_id: str, csrf_token: str = Form(...)
    ):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            row = db.get_client(conn, client_id)
            if not _owns(row, user, settings):
                _flash(request.session, "Not authorized for that credential.", "error")
                return RedirectResponse("/dashboard", status_code=303)
            secret = tokens.generate_secret()
            db.rotate_secret(conn, client_id, tokens.hash_secret(secret))
        finally:
            conn.close()
        return render(
            request,
            "secret_once.html",
            client_id=client_id,
            secret=secret,
            site=row["site"],
            recreated=True,
            snippet=_shoveler_snippet(settings, client_id, secret),
        )

    @app.post("/credentials/{client_id}/disable")
    def credentials_disable(
        request: Request, client_id: str, csrf_token: str = Form(...)
    ):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            row = db.get_client(conn, client_id)
            if not _owns(row, user, settings):
                _flash(request.session, "Not authorized for that credential.", "error")
                return RedirectResponse("/dashboard", status_code=303)
            db.disable_client(conn, client_id, "revoked-by-owner")
        finally:
            conn.close()
        _flash(request.session, f"Credential {client_id} disabled.", "info")
        return RedirectResponse("/dashboard", status_code=303)

    # --- Machine-facing routes ------------------------------------------

    @app.post("/token")
    async def token_endpoint(request: Request):
        form = await request.form()
        grant_type = form.get("grant_type")
        client_id = form.get("client_id")
        client_secret = form.get("client_secret")

        # HTTP Basic per RFC 6749 takes precedence if present.
        basic = _parse_basic_auth(request.headers.get("authorization"))
        if basic:
            client_id, client_secret = basic

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
                    grant_type=grant_type,
                    client_id=client_id,
                    client_secret=client_secret,
                )
            except tokens.TokenError as exc:
                return JSONResponse({"error": exc.error}, status_code=exc.status)
        finally:
            conn.close()
        return JSONResponse(
            result.as_dict(), headers={"Cache-Control": "no-store", "Pragma": "no-cache"}
        )

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
                "grant_types_supported": ["client_credentials"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post",
                ],
            }
        )

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz():
        return "ok"

    return app


# Run with uvicorn in factory mode:  uvicorn --factory portal.main:create_app


# --- Module helpers ------------------------------------------------------

def _owns(row, user, settings: Settings) -> bool:
    """Owner-only: sub matches owner AND the user may manage that site."""
    if row is None:
        return False
    if row["owner_sub"] != user.sub:
        return False
    return authz.may_manage_site(
        user.groups, settings.comanage_group_prefix, row["site"]
    )


def _client_view(row, idle_days: int) -> dict:
    from datetime import datetime, timezone

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
        "created_at": row["created_at"],
        "last_used_at": row["last_used_at"],
        "status": status,
        "disabled_reason": row["disabled_reason"],
    }


def _parse_basic_auth(header: Optional[str]) -> Optional[tuple[str, str]]:
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(header.split(" ", 1)[1], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, IndexError):
        return None
    if ":" not in raw:
        return None
    cid, secret = raw.split(":", 1)
    return cid, secret


def _shoveler_snippet(settings: Settings, client_id: str, secret: str) -> str:
    token_endpoint = settings.portal_base_url.rstrip("/") + "/token"
    return (
        "# xrootd-monitoring-shoveler config.yaml\n"
        "# Credentials issued by the Shoveler Auth Portal (client_credentials).\n"
        "mq: amqp\n"
        "amqp:\n"
        "  # adjust host/exchange to your RabbitMQ deployment\n"
        "  url: amqps://your-rabbit-host:5671\n"
        "  exchange: shoveled\n"
        "  token:\n"
        f'    client_id: "{client_id}"\n'
        f'    client_secret: "{secret}"\n'
        f'    token_endpoint: "{token_endpoint}"\n'
    )
