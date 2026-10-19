"""FastAPI application: browser portal + machine-facing token/JWKS endpoints."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
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

from . import authz, db, registration, tokens
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
    app.state.register_rate_limiter = tokens.RateLimiter(
        settings.register_rate_limit, settings.register_rate_window
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
        sites = authz.sites_for_groups(
            user.groups,
            settings.comanage_group_prefix,
            admin_group=settings.registry_admin_group,
        )
        if not sites:
            return render(
                request,
                "not_authorized.html",
                admin_contact=settings.admin_contact,
            )
        conn = db.connect(settings.db_path)
        try:
            rows = db.list_clients_for_sites(conn, sites)
            token_rows = db.list_registration_tokens_for_sites(conn, sites)
        finally:
            conn.close()
        by_site = {site: [] for site in sites}
        for row in rows:
            by_site[row["site"]].append(_client_view(row, settings.idle_days))
        tokens_by_site = {site: [] for site in sites}
        for row in token_rows:
            tokens_by_site[row["site"]].append(_token_view(row))
        return render(
            request,
            "dashboard.html",
            sites=sites,
            by_site=by_site,
            tokens_by_site=tokens_by_site,
        )

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

    @app.post("/registration-tokens")
    def registration_token_create(
        request: Request, site: str = Form(...), csrf_token: str = Form(...)
    ):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        if not authz.may_manage_site(
            user.groups,
            settings.comanage_group_prefix,
            site,
            admin_group=settings.registry_admin_group,
        ):
            _flash(request.session, "You may not manage that site.", "error")
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
            snippet=_shoveler_snippet(settings, site),
        )

    @app.post("/registration-tokens/{token_hash}/revoke")
    def registration_token_revoke(
        request: Request, token_hash: str, csrf_token: str = Form(...)
    ):
        user = current_user(request.session)
        if not user:
            return RedirectResponse("/", status_code=303)
        if not _check_csrf(request.session, csrf_token):
            _flash(request.session, "Invalid CSRF token.", "error")
            return RedirectResponse("/dashboard", status_code=303)
        conn = db.connect(settings.db_path)
        try:
            row = db.get_registration_token(conn, token_hash)
            # Any manager of the token's site may revoke it (not just its
            # creator), e.g. if it leaked or the creator has left.
            if row is None or not authz.may_manage_site(
                user.groups,
                settings.comanage_group_prefix,
                row["site"],
                admin_group=settings.registry_admin_group,
            ):
                _flash(request.session, "Not authorized for that token.", "error")
                return RedirectResponse("/dashboard", status_code=303)
            if not db.revoke_registration_token(conn, token_hash):
                _flash(request.session, "That token was already used or revoked.", "error")
                return RedirectResponse("/dashboard", status_code=303)
        finally:
            conn.close()
        _flash(request.session, "Registration token revoked.", "info")
        return RedirectResponse("/dashboard", status_code=303)

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

    @app.post("/credentials/{client_id}/enable")
    def credentials_enable(
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
            if not _can_reenable(row):
                # An admin revocation may mean a compromised key: recovery is a
                # new registration token (and so a new client and key).
                _flash(
                    request.session,
                    "This credential can't be re-enabled; create a new registration token.",
                    "error",
                )
                return RedirectResponse("/dashboard", status_code=303)
            db.enable_client(conn, client_id)
        finally:
            conn.close()
        _flash(request.session, f"Credential {client_id} re-enabled.", "info")
        return RedirectResponse("/dashboard", status_code=303)

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

def _owns(row, user, settings: Settings) -> bool:
    """Owner-only: sub matches owner AND the user may manage that site."""
    if row is None:
        return False
    if row["owner_sub"] != user.sub:
        return False
    return authz.may_manage_site(
        user.groups,
        settings.comanage_group_prefix,
        row["site"],
        admin_group=settings.registry_admin_group,
    )


# Disabled reasons the owner may undo. "revoked-by-admin" is deliberately
# absent: it may mean a compromised key, so recovery is a new registration.
REENABLE_REASONS = {"idle", "revoked-by-owner"}

# Where the one-time page tells operators to put the registration token (the
# shoveler's amqp.oauth.bootstrap_token_file). Its key and registration state
# are persisted alongside, under the same directory.
BOOTSTRAP_TOKEN_FILE = "/etc/xrootd-monitoring-shoveler/oauth/bootstrap.token"


def _can_reenable(row) -> bool:
    return bool(row["disabled"]) and row["disabled_reason"] in REENABLE_REASONS


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
        "can_reenable": _can_reenable(row),
    }


def _token_view(row) -> dict:
    if row["revoked"]:
        status = "revoked"
    elif row["used_at"]:
        status = "used"
    elif db.parse_ts(row["expires_at"]) <= datetime.now(timezone.utc):
        status = "expired"
    else:
        status = "pending"
    return {
        "token_hash": row["token_hash"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "client_id": row["client_id"],
        "owner_email": row["owner_email"],
        "status": status,
    }


def _shoveler_snippet(settings: Settings, site: str) -> str:
    base = settings.portal_base_url.rstrip("/")
    return (
        "# xrootd-monitoring-shoveler config.yaml (merge into your amqp: section)\n"
        "amqp:\n"
        "  oauth:\n"
        "    enabled: true\n"
        f"    token_url: {base}/token\n"
        f"    registration_url: {base}/register\n"
        f"    bootstrap_token_file: {BOOTSTRAP_TOKEN_FILE}\n"
        f"    client_name: {site}\n"
    )
