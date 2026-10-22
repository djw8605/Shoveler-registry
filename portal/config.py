"""Runtime configuration, loaded once from the environment.

Naming note: ``CILOGON_*`` are the portal's OWN credentials as an OIDC client
registered with CILogon (used to log humans in). They are entirely distinct
from the shoveler ``client_id``/``client_secret`` pairs this service issues.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


def _bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None or not val.strip():
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _require(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Required environment variable {name} is not set")
    return val


@dataclass(frozen=True)
class Settings:
    # --- Portal's CILogon (OIDC relying party) credentials ---
    cilogon_client_id: str
    cilogon_client_secret: str
    cilogon_discovery_url: str
    portal_base_url: str

    # --- Sessions ---
    # Signs session cookies. Empty: generated once and kept beside the
    # signing keys (keys.load_or_create_session_secret).
    session_secret: str

    # --- Storage ---
    db_path: str
    signing_key_dir: str
    # Optional operator-supplied signing key (PEM) and its kid. When set, it
    # signs all access tokens and is the only key in the JWKS (e.g. the key
    # RabbitMQ already trusts); otherwise keys are generated in signing_key_dir.
    signing_key_file: str
    signing_key_id: str

    # --- Issued-token claims (must match RabbitMQ's expectations) ---
    token_issuer: str
    resource_server_id: str
    token_ttl_seconds: int
    scope_claim: str
    scope_value: str

    # --- Operational ---
    idle_days: int
    admin_contact: str
    token_rate_limit: int
    token_rate_window: int

    # --- Shoveler self-registration ---
    # Lifetime of a one-time registration token minted on the dashboard.
    registration_token_ttl_seconds: int
    # Per-client-IP rate limit on /register: N requests per window seconds.
    register_rate_limit: int
    register_rate_window: int
    # Reject client assertions whose exp is further than this in the future.
    assertion_max_lifetime_seconds: int
    # Token-less registration: a shoveler that registers without a token is
    # held as pending until an admin approves it.
    allow_pending_registration: bool
    # At most this many pending clients at once (bounds open registration).
    max_pending_clients: int
    # Pending clients not approved within this long are deleted (expire job).
    pending_client_ttl_seconds: int

    # --- Shoveler health reports (POST /report) ---
    # Reports are kept this long (each shoveler's latest one is kept longer, so
    # "last report" survives); the dashboard charts this window.
    metrics_retention_hours: int
    # Per-client_id rate limit on /report: N requests per window seconds.
    report_rate_limit: int
    report_rate_window: int

    # --- Authorization ---
    # Members of this COmanage group (CILogon ``isMemberOf`` claim) are admins:
    # they approve shovelers, mint registration tokens, and disable/re-enable
    # shovelers. ADMIN_SUBS (below) adds individual admins by CILogon sub.
    admin_group: str
    # CILogon subs (exact) that are admins regardless of groups: a stopgap
    # allow-list for when group claims aren't released to this client.
    admin_subs: tuple[str, ...]

    @property
    def redirect_uri(self) -> str:
        return self.portal_base_url.rstrip("/") + "/auth/callback"

    @property
    def token_endpoint_audiences(self) -> frozenset[str]:
        """Accepted ``aud`` values for client assertions at /token (exact match)."""
        return frozenset(
            {
                self.portal_base_url.rstrip("/") + "/token",
                self.token_issuer.rstrip("/") + "/token",
                self.token_issuer,
            }
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        cilogon_client_id=_require("CILOGON_CLIENT_ID"),
        cilogon_client_secret=_require("CILOGON_CLIENT_SECRET"),
        cilogon_discovery_url=os.environ.get(
            "CILOGON_DISCOVERY_URL",
            "https://cilogon.org/.well-known/openid-configuration",
        ),
        portal_base_url=_require("PORTAL_BASE_URL"),
        # Optional: when unset, create_app generates one on the data volume.
        session_secret=os.environ.get("SESSION_SECRET", ""),
        db_path=os.environ.get("DB_PATH", "./data/portal.db"),
        signing_key_dir=os.environ.get("SIGNING_KEY_DIR", "./data/keys"),
        signing_key_file=os.environ.get("SIGNING_KEY_FILE", "").strip(),
        signing_key_id=os.environ.get("SIGNING_KEY_ID", "").strip(),
        token_issuer=_require("TOKEN_ISSUER"),
        resource_server_id=_require("RESOURCE_SERVER_ID"),
        token_ttl_seconds=int(os.environ.get("TOKEN_TTL_SECONDS", "14400")),
        scope_claim=os.environ.get("SCOPE_CLAIM", "scope"),
        scope_value=os.environ.get(
            "SCOPE_VALUE", "my_rabbit_server.write:xrd-mon/shoveled-xrd"
        ),
        idle_days=int(os.environ.get("IDLE_DAYS", "30")),
        admin_contact=os.environ.get("ADMIN_CONTACT", "your central admin"),
        token_rate_limit=int(os.environ.get("TOKEN_RATE_LIMIT", "30")),
        token_rate_window=int(os.environ.get("TOKEN_RATE_WINDOW", "60")),
        registration_token_ttl_seconds=int(
            os.environ.get("REGISTRATION_TOKEN_TTL_SECONDS", "259200")
        ),
        register_rate_limit=int(os.environ.get("REGISTER_RATE_LIMIT", "10")),
        register_rate_window=int(os.environ.get("REGISTER_RATE_WINDOW", "60")),
        assertion_max_lifetime_seconds=int(
            os.environ.get("ASSERTION_MAX_LIFETIME_SECONDS", "300")
        ),
        allow_pending_registration=_bool("ALLOW_PENDING_REGISTRATION", True),
        max_pending_clients=int(os.environ.get("MAX_PENDING_CLIENTS", "100")),
        pending_client_ttl_seconds=int(
            os.environ.get("PENDING_CLIENT_TTL_SECONDS", "604800")
        ),
        metrics_retention_hours=int(os.environ.get("METRICS_RETENTION_HOURS", "24")),
        report_rate_limit=int(os.environ.get("REPORT_RATE_LIMIT", "10")),
        report_rate_window=int(os.environ.get("REPORT_RATE_WINDOW", "60")),
        admin_group=_require("ADMIN_GROUP").strip(),
        admin_subs=tuple(
            s.strip() for s in os.environ.get("ADMIN_SUBS", "").split(",") if s.strip()
        ),
    )
