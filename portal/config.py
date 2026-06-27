"""Runtime configuration, loaded once from the environment.

Naming note: ``CILOGON_*`` are the portal's OWN credentials as an OIDC client
registered with CILogon (used to log humans in). They are entirely distinct
from the shoveler ``client_id``/``client_secret`` pairs this service issues.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


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
    session_secret: str

    # --- Storage ---
    db_path: str
    signing_key_dir: str

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

    # --- COmanage group-based authorization ---
    # Site authorization comes from the CILogon ``isMemberOf`` claim (the
    # COmanage groups the user belongs to). A group named
    # ``<comanage_group_prefix><site>`` grants management of ``<site>``; the
    # site name is the part of the group name after the prefix.
    comanage_group_prefix: str
    # Membership in this COmanage group grants registry-wide admin (sees all
    # sites at /admin, may disable any client). Empty disables the admin view.
    registry_admin_group: str

    @property
    def redirect_uri(self) -> str:
        return self.portal_base_url.rstrip("/") + "/auth/callback"


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
        session_secret=_require("SESSION_SECRET"),
        db_path=os.environ.get("DB_PATH", "./data/portal.db"),
        signing_key_dir=os.environ.get("SIGNING_KEY_DIR", "./data/keys"),
        token_issuer=_require("TOKEN_ISSUER"),
        resource_server_id=_require("RESOURCE_SERVER_ID"),
        token_ttl_seconds=int(os.environ.get("TOKEN_TTL_SECONDS", "14400")),
        scope_claim=os.environ.get("SCOPE_CLAIM", "extra_scope"),
        scope_value=os.environ.get(
            "SCOPE_VALUE", "my_rabbit_server.write:*/xrd-shoveled"
        ),
        idle_days=int(os.environ.get("IDLE_DAYS", "30")),
        admin_contact=os.environ.get("ADMIN_CONTACT", "your central admin"),
        token_rate_limit=int(os.environ.get("TOKEN_RATE_LIMIT", "30")),
        token_rate_window=int(os.environ.get("TOKEN_RATE_WINDOW", "60")),
        comanage_group_prefix=os.environ.get("COMANAGE_GROUP_PREFIX", "shoveler-"),
        registry_admin_group=os.environ.get("REGISTRY_ADMIN_GROUP", "").strip(),
    )
