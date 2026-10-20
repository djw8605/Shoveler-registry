"""CILogon OIDC relying-party login (authorization-code flow, state + PKCE),
built on Authlib's Starlette client.

The portal authenticates humans against CILogon and trusts only the ``sub``
claim as a stable identifier; ``email``/``name`` are best-effort. The ID token
is fully validated (signature via CILogon's JWKS, plus iss/aud/exp/nonce).

These CILogon credentials are the PORTAL's own OIDC-client credentials and are
unrelated to the shoveler client_id/secret pairs this service issues.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from authlib.integrations.starlette_client import OAuth

from .config import Settings

log = logging.getLogger("portal.auth")


@dataclass
class UserInfo:
    sub: str
    email: Optional[str]
    name: Optional[str]
    # COmanage group memberships from CILogon's ``isMemberOf`` claim. Drives
    # site authorization (see ``authz.py``).
    groups: tuple[str, ...] = ()


def _normalize_groups(value) -> tuple[str, ...]:
    """Coerce an ``isMemberOf`` claim into a tuple of group-name strings.

    CILogon usually delivers a JSON array of strings, but tolerate a single
    string and COmanage's object form (``{"name": ...}``) defensively.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    groups = []
    for item in value:
        if isinstance(item, str):
            groups.append(item)
        elif isinstance(item, dict) and isinstance(item.get("name"), str):
            groups.append(item["name"])
    return tuple(groups)


def build_oauth(settings: Settings) -> OAuth:
    """Authlib registry holding the CILogon relying-party client.

    Authlib does discovery, ``state``/``nonce``/PKCE generation (kept in the
    session by SessionMiddleware), the code exchange, and ID-token validation
    (signature via CILogon's JWKS, plus iss/aud/exp/nonce).
    """
    oauth = OAuth()
    oauth.register(
        name="cilogon",
        client_id=settings.cilogon_client_id,
        client_secret=settings.cilogon_client_secret,
        server_metadata_url=settings.cilogon_discovery_url,
        client_kwargs={
            "scope": "openid email profile org.cilogon.userinfo",
            "code_challenge_method": "S256",
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    return oauth


async def user_from_token(client, token: dict) -> UserInfo:
    """Build a UserInfo from a token response whose ID token Authlib validated."""
    claims = token["userinfo"]
    # Which scopes CILogon granted and which claims it sent, by NAME only
    # (never values or tokens): enough to see why groups are missing.
    log.info(
        "login sub=%s granted_scope=%r id_token_claims=%s",
        claims["sub"],
        token.get("scope"),
        sorted(claims),
    )

    # COmanage group memberships arrive in the ``isMemberOf`` claim (released
    # by the ``org.cilogon.userinfo`` scope). Some CILogon deployments put it
    # in the ID token; others only at the userinfo endpoint, so fall back to
    # userinfo using the access token when the ID token doesn't carry it.
    groups = _normalize_groups(claims.get("isMemberOf"))
    source = "id_token"
    if not groups and token.get("access_token"):
        groups = await _fetch_groups(client, token)
        source = "userinfo"
    log.info("login sub=%s groups=%d (from %s)", claims["sub"], len(groups), source)
    return UserInfo(
        sub=claims["sub"],
        email=claims.get("email"),
        name=claims.get("name"),
        groups=groups,
    )


async def _fetch_groups(client, token: dict) -> tuple[str, ...]:
    try:
        info = await client.userinfo(token=token)
    except Exception as exc:  # noqa: BLE001 - group info is best-effort
        # Any failure (unreachable endpoint, HTTP error, bad JSON, an Authlib
        # error) just means the user sees no sites until it recovers; log it
        # so an admin sent to the not-authorized page can be diagnosed.
        log.warning("userinfo group lookup failed: %s", exc)
        return ()
    log.info("userinfo: claims=%s", sorted(info))
    return _normalize_groups(info.get("isMemberOf"))


# --- Session helpers -----------------------------------------------------

def current_user(session) -> Optional[UserInfo]:
    sub = session.get("sub")
    if not sub:
        return None
    return UserInfo(
        sub=sub,
        email=session.get("email"),
        name=session.get("name"),
        groups=tuple(session.get("groups") or ()),
    )


def login_user(session, user: UserInfo) -> None:
    session["sub"] = user.sub
    session["email"] = user.email
    session["name"] = user.name
    session["groups"] = list(user.groups)


def logout_user(session) -> None:
    for key in ("sub", "email", "name", "groups"):
        session.pop(key, None)
