"""CILogon OIDC relying-party login (authorization-code flow, state + PKCE).

The portal authenticates humans against CILogon and trusts only the ``sub``
claim as a stable identifier; ``email``/``name`` are best-effort. The ID token
is fully validated (signature via CILogon's JWKS, plus iss/aud/exp/nonce).

These CILogon credentials are the PORTAL's own OIDC-client credentials and are
unrelated to the shoveler client_id/secret pairs this service issues.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlencode

import httpx
import jwt

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


class OIDCError(Exception):
    pass


class OIDCClient:
    """Lazily-discovered CILogon client. One instance is shared by the app."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._metadata: Optional[dict] = None
        self._jwks_client: Optional[jwt.PyJWKClient] = None

    def metadata(self) -> dict:
        if self._metadata is None:
            resp = httpx.get(self.settings.cilogon_discovery_url, timeout=10)
            resp.raise_for_status()
            self._metadata = resp.json()
        return self._metadata

    def _jwks(self) -> jwt.PyJWKClient:
        if self._jwks_client is None:
            self._jwks_client = jwt.PyJWKClient(self.metadata()["jwks_uri"])
        return self._jwks_client

    # --- Step 1: build the authorization redirect ---
    def authorization_url(self) -> tuple[str, dict]:
        """Return (url, transient) where transient must be stored in session."""
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        params = {
            "response_type": "code",
            "client_id": self.settings.cilogon_client_id,
            "redirect_uri": self.settings.redirect_uri,
            "scope": "openid email profile org.cilogon.userinfo",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        url = self.metadata()["authorization_endpoint"] + "?" + urlencode(params)
        return url, {"state": state, "nonce": nonce, "code_verifier": verifier}

    # --- Step 2: exchange the code and validate the ID token ---
    def exchange_code(self, code: str, verifier: str, expected_nonce: str) -> UserInfo:
        meta = self.metadata()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.settings.redirect_uri,
            "client_id": self.settings.cilogon_client_id,
            "client_secret": self.settings.cilogon_client_secret,
            "code_verifier": verifier,
        }
        resp = httpx.post(meta["token_endpoint"], data=data, timeout=10)
        if resp.status_code != 200:
            raise OIDCError(f"token exchange failed: {resp.status_code}")
        payload = resp.json()
        id_token = payload.get("id_token")
        if not id_token:
            raise OIDCError("no id_token in token response")

        signing_key = self._jwks().get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.settings.cilogon_client_id,
            issuer=meta["issuer"],
            options={"require": ["exp", "iat", "sub"]},
        )
        if claims.get("nonce") != expected_nonce:
            raise OIDCError("nonce mismatch")

        # Which scopes CILogon granted and which claims it sent, by NAME only
        # (never values or tokens): enough to see why groups are missing.
        log.info(
            "login sub=%s granted_scope=%r id_token_claims=%s",
            claims["sub"],
            payload.get("scope"),
            sorted(claims),
        )

        # COmanage group memberships arrive in the ``isMemberOf`` claim (released
        # by the ``org.cilogon.userinfo`` scope). Some CILogon deployments put it
        # in the ID token; others only at the userinfo endpoint, so fall back to
        # userinfo using the access token when the ID token doesn't carry it.
        groups = _normalize_groups(claims.get("isMemberOf"))
        source = "id_token"
        if not groups and payload.get("access_token"):
            groups = self._fetch_groups(meta, payload["access_token"])
            source = "userinfo"
        log.info("login sub=%s groups=%d (from %s)", claims["sub"], len(groups), source)

        return UserInfo(
            sub=claims["sub"],
            email=claims.get("email"),
            name=claims.get("name"),
            groups=groups,
        )

    def _fetch_groups(self, meta: dict, access_token: str) -> tuple[str, ...]:
        endpoint = meta.get("userinfo_endpoint")
        if not endpoint:
            log.warning("userinfo: no userinfo_endpoint in CILogon metadata")
            return ()
        try:
            resp = httpx.get(
                endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            resp.raise_for_status()
            info = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            # Group info is best-effort, but say why it's missing.
            log.warning("userinfo: request failed: %s", exc)
            return ()
        log.info("userinfo: claims=%s", sorted(info) if isinstance(info, dict) else type(info).__name__)
        if not isinstance(info, dict):
            return ()
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
    for key in ("sub", "email", "name", "groups", "oidc"):
        session.pop(key, None)
