"""Token minting and the client-credentials grant logic.

Clients authenticate with ``private_key_jwt`` (RFC 7523): a short-lived JWT
signed by the private key whose public half they registered (see
registration.py). The ``/token`` endpoint returns a uniform ``invalid_client``
for any authentication failure (unknown or disabled client, bad signature,
wrong audience, expired or replayed assertion) so it never reveals which.

A pending client (registered without a token, not yet approved) that proves
possession of its key gets ``400 authorization_pending`` instead of a token;
the shoveler keeps polling until an approver assigns its site.
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import jwt
from jwt.algorithms import RSAAlgorithm

from . import db
from .config import Settings
from .keys import ALG, KeyStore

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
# Clock-skew allowance for client assertions' exp/iat.
ASSERTION_LEEWAY_SECONDS = 60


def generate_registration_token() -> str:
    """One-time registration (initial access) token; shown once."""
    return secrets.token_urlsafe(32)


def hash_registration_token(token: str) -> str:
    """SHA-256, not argon2: the token is 256 random bits, so a fast hash is
    safe, and it lets /register look the token up by its hash."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_client_id() -> str:
    return "shoveler-" + secrets.token_hex(8)


def build_claims(settings: Settings, client_id: str) -> dict:
    now = datetime.now(timezone.utc)
    iat = int(now.timestamp())
    return {
        "iss": settings.token_issuer,
        "sub": client_id,
        "aud": settings.resource_server_id,
        "iat": iat,
        "exp": iat + settings.token_ttl_seconds,
        "jti": uuid.uuid4().hex,
        settings.scope_claim: settings.scope_value,
    }


def mint_token(settings: Settings, keystore: KeyStore, client_id: str) -> str:
    claims = build_claims(settings, client_id)
    active = keystore.active
    return jwt.encode(
        claims,
        active.private_key,
        algorithm=ALG,
        headers={"kid": active.kid},
    )


class TokenError(Exception):
    """Raised for client-credentials failures; carries an HTTP status + code."""

    def __init__(self, status: int, error: str):
        self.status = status
        self.error = error
        super().__init__(error)


def _invalid_client() -> TokenError:
    return TokenError(401, "invalid_client")


@dataclass
class TokenResponse:
    access_token: str
    expires_in: int
    token_type: str = "Bearer"

    def as_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
        }


class RateLimiter:
    """Tiny in-process sliding-window limiter, keyed by client_id or client IP."""

    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and bucket[0] <= now - self.window:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


def assertion_subject(assertion: Optional[str]) -> Optional[str]:
    """The UNVERIFIED ``sub`` of a client assertion.

    Only for looking up the client and keying the rate limiter; nothing is
    trusted until verify_assertion has checked the signature.
    """
    if not assertion:
        return None
    try:
        claims = jwt.decode(assertion, options={"verify_signature": False})
    except jwt.PyJWTError:
        return None
    sub = claims.get("sub")
    return sub if isinstance(sub, str) and sub else None


def verify_assertion(settings: Settings, client, assertion: str) -> dict:
    """Fully verify a client assertion against the client's registered key.

    Returns the verified claims, or raises TokenError(invalid_client).
    """
    try:
        header = jwt.get_unverified_header(assertion)
        if header.get("kid") != client["kid"]:
            raise _invalid_client()
        key = RSAAlgorithm.from_jwk(client["public_jwk"])
        claims = jwt.decode(
            assertion,
            key,
            # RS256 only: rejects alg "none" and HS256-with-the-public-key.
            algorithms=["RS256"],
            audience=sorted(settings.token_endpoint_audiences),
            issuer=client["client_id"],
            leeway=ASSERTION_LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "jti", "iss", "sub", "aud"]},
        )
    except jwt.PyJWTError:
        raise _invalid_client() from None
    if claims["sub"] != client["client_id"]:
        raise _invalid_client()
    if not isinstance(claims["jti"], str) or not claims["jti"]:
        raise _invalid_client()
    if claims["exp"] > time.time() + settings.assertion_max_lifetime_seconds:
        raise _invalid_client()
    return claims


def issue_token(
    conn,
    settings: Settings,
    keystore: KeyStore,
    *,
    grant_type: Optional[str],
    client_assertion_type: Optional[str],
    client_assertion: Optional[str],
) -> TokenResponse:
    """Authenticate a private_key_jwt client-credentials request and mint a token.

    Raises TokenError on any failure.
    """
    if grant_type != "client_credentials":
        raise TokenError(400, "unsupported_grant_type")
    if client_assertion_type != ASSERTION_TYPE or not client_assertion:
        raise _invalid_client()

    client_id = assertion_subject(client_assertion)
    client = db.get_client(conn, client_id) if client_id else None
    if client is None or client["disabled"]:
        raise _invalid_client()

    claims = verify_assertion(settings, client, client_assertion)
    # Each assertion is single-use. Rows can be purged once even the leeway
    # can no longer make their exp acceptable.
    if not db.record_assertion(
        conn,
        client_id=client["client_id"],
        jti=claims["jti"],
        exp=int(claims["exp"]),
        purge_before=int(time.time()) - ASSERTION_LEEWAY_SECONDS,
    ):
        raise _invalid_client()
    # Only after full verification, so only the key holder learns it's pending.
    if client["pending"]:
        raise TokenError(400, "authorization_pending")

    token = mint_token(settings, keystore, client["client_id"])
    db.touch_last_used(conn, client["client_id"])
    return TokenResponse(access_token=token, expires_in=settings.token_ttl_seconds)
