"""Token minting and the client-credentials grant logic.

Secrets are hashed with argon2 and verified in constant time. The ``/token``
endpoint returns a uniform ``invalid_client`` for any failure (unknown id,
disabled client, or wrong secret) so it never reveals which was wrong.
"""

from __future__ import annotations

import secrets
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from . import db
from .config import Settings
from .keys import ALG, KeyStore

_hasher = PasswordHasher()


def generate_secret() -> str:
    """High-entropy client secret; shown once, never stored in the clear."""
    return secrets.token_urlsafe(32)


def generate_client_id() -> str:
    return "shoveler-" + secrets.token_hex(8)


def hash_secret(secret: str) -> str:
    return _hasher.hash(secret)


def verify_secret(secret_hash: str, secret: str) -> bool:
    try:
        return _hasher.verify(secret_hash, secret)
    except VerifyMismatchError:
        return False
    except Exception:
        # Malformed stored hash, etc. Treat as a mismatch; never raise to caller.
        return False


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
    """Tiny in-process sliding-window limiter, keyed by client_id."""

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


def issue_token(
    conn,
    settings: Settings,
    keystore: KeyStore,
    *,
    grant_type: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
) -> TokenResponse:
    """Validate a client-credentials request and mint a token.

    Raises TokenError on any failure.
    """
    if grant_type != "client_credentials":
        raise TokenError(400, "unsupported_grant_type")

    if not client_id or not client_secret:
        raise TokenError(401, "invalid_client")

    row = db.get_client(conn, client_id)
    if row is None:
        # Verify against a dummy hash to keep timing roughly uniform.
        verify_secret(
            "$argon2id$v=19$m=65536,t=3,p=4$" + "A" * 22 + "$" + "B" * 43,
            client_secret,
        )
        raise TokenError(401, "invalid_client")

    if row["disabled"]:
        verify_secret(row["secret_hash"], client_secret)
        raise TokenError(401, "invalid_client")

    if not verify_secret(row["secret_hash"], client_secret):
        raise TokenError(401, "invalid_client")

    token = mint_token(settings, keystore, client_id)
    db.touch_last_used(conn, client_id)
    return TokenResponse(access_token=token, expires_in=settings.token_ttl_seconds)
