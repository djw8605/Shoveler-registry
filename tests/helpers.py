"""Test helpers: shoveler-side RSA keys, JWKs, client assertions, seeded rows.

Imported by test modules as ``helpers`` (pytest puts ``tests/`` on sys.path).
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from portal import db, keys, tokens

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def new_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def kid_for(key) -> str:
    """The shoveler uses the RFC 7638 thumbprint as its kid."""
    return keys._thumbprint(key.public_key())


def public_jwk(key, kid: str | None = None) -> dict:
    """The JWK exactly as the Go shoveler sends it at registration."""
    numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid or kid_for(key),
        "n": keys._b64url_uint(numbers.n),
        "e": keys._b64url_uint(numbers.e),
    }


def registration_body(key, **overrides) -> dict:
    body = {
        "client_name": "shoveler",
        "grant_types": ["client_credentials"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": {"keys": [public_jwk(key)]},
    }
    body.update(overrides)
    return body


def make_assertion(key, client_id: str, aud: str, *, kid: str | None = None,
                   headers: dict | None = None, **claim_overrides) -> str:
    """A client assertion shaped exactly like the Go client's (60s lifetime)."""
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": aud,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    for name, value in claim_overrides.items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    hdr = {"kid": kid or kid_for(key)}
    hdr.update(headers or {})
    return jwt.encode(claims, key, algorithm="RS256", headers=hdr)


def token_form(assertion: str) -> dict:
    return {
        "grant_type": "client_credentials",
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": assertion,
    }


def seed_token(settings, *, site="nebraska", owner_sub="sub", owner_email=None,
               expires_in: int = 3600) -> str:
    """Insert a registration token directly; returns the plaintext token."""
    db.init_db(settings.db_path)
    token = tokens.generate_registration_token()
    expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    conn = db.connect(settings.db_path)
    try:
        db.insert_registration_token(
            conn,
            token_hash=tokens.hash_registration_token(token),
            site=site,
            owner_sub=owner_sub,
            owner_email=owner_email,
            expires_at=db.to_iso(expires),
        )
    finally:
        conn.close()
    return token


_shared_key = None


def shared_key() -> rsa.RSAPrivateKey:
    """One key reused by fixtures that don't care which key a client has."""
    global _shared_key
    if _shared_key is None:
        _shared_key = new_key()
    return _shared_key


def seed_client(settings, client_id: str, *, key=None, site="nebraska",
                owner_sub="sub", owner_email=None, client_name="shoveler"):
    """Create a registered client (via a spent registration token); returns its key."""
    key = key or shared_key()
    token = seed_token(settings, site=site, owner_sub=owner_sub, owner_email=owner_email)
    conn = db.connect(settings.db_path)
    try:
        assert db.register_client(
            conn,
            token_hash=tokens.hash_registration_token(token),
            now=db.utcnow_iso(),
            client_id=client_id,
            client_name=client_name,
            public_jwk=json.dumps(public_jwk(key)),
            kid=kid_for(key),
            key_thumbprint=kid_for(key),
        )
    finally:
        conn.close()
    return key
