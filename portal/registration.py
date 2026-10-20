"""Dynamic client registration (RFC 7591 request format) for shovelers.

The shoveler generates its own RSA keypair and POSTs its PUBLIC key to
/register; from then on it authenticates at /token with ``private_key_jwt``
(see tokens.py). No shared secret exists. Two ways in:

* Without a token (no Authorization header; the usual way, while
  ALLOW_PENDING_REGISTRATION is on): the client is pending, with no site, and
  /token answers ``authorization_pending`` until an admin approves it on the
  dashboard and labels its site.
* With a one-time registration token an admin minted (bearer token): the
  token is spent and the client is active at once, labelled with the token's
  site. A present but bad token is always 401; it never falls back to pending.

RFC 7592 client management is deliberately not offered, so no
``registration_access_token`` is ever issued.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm

from . import db, keys, tokens

AUTH_METHOD = "private_key_jwt"
GRANT_TYPES = ["client_credentials"]
MIN_RSA_BITS = 2048
CLIENT_NAME_MAX = 100
# RSA private-key members (RFC 7518 section 6.3.2). A JWK carrying any of them
# is a private key the client should never have sent.
PRIVATE_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "oth"}


class RegistrationError(Exception):
    """A /register failure; carries the HTTP status and OAuth error body."""

    def __init__(self, status: int, error: str, description: Optional[str] = None):
        self.status = status
        self.error = error
        self.description = description
        super().__init__(error)

    def as_dict(self) -> dict:
        body = {"error": self.error}
        if self.description:
            body["error_description"] = self.description
        return body


def _invalid_token() -> RegistrationError:
    # One uniform response for missing/unknown/expired/revoked/used tokens.
    return RegistrationError(401, "invalid_token")


def _too_many_pending() -> RegistrationError:
    # 503 so the shoveler retries (it treats most 4xx as permanent).
    return RegistrationError(
        503, "temporarily_unavailable", "too many registrations awaiting approval"
    )


def _bad_metadata(description: str) -> RegistrationError:
    return RegistrationError(400, "invalid_client_metadata", description)


@dataclass(frozen=True)
class ClientMetadata:
    public_jwk: dict
    kid: str
    thumbprint: str
    client_name: Optional[str]


def validate_metadata(body) -> ClientMetadata:
    """Validate a registration request body. Raises RegistrationError (400)."""
    if not isinstance(body, dict):
        raise _bad_metadata("request body must be a JSON object")
    if body.get("token_endpoint_auth_method") != AUTH_METHOD:
        raise _bad_metadata("token_endpoint_auth_method must be private_key_jwt")
    if "grant_types" in body and body["grant_types"] != GRANT_TYPES:
        raise _bad_metadata('grant_types must be ["client_credentials"]')
    if "jwks_uri" in body:
        raise _bad_metadata("jwks_uri is not supported; send the public key in jwks")

    jwks = body.get("jwks")
    key_list = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(key_list, list) or len(key_list) != 1:
        raise _bad_metadata("jwks.keys must contain exactly one key")
    jwk = key_list[0]
    if not isinstance(jwk, dict):
        raise _bad_metadata("jwks.keys[0] must be a JWK object")
    if PRIVATE_MEMBERS & jwk.keys():
        raise _bad_metadata("jwks must contain only the public key")
    if jwk.get("kty") != "RSA":
        raise _bad_metadata("key must have kty RSA")
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise _bad_metadata("key must have a non-empty kid")
    if jwk.get("use") not in (None, "sig"):
        raise _bad_metadata("key use must be sig")
    if jwk.get("alg") not in (None, "RS256"):
        raise _bad_metadata("key alg must be RS256")

    try:
        public_key = RSAAlgorithm.from_jwk({"kty": "RSA", "n": jwk["n"], "e": jwk["e"]})
    except Exception:  # noqa: BLE001 - any parse failure is bad metadata
        raise _bad_metadata("key n/e are not a valid RSA public key") from None
    if not isinstance(public_key, RSAPublicKey):
        raise _bad_metadata("key must be an RSA public key")
    if public_key.key_size < MIN_RSA_BITS:
        raise _bad_metadata(f"RSA key must be at least {MIN_RSA_BITS} bits")

    name = body.get("client_name")
    if name is not None and not isinstance(name, str):
        raise _bad_metadata("client_name must be a string")
    name = (name or "").strip()[:CLIENT_NAME_MAX] or None

    numbers = public_key.public_numbers()
    # Store a normalized public JWK: only public members, canonical encoding.
    public_jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": keys._b64url_uint(numbers.n),
        "e": keys._b64url_uint(numbers.e),
    }
    return ClientMetadata(
        public_jwk=public_jwk,
        kid=kid,
        thumbprint=keys._thumbprint(public_key),
        client_name=name,
    )


def parse_bearer(header: Optional[str]) -> Optional[str]:
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    value = value.strip()
    if scheme.lower() != "bearer" or not value:
        return None
    return value


def _response(client) -> dict:
    body = {
        "client_id": client["client_id"],
        "client_id_issued_at": int(db.parse_ts(client["created_at"]).timestamp()),
        "grant_types": GRANT_TYPES,
        "token_endpoint_auth_method": AUTH_METHOD,
    }
    if client["client_name"]:
        body["client_name"] = client["client_name"]
    return body


def register(
    conn,
    settings,
    *,
    authorization: Optional[str],
    body,
    registered_ip: Optional[str] = None,
) -> dict:
    """Handle a /register request. Returns the 201 body.

    With a bearer registration token the client is created active; with no
    Authorization header at all it is created pending (if allowed). Raises
    RegistrationError on any failure.
    """
    if not authorization or not authorization.strip():
        if not settings.allow_pending_registration:
            raise _invalid_token()
        return _register_pending(
            conn, settings, body=body, registered_ip=registered_ip
        )
    bearer = parse_bearer(authorization)
    if not bearer:
        raise _invalid_token()
    return _register_with_token(conn, bearer=bearer, body=body)


def _register_pending(conn, settings, *, body, registered_ip: Optional[str]) -> dict:
    """Create a pending client for a token-less registration.

    Retrying with the same key returns the existing client instead of piling
    up duplicates. (A public key isn't secret, but neither is a client_id: only
    the private key's holder can use the client.)
    """
    meta = validate_metadata(body)
    existing = db.find_client_by_thumbprint(conn, meta.thumbprint)
    if existing is not None:
        return _response(existing)
    if db.count_pending_clients(conn) >= settings.max_pending_clients:
        raise _too_many_pending()
    client_id = tokens.generate_client_id()
    db.insert_pending_client(
        conn,
        client_id=client_id,
        client_name=meta.client_name,
        public_jwk=json.dumps(meta.public_jwk),
        kid=meta.kid,
        key_thumbprint=meta.thumbprint,
        registered_ip=registered_ip,
    )
    return _response(db.get_client(conn, client_id))


def _register_with_token(conn, *, bearer: str, body) -> dict:
    """Spend a registration token and create an active client.

    A retry of a registration whose response was lost (same token, same key)
    returns the original client.
    """
    token_hash = tokens.hash_registration_token(bearer)
    now = datetime.now(timezone.utc)

    def usable(row) -> bool:
        return (
            row is not None
            and not row["revoked"]
            and db.parse_ts(row["expires_at"]) > now
        )

    # Reject a bad token before looking at the metadata.
    if not usable(db.get_registration_token(conn, token_hash)):
        raise _invalid_token()

    meta = validate_metadata(body)
    client_id = tokens.generate_client_id()
    if db.register_client(
        conn,
        token_hash=token_hash,
        now=db.to_iso(now),
        client_id=client_id,
        client_name=meta.client_name,
        public_jwk=json.dumps(meta.public_jwk),
        kid=meta.kid,
        key_thumbprint=meta.thumbprint,
    ):
        return _response(db.get_client(conn, client_id))

    # Not spent just now: either already used (maybe by this same shoveler,
    # retrying after a lost response) or it became unusable meanwhile.
    row = db.get_registration_token(conn, token_hash)
    if usable(row) and row["used_at"] and row["client_id"]:
        client = db.get_client(conn, row["client_id"])
        if client is not None and secrets.compare_digest(
            client["key_thumbprint"], meta.thumbprint
        ):
            return _response(client)
    raise _invalid_token()
