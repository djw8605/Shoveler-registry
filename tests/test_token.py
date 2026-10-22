"""POST /token with private_key_jwt: valid assertions mint; everything else is invalid_client."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from helpers import (
    ASSERTION_TYPE,
    kid_for,
    make_assertion,
    new_key,
    seed_client,
    seed_pending,
    token_form,
)
from portal import db

CID = "shoveler-test0001"


def _aud(settings) -> str:
    return settings.portal_base_url.rstrip("/") + "/token"


def _verify(client, token, settings):
    jwks = client.get("/.well-known/jwks.json").json()
    header = jwt.get_unverified_header(token)
    jwk = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    return jwt.decode(
        token, key, algorithms=["RS256"], audience=settings.resource_server_id
    )


def _post(client, assertion):
    return client.post("/token", data=token_form(assertion))


def _assert_invalid_client(resp):
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_client"}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unsigned(header: dict, claims: dict) -> str:
    return _b64(json.dumps(header).encode()) + "." + _b64(json.dumps(claims).encode())


def _claims(settings, **over):
    now = int(time.time())
    claims = {"iss": CID, "sub": CID, "aud": _aud(settings), "iat": now,
              "exp": now + 60, "jti": "jti-" + str(now)}
    claims.update(over)
    return claims


@pytest.fixture
def key(settings):
    return seed_client(settings, CID, key=new_key())


def test_valid_assertion_mints_verifiable_token(client, settings, key):
    resp = _post(client, make_assertion(key, CID, _aud(settings)))
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == settings.token_ttl_seconds

    claims = _verify(client, body["access_token"], settings)
    assert claims["iss"] == settings.token_issuer
    assert claims["sub"] == CID
    assert claims["aud"] == settings.resource_server_id
    assert claims[settings.scope_claim] == settings.scope_value
    assert claims["exp"] - claims["iat"] == settings.token_ttl_seconds
    assert claims["jti"]


def test_go_client_request_shape(client, settings, key):
    # Exactly what oauth.go sends: typ JWT + kid header; string aud = token URL;
    # iss = sub = client_id; exp = iat + 60; jti = uuid4; optional scope param.
    now = int(time.time())
    assertion = jwt.encode(
        {"iss": CID, "sub": CID, "aud": "https://portal.test/token", "iat": now,
         "exp": now + 60, "jti": "0b8f1a54-7a43-4c39-9f5e-6c3f7c1f0c11"},
        key, algorithm="RS256", headers={"typ": "JWT", "kid": kid_for(key)},
    )
    resp = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion,
            "scope": "my_rabbit_server.write:xrd-mon/shoveled-xrd",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    assert set(resp.json()) == {"access_token", "expires_in", "token_type"}
    # The requested scope is ignored; the configured one is granted.
    claims = _verify(client, resp.json()["access_token"], settings)
    assert claims[settings.scope_claim] == settings.scope_value


@pytest.mark.parametrize(
    "aud", ["https://portal.test/token", "https://portal.test/", ["other", "https://portal.test/token"]]
)
def test_accepted_audiences(client, settings, key, aud):
    # PORTAL_BASE_URL/token, TOKEN_ISSUER-base/token, TOKEN_ISSUER (exactly).
    assert _post(client, make_assertion(key, CID, aud)).status_code == 200


def test_trailing_slash_on_base_url_is_insignificant(settings):
    s = dataclasses.replace(settings, portal_base_url="https://portal.test/")
    assert "https://portal.test/token" in s.token_endpoint_audiences
    assert "https://portal.test//token" not in s.token_endpoint_audiences


def _wrong_key(settings, key):
    # Signed by a different key while claiming the registered kid.
    return make_assertion(new_key(), CID, _aud(settings), kid=kid_for(key))


def _kid_mismatch(settings, key):
    return make_assertion(key, CID, _aud(settings), kid="some-other-kid")


def _alg_none(settings, key):
    return _unsigned({"alg": "none", "typ": "JWT", "kid": kid_for(key)}, _claims(settings)) + "."


def _hs256_with_public_key(settings, key):
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signing_input = _unsigned({"alg": "HS256", "typ": "JWT", "kid": kid_for(key)}, _claims(settings))
    sig = hmac.new(pem, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + _b64(sig)


def _wrong_aud(settings, key):
    return make_assertion(key, CID, settings.resource_server_id)


def _aud_with_whitespace(settings, key):
    return make_assertion(key, CID, _aud(settings) + " ")


def _iss_not_sub(settings, key):
    return make_assertion(key, CID, _aud(settings), iss="shoveler-someone-else")


def _expired(settings, key):
    now = int(time.time())
    return make_assertion(key, CID, _aud(settings), iat=now - 600, exp=now - 300)


def _exp_too_far(settings, key):
    now = int(time.time())
    return make_assertion(key, CID, _aud(settings), exp=now + settings.assertion_max_lifetime_seconds + 120)


def _no_jti(settings, key):
    return make_assertion(key, CID, _aud(settings), jti=None)


def _no_iat(settings, key):
    return make_assertion(key, CID, _aud(settings), iat=None)


def _unknown_client(settings, key):
    return make_assertion(key, "shoveler-nope", _aud(settings))


def _garbage(settings, key):
    return "not.a.jwt"


@pytest.mark.parametrize(
    "build",
    [_wrong_key, _kid_mismatch, _alg_none, _hs256_with_public_key, _wrong_aud,
     _aud_with_whitespace, _iss_not_sub, _expired, _exp_too_far, _no_jti, _no_iat,
     _unknown_client, _garbage],
)
def test_bad_assertions_are_uniform_invalid_client(client, settings, key, build):
    _assert_invalid_client(_post(client, build(settings, key)))


def test_replayed_assertion_is_rejected(client, settings, key):
    assertion = make_assertion(key, CID, _aud(settings))
    assert _post(client, assertion).status_code == 200
    _assert_invalid_client(_post(client, assertion))


def test_disabled_client_is_rejected(client, settings, key):
    conn = db.connect(settings.db_path)
    try:
        db.disable_client(conn, CID, "disabled-by-admin")
    finally:
        conn.close()
    _assert_invalid_client(_post(client, make_assertion(key, CID, _aud(settings))))


@pytest.mark.parametrize(
    "form",
    [
        {"client_assertion_type": "urn:wrong"},
        {"client_assertion_type": None},
        {"client_assertion": None},
    ],
)
def test_missing_or_wrong_assertion_params(client, settings, key, form):
    data = token_form(make_assertion(key, CID, _aud(settings)))
    for k, v in form.items():
        if v is None:
            data.pop(k)
        else:
            data[k] = v
    _assert_invalid_client(client.post("/token", data=data))


def test_client_secret_is_no_longer_accepted(client, settings, key):
    resp = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": CID, "client_secret": "x"},
    )
    _assert_invalid_client(resp)


def test_unsupported_grant_type(client, settings, key):
    data = token_form(make_assertion(key, CID, _aud(settings)))
    data["grant_type"] = "password"
    resp = client.post("/token", data=data)
    assert resp.status_code == 400
    assert resp.json() == {"error": "unsupported_grant_type"}


def test_last_used_updates_on_mint(client, settings, key):
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, CID)["last_used_at"] is None
    finally:
        conn.close()
    assert _post(client, make_assertion(key, CID, _aud(settings))).status_code == 200
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, CID)["last_used_at"] is not None
    finally:
        conn.close()


def test_token_is_rate_limited_per_client(settings):
    from portal.main import create_app

    key = seed_client(settings, CID, key=new_key())
    client = TestClient(
        create_app(dataclasses.replace(settings, token_rate_limit=1)),
        base_url="https://testserver",
    )
    assert _post(client, make_assertion(key, CID, _aud(settings))).status_code == 200
    resp = _post(client, make_assertion(key, CID, _aud(settings)))
    assert resp.status_code == 429
    assert resp.json() == {"error": "invalid_client"}


def test_discovery_advertises_registration_and_private_key_jwt(client):
    doc = client.get("/.well-known/openid-configuration").json()
    assert doc["registration_endpoint"] == "https://portal.test/register"
    assert doc["token_endpoint"] == "https://portal.test/token"
    assert doc["token_endpoint_auth_methods_supported"] == ["private_key_jwt"]
    assert doc["token_endpoint_auth_signing_alg_values_supported"] == ["RS256"]


def test_pending_client_gets_authorization_pending(client, settings):
    key = seed_pending(settings, "shoveler-pend1", key=new_key())
    resp = _post(client, make_assertion(key, "shoveler-pend1", _aud(settings)))
    assert resp.status_code == 400
    assert resp.json() == {"error": "authorization_pending"}

    # Approved: the same key now gets tokens.
    conn = db.connect(settings.db_path)
    try:
        db.approve_client(conn, "shoveler-pend1", site="nebraska", owner_sub="a", owner_email=None)
    finally:
        conn.close()
    assert _post(client, make_assertion(key, "shoveler-pend1", _aud(settings))).status_code == 200


def test_rejected_client_is_invalid_client(client, settings):
    # Even with its own key: a rejected registration is just refused.
    key = seed_pending(settings, "shoveler-pend1", key=new_key())
    conn = db.connect(settings.db_path)
    try:
        assert db.reject_pending_client(conn, "shoveler-pend1")
    finally:
        conn.close()
    _assert_invalid_client(_post(client, make_assertion(key, "shoveler-pend1", _aud(settings))))


def test_pending_status_needs_a_valid_assertion(client, settings):
    # Without the private key you learn nothing: same invalid_client as always.
    key = seed_pending(settings, "shoveler-pend1", key=new_key())
    _assert_invalid_client(
        _post(client, make_assertion(new_key(), "shoveler-pend1", _aud(settings), kid=kid_for(key)))
    )
