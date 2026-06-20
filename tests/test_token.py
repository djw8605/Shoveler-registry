"""Token endpoint: valid creds -> verifiable JWT; bad/disabled -> invalid_client."""

from __future__ import annotations

import json

import jwt
from jwt.algorithms import RSAAlgorithm

from portal import db, tokens


def _make_client(settings, secret="topsecret-value", disabled=False):
    conn = db.connect(settings.db_path)
    try:
        client_id = tokens.generate_client_id()
        db.insert_client(
            conn,
            client_id=client_id,
            secret_hash=tokens.hash_secret(secret),
            site="nebraska",
            owner_sub="http://cilogon.org/serverA/users/11111",
            owner_email="alice@unl.edu",
        )
        if disabled:
            db.disable_client(conn, client_id, "revoked-by-owner")
    finally:
        conn.close()
    return client_id


def _verify(client, token, settings):
    jwks = client.get("/.well-known/jwks.json").json()
    header = jwt.get_unverified_header(token)
    jwk = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    return jwt.decode(
        token, key, algorithms=["RS256"], audience=settings.resource_server_id
    )


def test_valid_credentials_mint_verifiable_token(client, settings):
    cid = _make_client(settings, secret="s3cr3t-aaa")
    resp = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": cid,
            "client_secret": "s3cr3t-aaa",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == settings.token_ttl_seconds

    claims = _verify(client, body["access_token"], settings)
    assert claims["iss"] == settings.token_issuer
    assert claims["sub"] == cid
    # aud must be EXACTLY the resource server id, no surrounding whitespace.
    assert claims["aud"] == settings.resource_server_id
    assert claims["aud"] == claims["aud"].strip()
    assert claims[settings.scope_claim] == settings.scope_value
    assert "jti" in claims and "iat" in claims and "exp" in claims


def test_last_used_updates_on_mint(client, settings):
    cid = _make_client(settings, secret="s3cr3t-bbb")
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, cid)["last_used_at"] is None
    finally:
        conn.close()

    client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": cid,
            "client_secret": "s3cr3t-bbb",
        },
    )
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, cid)["last_used_at"] is not None
    finally:
        conn.close()


def test_bad_secret_is_invalid_client(client, settings):
    cid = _make_client(settings, secret="right")
    resp = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": cid, "client_secret": "wrong"},
    )
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_client"}


def test_unknown_client_is_invalid_client(client, settings):
    resp = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": "shoveler-nope", "client_secret": "x"},
    )
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_client"}


def test_disabled_client_is_invalid_client(client, settings):
    cid = _make_client(settings, secret="right", disabled=True)
    resp = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": cid, "client_secret": "right"},
    )
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_client"}


def test_unsupported_grant_type(client, settings):
    resp = client.post(
        "/token",
        data={"grant_type": "password", "client_id": "x", "client_secret": "y"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "unsupported_grant_type"


def test_http_basic_auth_accepted(client, settings):
    cid = _make_client(settings, secret="basic-secret")
    resp = client.post(
        "/token",
        data={"grant_type": "client_credentials"},
        auth=(cid, "basic-secret"),
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()
