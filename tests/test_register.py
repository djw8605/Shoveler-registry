"""POST /register: one-time registration tokens + RFC 7591 metadata validation."""

from __future__ import annotations

import dataclasses
import threading

import pytest
from fastapi.testclient import TestClient

from helpers import new_key, public_jwk, registration_body, seed_token
from portal import db, registration, tokens


def _register(client, token, body):
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return client.post("/register", json=body, headers=headers)


def _client_count(settings) -> int:
    conn = db.connect(settings.db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
    finally:
        conn.close()


def _assert_invalid_token(resp):
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_token"}
    assert resp.headers["www-authenticate"] == 'Bearer error="invalid_token"'


def test_happy_path_creates_client_and_spends_token(client, settings):
    token = seed_token(settings, site="nebraska", owner_sub="alice", owner_email="a@unl.edu")
    key = new_key()
    resp = _register(client, token, registration_body(key, client_name="  neb-xrd1  "))
    assert resp.status_code == 201
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["client_id"].startswith("shoveler-")
    assert body["client_name"] == "neb-xrd1"
    assert body["grant_types"] == ["client_credentials"]
    assert body["token_endpoint_auth_method"] == "private_key_jwt"
    assert isinstance(body["client_id_issued_at"], int)
    # No RFC 7592 management credential is ever issued.
    assert "registration_access_token" not in body
    assert "registration_client_uri" not in body

    conn = db.connect(settings.db_path)
    try:
        row = db.get_client(conn, body["client_id"])
        assert (row["site"], row["owner_sub"], row["owner_email"]) == ("nebraska", "alice", "a@unl.edu")
        assert row["kid"] == public_jwk(key)["kid"]
        assert row["disabled"] == 0
        tok = db.get_registration_token(conn, tokens.hash_registration_token(token))
        assert tok["used_at"] is not None
        assert tok["client_id"] == body["client_id"]
    finally:
        conn.close()


def test_go_client_extra_fields_are_ignored(client, settings):
    # The shoveler may send software_version; scope requests are ignored too.
    token = seed_token(settings)
    body = registration_body(new_key(), software_version="1.4.0", scope="anything")
    assert _register(client, token, body).status_code == 201


def test_client_name_is_capped(client, settings):
    token = seed_token(settings)
    resp = _register(client, token, registration_body(new_key(), client_name="x" * 500))
    assert resp.json()["client_name"] == "x" * registration.CLIENT_NAME_MAX


def test_reused_token_with_different_key_is_rejected(client, settings):
    token = seed_token(settings)
    assert _register(client, token, registration_body(new_key())).status_code == 201
    _assert_invalid_token(_register(client, token, registration_body(new_key())))
    assert _client_count(settings) == 1


def test_retry_with_same_key_returns_same_client(client, settings):
    token = seed_token(settings)
    key = new_key()
    first = _register(client, token, registration_body(key))
    again = _register(client, token, registration_body(key))
    assert first.status_code == again.status_code == 201
    assert again.json()["client_id"] == first.json()["client_id"]
    assert _client_count(settings) == 1


def test_expired_token_is_rejected(client, settings):
    token = seed_token(settings, expires_in=-1)
    _assert_invalid_token(_register(client, token, registration_body(new_key())))


def test_revoked_token_is_rejected(client, settings):
    token = seed_token(settings)
    conn = db.connect(settings.db_path)
    try:
        db.revoke_registration_token(conn, tokens.hash_registration_token(token))
    finally:
        conn.close()
    _assert_invalid_token(_register(client, token, registration_body(new_key())))


@pytest.mark.parametrize("auth", [None, "Bearer", "Bearer garbage", "Basic abc"])
def test_missing_or_garbage_bearer_is_rejected(client, settings, auth):
    seed_token(settings)
    headers = {"Authorization": auth} if auth else {}
    resp = client.post("/register", json=registration_body(new_key()), headers=headers)
    _assert_invalid_token(resp)
    assert _client_count(settings) == 0


def _two_keys():
    a, b = new_key(), new_key()
    return {"keys": [public_jwk(a), public_jwk(b)]}


def _with_private_d():
    key = new_key()
    jwk = public_jwk(key)
    jwk["d"] = "AQAB"
    return {"keys": [jwk]}


def _jwk_with(**changes):
    jwk = public_jwk(new_key())
    for k, v in changes.items():
        if v is None:
            jwk.pop(k)
        else:
            jwk[k] = v
    return {"keys": [jwk]}


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(lambda: {"jwks": {"keys": [public_jwk(new_key(1024))]}}, id="1024-bit"),
        pytest.param(lambda: {"jwks": _two_keys()}, id="two-keys"),
        pytest.param(lambda: {"jwks_uri": "https://evil.example/jwks"}, id="jwks_uri"),
        pytest.param(lambda: {"token_endpoint_auth_method": "client_secret_basic"}, id="auth-method"),
        pytest.param(lambda: {"token_endpoint_auth_method": None}, id="no-auth-method"),
        pytest.param(lambda: {"jwks": _with_private_d()}, id="private-d"),
        pytest.param(lambda: {"grant_types": ["client_credentials", "refresh_token"]}, id="grant-types"),
        pytest.param(lambda: {"jwks": _jwk_with(kid="")}, id="empty-kid"),
        pytest.param(lambda: {"jwks": _jwk_with(alg="HS256")}, id="alg"),
        pytest.param(lambda: {"jwks": _jwk_with(use="enc")}, id="use"),
        pytest.param(lambda: {"jwks": _jwk_with(kty="EC")}, id="kty"),
        pytest.param(lambda: {"jwks": _jwk_with(n="not-base64!")}, id="bad-n"),
        pytest.param(lambda: {"jwks": {"keys": []}}, id="no-keys"),
        pytest.param(lambda: {"jwks": None}, id="no-jwks"),
        pytest.param(lambda: {"client_name": 42}, id="client-name-type"),
    ],
)
def test_bad_metadata_is_rejected_without_spending_token(client, settings, overrides):
    token = seed_token(settings)
    body = registration_body(new_key())
    for k, v in overrides().items():
        if v is None:
            body.pop(k, None)
        else:
            body[k] = v
    resp = _register(client, token, body)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"
    assert resp.json()["error_description"]
    # The token is still good for a correct request.
    assert _register(client, token, registration_body(new_key())).status_code == 201


def test_non_json_body_is_bad_metadata(client, settings):
    token = seed_token(settings)
    resp = client.post(
        "/register", content=b"not json", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_client_metadata"


def test_concurrent_use_creates_exactly_one_client(settings):
    token = seed_token(settings)
    bodies = [registration_body(new_key()) for _ in range(4)]
    barrier = threading.Barrier(len(bodies))
    results = []

    def worker(body):
        conn = db.connect(settings.db_path)
        try:
            barrier.wait()
            results.append(registration.register(conn, bearer=token, body=body))
        except registration.RegistrationError as exc:
            results.append(exc.status)
        finally:
            conn.close()

    threads = [threading.Thread(target=worker, args=(b,)) for b in bodies]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if isinstance(r, dict)]
    assert len(successes) == 1
    assert sorted(r for r in results if not isinstance(r, dict)) == [401, 401, 401]
    assert _client_count(settings) == 1


def test_register_is_rate_limited_per_ip(settings):
    from portal.main import create_app

    limited = dataclasses.replace(settings, register_rate_limit=2)
    client = TestClient(create_app(limited), base_url="https://testserver")
    for _ in range(2):
        assert _register(client, "nope", registration_body(new_key())).status_code == 401
    resp = _register(client, "nope", registration_body(new_key()))
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == "60"
