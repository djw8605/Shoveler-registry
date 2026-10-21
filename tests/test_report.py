"""POST /report: shovelers send health metrics with their access token."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from helpers import new_key, report_body, seed_client, seed_pending, seed_report
from portal import db, tokens
from portal.main import create_app

CID = "shoveler-rep00001"


def _token(app, settings, client_id=CID, **claims):
    """An access token as /token mints it, with optional claim overrides."""
    body = tokens.build_claims(settings, client_id)
    body.update(claims)
    active = app.state.keystore.active
    return jwt.encode(body, active.private_key, algorithm="RS256",
                      headers={"kid": active.kid})


def _post(client, token, body=None, **kw):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/report", json=report_body() if body is None else body,
                       headers=headers, **kw)


def _reports(settings, client_id=CID):
    conn = db.connect(settings.db_path)
    try:
        return db.list_reports(conn, "", client_id)
    finally:
        conn.close()


def test_report_is_stored(client, app, settings):
    seed_client(settings, CID)
    body = report_body(
        started_at="2026-10-21T01:02:03Z", interval=30, version=" v1.5.0 ",
        packets_received=1200, validations_failed=3, messages_published=1197,
        rabbitmq_reconnects=1, queue_size=4, some_future_metric=7,
    )
    resp = _post(client, _token(app, settings), body)
    assert resp.status_code == 204
    assert resp.headers["cache-control"] == "no-store"
    (row,) = _reports(settings)
    assert dict(row) | {"received_at": None} == {
        "client_id": CID,
        "received_at": None,
        "started_at": "2026-10-21T01:02:03.000000+00:00",
        "interval_seconds": 30,
        "version": "v1.5.0",
        "packets_received": 1200,
        "validations_failed": 3,
        "messages_published": 1197,
        "rabbitmq_reconnects": 1,
        "queue_size": 4,
    }


def test_missing_metrics_are_null(client, app, settings):
    seed_client(settings, CID)
    resp = _post(client, _token(app, settings), report_body(packets_received=5))
    assert resp.status_code == 204
    (row,) = _reports(settings)
    assert row["packets_received"] == 5 and row["messages_published"] is None


def _assert_invalid_token(resp):
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_token"}
    assert resp.headers["www-authenticate"] == 'Bearer error="invalid_token"'


def test_needs_a_bearer_token(client, settings):
    seed_client(settings, CID)
    _assert_invalid_token(_post(client, None))
    _assert_invalid_token(client.post("/report", json=report_body(),
                                      headers={"Authorization": "Basic abc"}))
    assert _reports(settings) == []


@pytest.mark.parametrize("claims", [
    {"aud": "someone_else"},
    {"iss": "https://elsewhere.test/"},
    {"exp": int(time.time()) - 3600},
    {"sub": "shoveler-unknown"},
    {"sub": None},
])
def test_rejects_bad_claims(client, app, settings, claims):
    seed_client(settings, CID)
    _assert_invalid_token(_post(client, _token(app, settings, **claims)))


def test_rejects_tokens_we_did_not_sign(client, settings):
    seed_client(settings, CID)
    claims = tokens.build_claims(settings, CID)
    forged = jwt.encode(claims, new_key(), algorithm="RS256",
                        headers={"kid": "someone-elses-kid"})
    _assert_invalid_token(_post(client, forged))
    # Our kid on a token signed with another key fails the signature check.
    active = client.app.state.keystore.active
    forged = jwt.encode(claims, new_key(), algorithm="RS256", headers={"kid": active.kid})
    _assert_invalid_token(_post(client, forged))
    _assert_invalid_token(_post(client, "x.y.z"))


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_rejects_alg_confusion(client, app, settings):
    seed_client(settings, CID)
    active = app.state.keystore.active
    claims = _b64(json.dumps(tokens.build_claims(settings, CID)).encode())

    def header(alg):
        return _b64(json.dumps({"alg": alg, "typ": "JWT", "kid": active.kid}).encode())

    _assert_invalid_token(_post(client, f"{header('none')}.{claims}."))
    # HS256 keyed with our (public) signing key's PEM.
    pem = active.public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signing_input = f"{header('HS256')}.{claims}"
    sig = hmac.new(pem, signing_input.encode(), hashlib.sha256).digest()
    _assert_invalid_token(_post(client, f"{signing_input}.{_b64(sig)}"))


def test_accepts_tokens_from_a_retired_key(tmp_path, settings):
    """After rotation, tokens signed by the previous key still report."""
    from fastapi.testclient import TestClient

    from portal import keys

    keys.ensure_keys(settings.signing_key_dir)
    old_app = create_app(settings)
    seed_client(settings, CID)
    old_token = _token(old_app, settings)
    keys.generate_key(settings.signing_key_dir)
    client = TestClient(create_app(settings), base_url="https://testserver")
    assert _post(client, old_token).status_code == 204


def test_rejects_pending_and_disabled_clients(client, app, settings):
    seed_pending(settings, "shoveler-pend1")
    _assert_invalid_token(_post(client, _token(app, settings, "shoveler-pend1")))
    seed_client(settings, CID)
    conn = db.connect(settings.db_path)
    try:
        db.disable_client(conn, CID, "disabled-by-admin")
    finally:
        conn.close()
    _assert_invalid_token(_post(client, _token(app, settings)))


@pytest.mark.parametrize("body,message", [
    ([], "request body must be a JSON object"),
    ({**report_body(), "started_at": "yesterday"}, "started_at must be an RFC 3339 timestamp"),
    ({**report_body(), "started_at": None}, "started_at must be an RFC 3339 timestamp"),
    ({**report_body(), "interval_seconds": 5}, "interval_seconds must be an integer from 10 to 3600"),
    ({**report_body(), "interval_seconds": "60"}, "interval_seconds must be an integer from 10 to 3600"),
    ({**report_body(), "interval_seconds": True}, "interval_seconds must be an integer from 10 to 3600"),
    ({**report_body(), "version": 1}, "version must be a string"),
    ({**report_body(), "metrics": [1]}, "metrics must be a JSON object"),
    (report_body(packets_received=-1), "metrics.packets_received is out of range"),
    (report_body(queue_size=2**60), "metrics.queue_size is out of range"),
    (report_body(queue_size=True), "metrics.queue_size must be a number"),
    (report_body(queue_size="3"), "metrics.queue_size must be a number"),
    (report_body(unknown=1), "metrics has none of: packets_received, validations_failed, "
                             "messages_published, rabbitmq_reconnects, queue_size"),
])
def test_rejects_bad_reports(client, app, settings, body, message):
    seed_client(settings, CID)
    resp = _post(client, _token(app, settings), body)
    assert resp.status_code == 400
    assert resp.json() == {"error": "invalid_request", "error_description": message}
    assert _reports(settings) == []


def test_rejects_non_json_and_huge_bodies(client, app, settings):
    seed_client(settings, CID)
    headers = {"Authorization": f"Bearer {_token(app, settings)}"}
    resp = client.post("/report", content=b"not json", headers=headers)
    assert resp.json()["error_description"] == "request body must be JSON"
    huge = report_body()
    huge["padding"] = "x" * 20000
    resp = client.post("/report", json=huge, headers=headers)
    assert resp.status_code == 400
    assert resp.json()["error_description"] == "report too large"


def test_rate_limited_per_client(settings):
    from fastapi.testclient import TestClient

    app = create_app(dataclasses.replace(settings, report_rate_limit=2))
    client = TestClient(app, base_url="https://testserver")
    seed_client(settings, CID)
    token = _token(app, settings)
    assert [_post(client, token).status_code for _ in range(3)] == [204, 204, 429]
    # Another shoveler has its own budget.
    seed_client(settings, "shoveler-rep00002")
    assert _post(client, _token(app, settings, "shoveler-rep00002")).status_code == 204


def test_old_reports_are_trimmed_on_insert(client, app, settings):
    seed_client(settings, CID)
    seed_client(settings, "shoveler-other")
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=3)
    for hours in (30, 25, 2):
        for cid in (CID, "shoveler-other"):
            seed_report(settings, cid, now - timedelta(hours=hours), started_at=start,
                        packets_received=hours)
    assert _post(client, _token(app, settings)).status_code == 204
    # This shoveler's reports older than 24 h are gone; the other's are kept.
    assert [r["packets_received"] for r in _reports(settings)] == [2, 10]
    assert len(_reports(settings, "shoveler-other")) == 3
