"""End-to-end browser flow: registration token -> /register -> /token -> disable -> re-enable."""

from __future__ import annotations

import re

import portal.main as main_mod
from helpers import make_assertion, new_key, registration_body, seed_client, token_form
from portal import db
from portal.auth import UserInfo

ALICE = "http://cilogon.org/serverA/users/11111"  # nebraska in conftest
ALICE_GROUPS = ("shoveler-nebraska",)  # COmanage group granting site "nebraska"
TOKEN_URL = "https://portal.test/token"


def _login(monkeypatch, sub=ALICE, email="alice@unl.edu", groups=ALICE_GROUPS):
    monkeypatch.setattr(
        main_mod, "current_user", lambda session: UserInfo(sub, email, "Alice", groups)
    )


def _csrf(client):
    html = client.get("/dashboard").text
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _field(html, elem_id):
    return re.search(rf'id="{elem_id}"[^>]*>([^<]+)<', html).group(1)


def _get_token(client, key, cid):
    return client.post("/token", data=token_form(make_assertion(key, cid, TOKEN_URL)))


def test_register_use_disable_reenable(client, settings, monkeypatch):
    _login(monkeypatch)
    csrf = _csrf(client)

    # Create shows the token exactly once + a snippet in the shoveler's format.
    page = client.post("/registration-tokens", data={"site": "nebraska", "csrf_token": csrf})
    assert page.status_code == 200
    assert "copy it now" in page.text
    assert "registration_url: https://portal.test/register" in page.text
    assert "token_url: https://portal.test/token" in page.text
    assert "bootstrap_token_file: /etc/xrootd-monitoring-shoveler/oauth/bootstrap.token" in page.text
    token = _field(page.text, "token")

    # The dashboard lists it as pending.
    assert ">pending<" in client.get("/dashboard").text

    # The shoveler registers its public key with the token...
    key = new_key()
    reg = client.post(
        "/register", json=registration_body(key, client_name="neb-xrd1"),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert reg.status_code == 201
    cid = reg.json()["client_id"]
    dash = client.get("/dashboard").text
    assert ">used<" in dash and cid in dash and "neb-xrd1" in dash

    # ...and fetches access tokens with private_key_jwt.
    assert _get_token(client, key, cid).status_code == 200

    # Owner disable stops token issuance.
    client.post(f"/credentials/{cid}/disable", data={"csrf_token": csrf})
    assert _get_token(client, key, cid).status_code == 401
    assert f"/credentials/{cid}/enable" in client.get("/dashboard").text

    # Re-enable restores it with the same key; no shoveler-side change needed.
    client.post(f"/credentials/{cid}/enable", data={"csrf_token": csrf})
    assert _get_token(client, key, cid).status_code == 200


def test_admin_revoked_client_cannot_be_reenabled_by_owner(client, settings, monkeypatch):
    key = seed_client(settings, "shoveler-neb1", owner_sub=ALICE)
    conn = db.connect(settings.db_path)
    try:
        db.disable_client(conn, "shoveler-neb1", "revoked-by-admin")
    finally:
        conn.close()
    _login(monkeypatch)
    csrf = _csrf(client)
    assert "/credentials/shoveler-neb1/enable" not in client.get("/dashboard").text

    resp = client.post("/credentials/shoveler-neb1/enable", data={"csrf_token": csrf})
    assert "create a new registration token" in resp.text
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, "shoveler-neb1")["disabled"] == 1
    finally:
        conn.close()
    assert _get_token(client, key, "shoveler-neb1").status_code == 401


def test_idle_client_can_be_reenabled(client, settings, monkeypatch):
    seed_client(settings, "shoveler-neb1", owner_sub=ALICE)
    conn = db.connect(settings.db_path)
    try:
        db.disable_client(conn, "shoveler-neb1", "idle")
    finally:
        conn.close()
    _login(monkeypatch)
    csrf = _csrf(client)
    client.post("/credentials/shoveler-neb1/enable", data={"csrf_token": csrf})
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, "shoveler-neb1")["disabled"] == 0
    finally:
        conn.close()


def test_revoke_pending_token(client, settings, monkeypatch):
    _login(monkeypatch)
    csrf = _csrf(client)
    page = client.post("/registration-tokens", data={"site": "nebraska", "csrf_token": csrf})
    token = _field(page.text, "token")
    token_hash = re.search(r'/registration-tokens/([0-9a-f]{64})/revoke', client.get("/dashboard").text).group(1)

    dash = client.post(f"/registration-tokens/{token_hash}/revoke", data={"csrf_token": csrf})
    assert "Registration token revoked." in dash.text and ">revoked<" in dash.text
    reg = client.post(
        "/register", json=registration_body(new_key()),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert reg.status_code == 401


def test_cannot_create_token_for_unmanaged_site(client, settings, monkeypatch):
    _login(monkeypatch)  # Alice manages nebraska only
    csrf = _csrf(client)
    resp = client.post("/registration-tokens", data={"site": "wisconsin", "csrf_token": csrf})
    # Redirected back to dashboard with a flash; no token created.
    assert resp.url.path == "/dashboard"
    assert "You may not manage that site." in resp.text
    assert 'id="token"' not in resp.text


def test_token_create_requires_csrf(client, settings, monkeypatch):
    _login(monkeypatch)
    _csrf(client)
    resp = client.post("/registration-tokens", data={"site": "nebraska", "csrf_token": "bad"})
    assert resp.url.path == "/dashboard"
    assert 'id="token"' not in resp.text


def test_other_users_token_cannot_be_revoked(client, settings, monkeypatch):
    # Bob also manages nebraska but didn't create Alice's token.
    _login(monkeypatch)
    csrf = _csrf(client)
    client.post("/registration-tokens", data={"site": "nebraska", "csrf_token": csrf})
    token_hash = re.search(r'/registration-tokens/([0-9a-f]{64})/revoke', client.get("/dashboard").text).group(1)

    _login(monkeypatch, sub="bob", email="bob@unl.edu")
    resp = client.post(f"/registration-tokens/{token_hash}/revoke", data={"csrf_token": csrf})
    assert "Not authorized for that token." in resp.text
