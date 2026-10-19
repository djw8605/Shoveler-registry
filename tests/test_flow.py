"""End-to-end browser flow: registration token -> /register -> /token -> disable -> re-enable."""

from __future__ import annotations

import re

import portal.main as main_mod
from helpers import (
    make_assertion,
    new_key,
    registration_body,
    seed_client,
    seed_pending,
    token_form,
)
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


def _alice_token_hash(client, monkeypatch):
    _login(monkeypatch)
    csrf = _csrf(client)
    client.post("/registration-tokens", data={"site": "nebraska", "csrf_token": csrf})
    html = client.get("/dashboard").text
    return csrf, re.search(r"/registration-tokens/([0-9a-f]{64})/revoke", html).group(1)


def test_any_site_manager_can_revoke_token(client, settings, monkeypatch):
    # Bob also manages nebraska; he didn't create Alice's token but may revoke it.
    csrf, token_hash = _alice_token_hash(client, monkeypatch)
    _login(monkeypatch, sub="bob", email="bob@unl.edu")
    resp = client.post(f"/registration-tokens/{token_hash}/revoke", data={"csrf_token": csrf})
    assert "Registration token revoked." in resp.text


def test_non_manager_cannot_revoke_token(client, settings, monkeypatch):
    csrf, token_hash = _alice_token_hash(client, monkeypatch)
    _login(monkeypatch, sub="bob", email="bob@wisc.edu", groups=("shoveler-wisconsin",))
    resp = client.post(f"/registration-tokens/{token_hash}/revoke", data={"csrf_token": csrf})
    assert "Not authorized for that token." in resp.text
    conn = db.connect(settings.db_path)
    try:
        assert db.get_registration_token(conn, token_hash)["revoked"] == 0
    finally:
        conn.close()


# --- Token-less registration: pending until approved -------------------------

def test_tokenless_shoveler_pending_then_approved(client, settings, monkeypatch):
    # The shoveler registers with no token...
    key = new_key()
    reg = client.post("/register", json=registration_body(key, client_name="shoveler@xrd9"))
    assert reg.status_code == 201
    cid = reg.json()["client_id"]
    # ...and polls /token, which says it's pending.
    assert _get_token(client, key, cid).json() == {"error": "authorization_pending"}

    # A nebraska manager sees it awaiting approval and approves it into nebraska.
    _login(monkeypatch)
    dash = client.get("/dashboard").text
    assert "Awaiting approval (1)" in dash and cid in dash and "shoveler@xrd9" in dash
    csrf = _csrf(client)
    resp = client.post(f"/pending/{cid}/approve", data={"site": "nebraska", "csrf_token": csrf})
    assert f"Approved {cid} for nebraska." in resp.text
    assert "Awaiting approval" not in resp.text

    # Tokens flow, and the approver owns it (so may disable it).
    assert _get_token(client, key, cid).status_code == 200
    conn = db.connect(settings.db_path)
    try:
        row = db.get_client(conn, cid)
        assert (row["pending"], row["site"], row["owner_sub"]) == (0, "nebraska", ALICE)
    finally:
        conn.close()
    client.post(f"/credentials/{cid}/disable", data={"csrf_token": csrf})
    assert _get_token(client, key, cid).status_code == 401


def test_cannot_approve_into_unmanaged_site(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    _login(monkeypatch)  # nebraska only
    csrf = _csrf(client)
    resp = client.post("/pending/shoveler-pend1/approve", data={"site": "wisconsin", "csrf_token": csrf})
    assert "You may not approve into that site." in resp.text
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, "shoveler-pend1")["pending"] == 1
    finally:
        conn.close()


def test_approve_requires_csrf(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    _login(monkeypatch)
    _csrf(client)
    resp = client.post("/pending/shoveler-pend1/approve", data={"site": "nebraska", "csrf_token": "bad"})
    assert "Invalid CSRF token." in resp.text
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, "shoveler-pend1")["pending"] == 1
    finally:
        conn.close()


def test_reject_deletes_pending_client(client, settings, monkeypatch):
    key = seed_pending(settings, "shoveler-pend1", key=new_key())
    _login(monkeypatch)
    csrf = _csrf(client)
    resp = client.post("/pending/shoveler-pend1/reject", data={"csrf_token": csrf})
    assert "Rejected shoveler-pend1." in resp.text
    assert _get_token(client, key, "shoveler-pend1").status_code == 401


def test_user_without_sites_cannot_reject(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    _login(monkeypatch)
    csrf = _csrf(client)  # a valid session CSRF token, so only authz can refuse
    _login(monkeypatch, sub="nobody", groups=("CO:members:active",))
    resp = client.post("/pending/shoveler-pend1/reject", data={"csrf_token": csrf})
    assert "Not authorized." in resp.text
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, "shoveler-pend1") is not None
    finally:
        conn.close()


def test_approved_twice_is_harmless(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    _login(monkeypatch)
    csrf = _csrf(client)
    client.post("/pending/shoveler-pend1/approve", data={"site": "nebraska", "csrf_token": csrf})
    resp = client.post("/pending/shoveler-pend1/approve", data={"site": "nebraska", "csrf_token": csrf})
    assert "That shoveler is no longer pending." in resp.text

