"""End-to-end: a shoveler registers itself, an admin lets it in, it gets tokens."""

from __future__ import annotations

import re

import portal.main as main_mod
from helpers import make_assertion, new_key, registration_body, token_form
from portal import db
from portal.auth import UserInfo

CAROL = "http://cilogon.org/serverA/users/30000"
TOKEN_URL = "https://portal.test/token"


def _as_admin(monkeypatch):
    monkeypatch.setattr(
        main_mod, "current_user",
        lambda session: UserInfo(CAROL, "carol@x.org", "Carol", ("shoveler-admins",)),
    )


def _csrf(client):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get("/dashboard").text).group(1)


def _get_token(client, key, cid):
    return client.post("/token", data=token_form(make_assertion(key, cid, TOKEN_URL)))


def test_self_registered_shoveler_approved_disabled_reenabled(client, settings, monkeypatch):
    # The shoveler registers with no token and polls; it's pending.
    key = new_key()
    reg = client.post("/register", json=registration_body(key, client_name="shoveler@xrd9"))
    assert reg.status_code == 201
    cid = reg.json()["client_id"]
    assert _get_token(client, key, cid).json() == {"error": "authorization_pending"}

    # An admin sees it, matches the client_id from the shoveler's log, approves.
    _as_admin(monkeypatch)
    dash = client.get("/dashboard").text
    assert "Awaiting approval (1)" in dash and cid in dash and "shoveler@xrd9" in dash
    csrf = _csrf(client)
    resp = client.post(f"/pending/{cid}/approve", data={"site": "nebraska", "csrf_token": csrf})
    assert f"Approved {cid} for nebraska." in resp.text
    assert "Awaiting approval" not in resp.text

    # Tokens flow on the shoveler's next poll.
    assert _get_token(client, key, cid).status_code == 200

    # Disable stops it; re-enable restores it with the same key.
    client.post(f"/credentials/{cid}/disable", data={"csrf_token": csrf})
    assert _get_token(client, key, cid).status_code == 401
    client.post(f"/credentials/{cid}/enable", data={"csrf_token": csrf})
    assert _get_token(client, key, cid).status_code == 200


def test_admin_token_lets_shoveler_in_without_approval(client, settings, monkeypatch):
    _as_admin(monkeypatch)
    page = client.post("/registration-tokens", data={"site": "nebraska", "csrf_token": _csrf(client)})
    assert page.status_code == 200 and "copy it now" in page.text
    assert "registration_url: https://portal.test/register" in page.text
    assert "token_url: https://portal.test/token" in page.text
    assert "bootstrap_token_file: /var/lib/xrootd-monitoring-shoveler/bootstrap.token" in page.text
    assert "sudo chown xrootd-monitoring-shoveler: /var/lib/xrootd-monitoring-shoveler/bootstrap.token" in page.text
    # No client_name: the shoveler's default (shoveler@<hostname>) is more useful.
    assert "client_name" not in page.text
    token = re.search(r'id="token"[^>]*>([^<]+)<', page.text).group(1)
    assert ">unused<" in client.get("/dashboard").text

    key = new_key()
    reg = client.post(
        "/register", json=registration_body(key), headers={"Authorization": f"Bearer {token}"}
    )
    assert reg.status_code == 201
    cid = reg.json()["client_id"]
    # Active at once, labelled with the token's site, attributed to its creator.
    assert _get_token(client, key, cid).status_code == 200
    conn = db.connect(settings.db_path)
    try:
        row = db.get_client(conn, cid)
        assert (row["pending"], row["site"], row["owner_sub"]) == (0, "nebraska", CAROL)
    finally:
        conn.close()
    dash = client.get("/dashboard").text
    assert ">used<" in dash and f"&rarr; {cid}" in dash


def test_revoked_token_cannot_register(client, settings, monkeypatch):
    _as_admin(monkeypatch)
    csrf = _csrf(client)
    page = client.post("/registration-tokens", data={"site": "nebraska", "csrf_token": csrf})
    token = re.search(r'id="token"[^>]*>([^<]+)<', page.text).group(1)
    token_hash = re.search(r"/registration-tokens/([0-9a-f]{64})/revoke", client.get("/dashboard").text).group(1)
    client.post(f"/registration-tokens/{token_hash}/revoke", data={"csrf_token": csrf})
    reg = client.post(
        "/register", json=registration_body(new_key()), headers={"Authorization": f"Bearer {token}"}
    )
    assert reg.status_code == 401
