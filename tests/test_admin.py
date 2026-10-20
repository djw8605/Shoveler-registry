"""The admin dashboard: approve/reject, disable/re-enable, registration tokens."""

from __future__ import annotations

import re

import portal.main as main_mod
from helpers import kid_for, seed_client, seed_pending, seed_token, shared_key
from portal import db, tokens
from portal.auth import UserInfo

CAROL = "http://cilogon.org/serverA/users/30000"
ADMIN_GROUPS = ("shoveler-admins",)  # conftest's ADMIN_GROUP


def _as_admin(monkeypatch):
    monkeypatch.setattr(
        main_mod, "current_user", lambda s: UserInfo(CAROL, "carol@x.org", "Carol", ADMIN_GROUPS)
    )


def _csrf(client):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get("/dashboard").text).group(1)


def _client(settings, client_id):
    conn = db.connect(settings.db_path)
    try:
        return db.get_client(conn, client_id)
    finally:
        conn.close()


def test_dashboard_lists_everything(client, settings, monkeypatch):
    seed_client(settings, "shoveler-neb1", site="nebraska", owner_email="alice@unl.edu")
    seed_client(settings, "shoveler-wis1", site="wisconsin")
    seed_pending(settings, "shoveler-pend1", client_name="shoveler@xrd9.unl.edu")
    _as_admin(monkeypatch)
    page = client.get("/dashboard").text
    assert "Awaiting approval (1)" in page
    assert "shoveler-pend1" in page and "shoveler@xrd9.unl.edu" in page and "192.0.2.7" in page
    assert "shoveler-neb1" in page and "shoveler-wis1" in page and "alice@unl.edu" in page
    # Name and a shortened key thumbprint for each shoveler.
    assert ">shoveler<" in page and kid_for(shared_key())[:12] in page
    # Seed tokens show as used, with the client they created.
    assert ">used<" in page and "&rarr; shoveler-neb1" in page
    # Known sites are offered when typing a site label.
    assert '<option value="nebraska">' in page and '<option value="wisconsin">' in page


def test_no_pending_card_when_none_pending(client, settings, monkeypatch):
    _as_admin(monkeypatch)
    assert "Awaiting approval" not in client.get("/dashboard").text


def test_approve_labels_site_and_records_approver(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    _as_admin(monkeypatch)
    resp = client.post(
        "/pending/shoveler-pend1/approve",
        data={"site": "  brand-new-site ", "csrf_token": _csrf(client)},
    )
    assert "Approved shoveler-pend1 for brand-new-site." in resp.text
    row = _client(settings, "shoveler-pend1")
    assert (row["pending"], row["site"], row["owner_sub"], row["owner_email"]) == (
        0, "brand-new-site", CAROL, "carol@x.org"
    )


def test_approve_needs_a_site(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    _as_admin(monkeypatch)
    for site in ("   ", "x" * 101):
        resp = client.post(
            "/pending/shoveler-pend1/approve", data={"site": site, "csrf_token": _csrf(client)}
        )
        assert "Enter a site name to approve into." in resp.text
    assert _client(settings, "shoveler-pend1")["pending"] == 1


def test_approve_twice_is_harmless(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    _as_admin(monkeypatch)
    csrf = _csrf(client)
    client.post("/pending/shoveler-pend1/approve", data={"site": "nebraska", "csrf_token": csrf})
    resp = client.post("/pending/shoveler-pend1/approve", data={"site": "wisconsin", "csrf_token": csrf})
    assert "That shoveler is no longer pending." in resp.text
    assert _client(settings, "shoveler-pend1")["site"] == "nebraska"


def test_reject_deletes_pending(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    _as_admin(monkeypatch)
    resp = client.post("/pending/shoveler-pend1/reject", data={"csrf_token": _csrf(client)})
    assert "Rejected shoveler-pend1." in resp.text
    assert _client(settings, "shoveler-pend1") is None


def test_disable_and_reenable_any_shoveler(client, settings, monkeypatch):
    seed_client(settings, "shoveler-neb1", owner_sub="someone-else")
    _as_admin(monkeypatch)
    csrf = _csrf(client)
    resp = client.post("/credentials/shoveler-neb1/disable", data={"csrf_token": csrf})
    assert "Shoveler shoveler-neb1 disabled." in resp.text
    row = _client(settings, "shoveler-neb1")
    assert (row["disabled"], row["disabled_reason"]) == (1, "disabled-by-admin")
    assert "/credentials/shoveler-neb1/enable" in resp.text

    resp = client.post("/credentials/shoveler-neb1/enable", data={"csrf_token": csrf})
    assert "Shoveler shoveler-neb1 re-enabled." in resp.text
    assert _client(settings, "shoveler-neb1")["disabled"] == 0


def test_idle_shoveler_can_be_reenabled(client, settings, monkeypatch):
    seed_client(settings, "shoveler-neb1")
    conn = db.connect(settings.db_path)
    try:
        db.disable_client(conn, "shoveler-neb1", "idle")
    finally:
        conn.close()
    _as_admin(monkeypatch)
    client.post("/credentials/shoveler-neb1/enable", data={"csrf_token": _csrf(client)})
    assert _client(settings, "shoveler-neb1")["disabled"] == 0


def test_pending_shoveler_cannot_be_disabled_or_enabled(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    _as_admin(monkeypatch)
    csrf = _csrf(client)
    assert "No such shoveler." in client.post(
        "/credentials/shoveler-pend1/disable", data={"csrf_token": csrf}
    ).text
    assert "isn&#39;t disabled" in client.post(
        "/credentials/shoveler-pend1/enable", data={"csrf_token": csrf}
    ).text
    assert _client(settings, "shoveler-pend1")["pending"] == 1


def test_create_token_needs_a_site(client, settings, monkeypatch):
    _as_admin(monkeypatch)
    resp = client.post("/registration-tokens", data={"site": " ", "csrf_token": _csrf(client)})
    assert "Enter a site name for the token." in resp.text
    assert 'id="token"' not in resp.text


def test_revoke_unused_token(client, settings, monkeypatch):
    token = seed_token(settings, site="nebraska")
    token_hash = tokens.hash_registration_token(token)
    _as_admin(monkeypatch)
    page = client.get("/dashboard").text
    assert ">unused<" in page and f"/registration-tokens/{token_hash}/revoke" in page
    resp = client.post(f"/registration-tokens/{token_hash}/revoke", data={"csrf_token": _csrf(client)})
    assert "Registration token revoked." in resp.text and ">revoked<" in resp.text
    again = client.post(f"/registration-tokens/{token_hash}/revoke", data={"csrf_token": _csrf(client)})
    assert "That token was already used or revoked." in again.text


def test_posts_require_csrf(client, settings, monkeypatch):
    seed_pending(settings, "shoveler-pend1")
    seed_client(settings, "shoveler-neb1")
    _as_admin(monkeypatch)
    client.get("/dashboard")
    for path, form in [
        ("/pending/shoveler-pend1/approve", {"site": "nebraska"}),
        ("/pending/shoveler-pend1/reject", {}),
        ("/registration-tokens", {"site": "nebraska"}),
        ("/credentials/shoveler-neb1/disable", {}),
    ]:
        resp = client.post(path, data=dict(form, csrf_token="bad"))
        assert "Invalid CSRF token." in resp.text, path
    assert _client(settings, "shoveler-pend1")["pending"] == 1
    assert _client(settings, "shoveler-neb1")["disabled"] == 0
