"""Allow-list enforcement and per-user site visibility on the dashboard."""

from __future__ import annotations

import portal.main as main_mod
from portal import authz, db, tokens
from portal.auth import UserInfo

ALICE = "http://cilogon.org/serverA/users/11111"  # nebraska
BOB = "http://cilogon.org/serverA/users/22222"     # wisconsin
NOBODY = "http://cilogon.org/serverA/users/99999"


def test_sites_for_sub(settings):
    assert authz.sites_for_sub(settings.site_admins_file, ALICE) == ["nebraska"]
    assert authz.sites_for_sub(settings.site_admins_file, BOB) == ["wisconsin"]
    assert authz.sites_for_sub(settings.site_admins_file, NOBODY) == []


def test_may_manage_site(settings):
    assert authz.may_manage_site(settings.site_admins_file, ALICE, "nebraska")
    assert not authz.may_manage_site(settings.site_admins_file, ALICE, "wisconsin")


def _seed(settings):
    conn = db.connect(settings.db_path)
    try:
        db.insert_client(
            conn, client_id="shoveler-neb1", secret_hash=tokens.hash_secret("a"),
            site="nebraska", owner_sub=ALICE, owner_email="alice@unl.edu",
        )
        db.insert_client(
            conn, client_id="shoveler-wis1", secret_hash=tokens.hash_secret("b"),
            site="wisconsin", owner_sub=BOB, owner_email="bob@wisc.edu",
        )
    finally:
        conn.close()


def test_dashboard_shows_only_user_sites(app, client, settings, monkeypatch):
    _seed(settings)
    monkeypatch.setattr(
        main_mod, "current_user", lambda session: UserInfo(ALICE, "alice@unl.edu", "Alice")
    )
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    body = resp.text
    assert "shoveler-neb1" in body
    assert "shoveler-wis1" not in body
    assert "nebraska" in body
    assert "wisconsin" not in body


def test_unauthorized_user_gets_not_authorized_page(app, client, settings, monkeypatch):
    monkeypatch.setattr(
        main_mod, "current_user", lambda session: UserInfo(NOBODY, None, None)
    )
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Not yet authorized" in resp.text
