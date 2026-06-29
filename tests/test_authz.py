"""Group-based authorization and per-user site visibility on the dashboard."""

from __future__ import annotations

import portal.main as main_mod
from portal import authz, db, tokens
from portal.auth import UserInfo

ALICE = "http://cilogon.org/serverA/users/11111"  # nebraska
BOB = "http://cilogon.org/serverA/users/22222"     # wisconsin

# COmanage group memberships (the CILogon ``isMemberOf`` claim).
ALICE_GROUPS = ("CO:members:active", "shoveler-nebraska")
BOB_GROUPS = ("shoveler-wisconsin",)
NOBODY_GROUPS = ("CO:members:active",)

PREFIX = "shoveler-"


def test_sites_for_groups():
    assert authz.sites_for_groups(ALICE_GROUPS, PREFIX) == ["nebraska"]
    assert authz.sites_for_groups(BOB_GROUPS, PREFIX) == ["wisconsin"]
    # A user in no site group (only built-in COmanage groups) manages nothing.
    assert authz.sites_for_groups(NOBODY_GROUPS, PREFIX) == []
    assert authz.sites_for_groups((), PREFIX) == []


def test_sites_for_groups_multiple_and_deduped():
    groups = ("shoveler-nebraska", "shoveler-wisconsin", "shoveler-nebraska")
    assert authz.sites_for_groups(groups, PREFIX) == ["nebraska", "wisconsin"]


def test_sites_for_groups_ignores_empty_and_bare_prefix():
    # A group equal to the bare prefix has no site suffix; ignore it.
    assert authz.sites_for_groups(("shoveler-",), PREFIX) == []


def test_may_manage_site():
    assert authz.may_manage_site(ALICE_GROUPS, PREFIX, "nebraska")
    assert not authz.may_manage_site(ALICE_GROUPS, PREFIX, "wisconsin")


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
        main_mod,
        "current_user",
        lambda session: UserInfo(ALICE, "alice@unl.edu", "Alice", ALICE_GROUPS),
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
        main_mod,
        "current_user",
        lambda session: UserInfo("nobody", None, None, NOBODY_GROUPS),
    )
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Not yet authorized" in resp.text
