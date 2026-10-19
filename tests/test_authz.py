"""Group-based authorization and per-user site visibility on the dashboard."""

from __future__ import annotations

import re

import portal.main as main_mod
from helpers import seed_client
from portal import authz
from portal.auth import UserInfo

ALICE = "http://cilogon.org/serverA/users/11111"  # nebraska
BOB = "http://cilogon.org/serverA/users/22222"     # wisconsin

# COmanage group memberships (the CILogon ``isMemberOf`` claim).
ALICE_GROUPS = ("CO:members:active", "shoveler-nebraska")
BOB_GROUPS = ("shoveler-wisconsin",)
NOBODY_GROUPS = ("CO:members:active",)

PREFIX = "shoveler-"
# The registry-admin group (conftest) shares the site prefix, as in the docs.
ADMIN = "shoveler-admins"


def test_sites_for_groups():
    assert authz.sites_for_groups(ALICE_GROUPS, PREFIX, admin_group=ADMIN) == ["nebraska"]
    assert authz.sites_for_groups(BOB_GROUPS, PREFIX, admin_group=ADMIN) == ["wisconsin"]
    # A user in no site group (only built-in COmanage groups) manages nothing.
    assert authz.sites_for_groups(NOBODY_GROUPS, PREFIX, admin_group=ADMIN) == []
    assert authz.sites_for_groups((), PREFIX, admin_group=ADMIN) == []


def test_sites_for_groups_multiple_and_deduped():
    groups = ("shoveler-nebraska", "shoveler-wisconsin", "shoveler-nebraska")
    assert authz.sites_for_groups(groups, PREFIX, admin_group=ADMIN) == ["nebraska", "wisconsin"]


def test_sites_for_groups_ignores_empty_and_bare_prefix():
    # A group equal to the bare prefix has no site suffix; ignore it.
    assert authz.sites_for_groups(("shoveler-",), PREFIX, admin_group=ADMIN) == []


def test_may_manage_site():
    assert authz.may_manage_site(ALICE_GROUPS, PREFIX, "nebraska", admin_group=ADMIN)
    assert not authz.may_manage_site(ALICE_GROUPS, PREFIX, "wisconsin", admin_group=ADMIN)


def test_admin_group_is_not_a_site():
    # "shoveler-admins" starts with the prefix but is the admin role, not site "admins".
    groups = ("shoveler-admins", "shoveler-nebraska")
    assert authz.sites_for_groups(groups, PREFIX, admin_group=ADMIN) == ["nebraska"]
    assert not authz.may_manage_site(groups, PREFIX, "admins", admin_group=ADMIN)


def test_without_admin_group_every_prefixed_group_is_a_site():
    # With no REGISTRY_ADMIN_GROUP configured there is nothing to exclude.
    assert authz.sites_for_groups(("shoveler-admins",), PREFIX, admin_group="") == ["admins"]


def _seed(settings):
    seed_client(settings, "shoveler-neb1", site="nebraska", owner_sub=ALICE,
                owner_email="alice@unl.edu")
    seed_client(settings, "shoveler-wis1", site="wisconsin", owner_sub=BOB,
                owner_email="bob@wisc.edu")


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


def test_registry_admin_only_has_no_admins_site(app, client, settings, monkeypatch):
    monkeypatch.setattr(
        main_mod,
        "current_user",
        lambda session: UserInfo("carol", "c@x.org", "Carol", (settings.registry_admin_group,)),
    )
    resp = client.get("/dashboard")
    # No site groups: the not-authorized page, not a card for a site "admins".
    assert "Not yet authorized" in resp.text
    assert 'name="site" value="admins"' not in resp.text


def test_cannot_create_registration_token_for_admin_group(app, client, settings, monkeypatch):
    groups = (settings.registry_admin_group, "shoveler-nebraska")
    monkeypatch.setattr(
        main_mod, "current_user", lambda session: UserInfo("carol", "c@x.org", "Carol", groups)
    )
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/dashboard").text).group(1)
    resp = client.post("/registration-tokens", data={"site": "admins", "csrf_token": csrf})
    assert resp.url.path == "/dashboard"
    assert "You may not manage that site." in resp.text
    assert 'id="token"' not in resp.text
