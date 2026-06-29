"""Registry-admin view: sees all sites' clients; may disable any of them."""

from __future__ import annotations

import portal.main as main_mod
from portal import authz, db, tokens
from portal.auth import UserInfo

ALICE = "http://cilogon.org/serverA/users/11111"  # nebraska site-admin
CAROL = "http://cilogon.org/serverA/users/30000"  # registry admin (conftest)

ALICE_GROUPS = ("shoveler-nebraska",)
CAROL_GROUPS = ("shoveler-admins",)  # registry admin group (conftest)


def test_is_registry_admin(settings):
    g = settings.registry_admin_group
    assert authz.is_registry_admin(g, CAROL_GROUPS)
    assert not authz.is_registry_admin(g, ALICE_GROUPS)
    assert not authz.is_registry_admin(g, ())
    # An empty admin group disables the role even for matching membership.
    assert not authz.is_registry_admin("", CAROL_GROUPS)


def _seed(settings):
    conn = db.connect(settings.db_path)
    try:
        db.insert_client(
            conn, client_id="shoveler-neb1", secret_hash=tokens.hash_secret("a"),
            site="nebraska", owner_sub=ALICE, owner_email="alice@unl.edu",
        )
        db.insert_client(
            conn, client_id="shoveler-wis1", secret_hash=tokens.hash_secret("b"),
            site="wisconsin", owner_sub="someone", owner_email="bob@wisc.edu",
        )
    finally:
        conn.close()


def test_admin_sees_all_sites(app, client, settings, monkeypatch):
    _seed(settings)
    monkeypatch.setattr(main_mod, "current_user", lambda s: UserInfo(CAROL, "c@x.org", "Carol", CAROL_GROUPS))
    resp = client.get("/admin")
    assert resp.status_code == 200
    # Both sites' clients are visible, with owner emails.
    assert "shoveler-neb1" in resp.text and "shoveler-wis1" in resp.text
    assert "nebraska" in resp.text and "wisconsin" in resp.text
    assert "bob@wisc.edu" in resp.text


def test_non_admin_cannot_reach_admin(app, client, settings, monkeypatch):
    monkeypatch.setattr(main_mod, "current_user", lambda s: UserInfo(ALICE, "a@x.org", "Alice", ALICE_GROUPS))
    resp = client.get("/admin", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard"


def test_admin_can_disable_any_client(app, client, settings, monkeypatch):
    _seed(settings)
    monkeypatch.setattr(main_mod, "current_user", lambda s: UserInfo(CAROL, "c@x.org", "Carol", CAROL_GROUPS))
    csrf = __import__("re").search(
        r'name="csrf_token" value="([^"]+)"', client.get("/admin").text
    ).group(1)
    # Carol disables a client she does not own, on a site she doesn't manage.
    client.post("/admin/shoveler-wis1/disable", data={"csrf_token": csrf})
    conn = db.connect(settings.db_path)
    try:
        row = db.get_client(conn, "shoveler-wis1")
        assert row["disabled"] == 1
        assert row["disabled_reason"] == "revoked-by-admin"
    finally:
        conn.close()


def test_admin_disable_requires_csrf(app, client, settings, monkeypatch):
    _seed(settings)
    monkeypatch.setattr(main_mod, "current_user", lambda s: UserInfo(CAROL, "c@x.org", "Carol", CAROL_GROUPS))
    client.get("/admin")  # establish session/csrf
    resp = client.post(
        "/admin/shoveler-neb1/disable", data={"csrf_token": "bad"}, follow_redirects=False
    )
    assert resp.status_code == 303
    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, "shoveler-neb1")["disabled"] == 0
    finally:
        conn.close()
