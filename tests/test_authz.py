"""Only members of ADMIN_GROUP may use the portal; everyone else is refused."""

from __future__ import annotations

import re

import pytest

import portal.main as main_mod
from helpers import seed_client, seed_pending, seed_token
from portal import authz, db, tokens
from portal.auth import UserInfo

ADMIN_GROUPS = ("CO:members:active", "shoveler-admins")  # conftest's ADMIN_GROUP
OTHER_GROUPS = ("CO:members:active", "shoveler-nebraska")


def _login(monkeypatch, groups):
    monkeypatch.setattr(
        main_mod, "current_user", lambda session: UserInfo("someone", "s@x.org", "S", groups)
    )


def test_is_admin():
    assert authz.is_admin("shoveler-admins", ADMIN_GROUPS)
    assert not authz.is_admin("shoveler-admins", OTHER_GROUPS)
    assert not authz.is_admin("shoveler-admins", ())
    # An empty admin group admits nobody, even someone with an empty group.
    assert not authz.is_admin("", ("",))


def test_logged_out_sees_login_page(client):
    resp = client.get("/")
    assert "Log in with CILogon" in resp.text
    assert client.get("/dashboard", follow_redirects=False).headers["location"] == "/"


def test_non_admin_sees_not_authorized_and_no_data(client, settings, monkeypatch):
    seed_client(settings, "shoveler-neb1")
    seed_pending(settings, "shoveler-pend1")
    _login(monkeypatch, OTHER_GROUPS)
    resp = client.get("/dashboard")
    assert "Not authorized" in resp.text
    assert "shoveler-neb1" not in resp.text and "shoveler-pend1" not in resp.text


def test_shoveler_page_is_for_admins_only(client, settings, monkeypatch):
    seed_client(settings, "shoveler-neb1")
    assert client.get("/shovelers/shoveler-neb1", follow_redirects=False).headers[
        "location"
    ] == "/"
    _login(monkeypatch, OTHER_GROUPS)
    resp = client.get("/shovelers/shoveler-neb1")
    assert "Not authorized" in resp.text and "shoveler-neb1" not in resp.text


def test_admin_sees_dashboard(client, settings, monkeypatch):
    _login(monkeypatch, ADMIN_GROUPS)
    resp = client.get("/dashboard")
    assert "Registered shovelers" in resp.text and "Not authorized" not in resp.text


def _state(settings):
    conn = db.connect(settings.db_path)
    try:
        return (
            db.get_client(conn, "shoveler-pend1"),
            db.get_client(conn, "shoveler-neb1")["disabled"],
            db.get_client(conn, "shoveler-off")["disabled"],
            [dict(r) for r in db.list_registration_tokens(conn)],
        )
    finally:
        conn.close()


@pytest.mark.parametrize(
    "path, form",
    [
        ("/pending/shoveler-pend1/approve", {"site": "nebraska"}),
        ("/pending/shoveler-pend1/reject", {}),
        ("/registration-tokens", {"site": "nebraska"}),
        ("/registration-tokens/{token_hash}/revoke", {}),
        ("/credentials/shoveler-neb1/disable", {}),
        ("/credentials/shoveler-off/enable", {}),
    ],
)
def test_non_admin_cannot_change_anything(client, settings, monkeypatch, path, form):
    seed_pending(settings, "shoveler-pend1")
    seed_client(settings, "shoveler-neb1")
    seed_client(settings, "shoveler-off")
    conn = db.connect(settings.db_path)
    try:
        db.disable_client(conn, "shoveler-off", "disabled-by-admin")
    finally:
        conn.close()
    token = seed_token(settings)
    path = path.format(token_hash=tokens.hash_registration_token(token))

    # A real session CSRF token (taken as an admin), so only authz can refuse.
    _login(monkeypatch, ADMIN_GROUPS)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/dashboard").text).group(1)
    before = _state(settings)

    _login(monkeypatch, OTHER_GROUPS)
    resp = client.post(path, data=dict(form, csrf_token=csrf))
    assert "Not authorized" in resp.text
    assert 'id="token"' not in resp.text
    assert _state(settings) == before


def test_logged_out_post_redirects_to_login(client, settings):
    seed_pending(settings, "shoveler-pend1")
    resp = client.post(
        "/pending/shoveler-pend1/approve",
        data={"site": "nebraska", "csrf_token": "x"},
        follow_redirects=False,
    )
    assert resp.status_code == 303 and resp.headers["location"] == "/"
