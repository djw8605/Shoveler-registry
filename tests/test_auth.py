"""CILogon login: where groups come from, and what login logs (names, not values)."""

from __future__ import annotations

import logging
import time
from types import SimpleNamespace

import httpx
import jwt
import pytest

import portal.auth as auth
from helpers import new_key

ISSUER = "https://cilogon.org"
META = {
    "issuer": ISSUER,
    "token_endpoint": "https://cilogon.org/oauth2/token",
    "userinfo_endpoint": "https://cilogon.org/oauth2/userinfo",
    "jwks_uri": "https://cilogon.org/oauth2/certs",
}


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", META["userinfo_endpoint"])
            raise httpx.HTTPStatusError(
                f"{self.status_code} error", request=request,
                response=httpx.Response(self.status_code, request=request),
            )


@pytest.fixture
def oidc(settings, monkeypatch):
    """An OIDCClient talking to a fake CILogon; returns (client, set_responses)."""
    key = new_key()
    client = auth.OIDCClient(settings)
    monkeypatch.setattr(client, "metadata", lambda: META)
    monkeypatch.setattr(
        client, "_jwks",
        lambda: SimpleNamespace(get_signing_key_from_jwt=lambda _t: SimpleNamespace(key=key.public_key())),
    )
    calls = {"userinfo": 0}
    state = {}

    def set_responses(id_claims, *, scope="openid email profile org.cilogon.userinfo",
                      userinfo=(200, {})):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": settings.cilogon_client_id, "sub": "http://cilogon.org/serverA/users/1",
                  "iat": now, "exp": now + 300, "nonce": "n0nce", "email": "alice@example.org"}
        claims.update(id_claims)
        state["token"] = {"id_token": jwt.encode(claims, key, algorithm="RS256"),
                          "access_token": "opaque-access-token", "scope": scope}
        state["userinfo"] = userinfo

    def fake_post(url, data, timeout):
        assert url == META["token_endpoint"]
        return _Resp(200, state["token"])

    def fake_get(url, headers, timeout):
        assert url == META["userinfo_endpoint"]
        calls["userinfo"] += 1
        return _Resp(*state["userinfo"])

    monkeypatch.setattr(auth.httpx, "post", fake_post)
    monkeypatch.setattr(auth.httpx, "get", fake_get)
    return client, set_responses, calls


def test_groups_from_id_token(oidc, caplog):
    client, set_responses, calls = oidc
    set_responses({"isMemberOf": ["CO:members:active", "shoveler-admins"]})
    with caplog.at_level(logging.INFO, logger="portal.auth"):
        user = client.exchange_code("code", "verifier", "n0nce")
    assert user.groups == ("CO:members:active", "shoveler-admins")
    assert calls["userinfo"] == 0
    text = caplog.text
    assert "granted_scope='openid email profile org.cilogon.userinfo'" in text
    assert "'isMemberOf'" in text and "groups=2 (from id_token)" in text
    # Claim names only: no values (beyond the sub identifier), never tokens.
    assert "alice@example.org" not in text and "opaque-access-token" not in text


def test_groups_from_userinfo_when_id_token_has_none(oidc, caplog):
    client, set_responses, calls = oidc
    set_responses({}, userinfo=(200, {"sub": "x", "isMemberOf": ["shoveler-admins"]}))
    with caplog.at_level(logging.INFO, logger="portal.auth"):
        user = client.exchange_code("code", "verifier", "n0nce")
    assert user.groups == ("shoveler-admins",)
    assert calls["userinfo"] == 1
    assert "userinfo: claims=['isMemberOf', 'sub']" in caplog.text
    assert "groups=1 (from userinfo)" in caplog.text


def test_no_groups_anywhere_is_logged(oidc, caplog):
    client, set_responses, _ = oidc
    set_responses({}, scope="openid email profile", userinfo=(200, {"sub": "x", "email": "e"}))
    with caplog.at_level(logging.INFO, logger="portal.auth"):
        user = client.exchange_code("code", "verifier", "n0nce")
    assert user.groups == ()
    # The log shows the scope wasn't granted and no claim carried groups.
    assert "granted_scope='openid email profile'" in caplog.text
    assert "userinfo: claims=['email', 'sub']" in caplog.text
    assert "groups=0 (from userinfo)" in caplog.text


def test_userinfo_failure_is_a_warning_not_silent(oidc, caplog):
    client, set_responses, _ = oidc
    set_responses({}, userinfo=(403, {}))
    with caplog.at_level(logging.INFO, logger="portal.auth"):
        user = client.exchange_code("code", "verifier", "n0nce")
    assert user.groups == ()
    failures = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert failures and "userinfo: request failed: 403" in failures[0].getMessage()
