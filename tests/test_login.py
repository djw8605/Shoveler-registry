"""CILogon login (Authlib): redirect shape, callback validation, group capture.

CILogon is stubbed at the HTTP transport: an ``httpx.MockTransport`` serves the
discovery document, JWKS, token and userinfo endpoints, issuing ID tokens
signed with a test key. Everything above the transport (discovery, state,
nonce and PKCE bookkeeping in the session, the token request and its client
authentication, the JWKS fetch, ID-token validation, the userinfo call, the
session login) is the real code path.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest

import helpers

ISSUER = "https://cilogon.test"
SUB = "http://cilogon.org/serverA/users/30000"
ADMIN = "shoveler-admins"
ACCESS_TOKEN = "cilogon-access-token"


class FakeCILogon:
    def __init__(self, settings):
        self.settings = settings
        self.key = helpers.new_key()
        self.requests: list[httpx.Request] = []
        self.claims: dict = {"isMemberOf": [ADMIN]}
        self.userinfo: dict = {}
        self.userinfo_error: Exception | None = None
        self.nonce: str | None = None
        self.nonce_override: str | None = None

    def requests_to(self, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == path]

    def id_token(self) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": self.settings.cilogon_client_id,
            "sub": SUB,
            "iat": now,
            "exp": now + 300,
            "nonce": self.nonce_override or self.nonce,
            "email": "carol@example.org",
            **self.claims,
        }
        return jwt.encode(
            claims, self.key, algorithm="RS256",
            headers={"kid": helpers.kid_for(self.key)},
        )

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if str(request.url) == self.settings.cilogon_discovery_url:
            return httpx.Response(200, json={
                "issuer": ISSUER,
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/oauth2/token",
                "userinfo_endpoint": ISSUER + "/oauth2/userinfo",
                "jwks_uri": ISSUER + "/oauth2/certs",
                "id_token_signing_alg_values_supported": ["RS256"],
            })
        path = request.url.path
        if path == "/oauth2/certs":
            return httpx.Response(200, json={"keys": [helpers.public_jwk(self.key)]})
        if path == "/oauth2/token":
            return httpx.Response(200, json={
                "access_token": ACCESS_TOKEN,
                "token_type": "Bearer",
                "expires_in": 900,
                "id_token": self.id_token(),
            })
        if path == "/oauth2/userinfo":
            if self.userinfo_error:
                raise self.userinfo_error
            return httpx.Response(200, json={"sub": SUB, **self.userinfo})
        return httpx.Response(404)


@pytest.fixture
def idp(app, settings):
    """Stubbed CILogon; ``idp.requests`` records every request Authlib sends."""
    fake = FakeCILogon(settings)
    transport = httpx.MockTransport(fake.handle)
    app.state.oauth.cilogon.client_kwargs["transport"] = transport
    return fake


def start_login(client, idp) -> dict:
    resp = client.get("/auth/login", follow_redirects=False)
    assert resp.status_code in (302, 303)
    loc = urlparse(resp.headers["location"])
    params = {k: v[0] for k, v in parse_qs(loc.query).items()}
    idp.nonce = params["nonce"]
    idp.authorize_url = f"{loc.scheme}://{loc.netloc}{loc.path}"
    return params


def finish_login(client, state: str, code: str = "the-code"):
    return client.get(
        "/auth/callback", params={"code": code, "state": state}, follow_redirects=False
    )


def logged_in(client) -> bool:
    resp = client.get("/dashboard", follow_redirects=False)
    return resp.status_code == 200


def test_login_redirects_with_state_nonce_and_pkce(client, idp, settings):
    params = start_login(client, idp)
    assert idp.authorize_url == ISSUER + "/authorize"
    assert params["response_type"] == "code"
    assert params["client_id"] == settings.cilogon_client_id
    assert params["redirect_uri"] == settings.redirect_uri
    assert params["scope"] == "openid email profile org.cilogon.userinfo"
    assert params["state"] and params["nonce"]
    assert params["code_challenge_method"] == "S256"
    assert params["code_challenge"]


def test_callback_logs_in_admin_with_client_secret_post_and_pkce(client, idp, settings):
    params = start_login(client, idp)
    resp = finish_login(client, params["state"])
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard"
    assert logged_in(client)

    [token_req] = idp.requests_to("/oauth2/token")
    assert token_req.method == "POST"
    form = {k: v[0] for k, v in parse_qs(token_req.content.decode()).items()}
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "the-code"
    assert form["code_verifier"]
    assert form["redirect_uri"] == settings.redirect_uri
    assert form["client_id"] == settings.cilogon_client_id
    assert form["client_secret"] == settings.cilogon_client_secret
    assert "authorization" not in token_req.headers  # not client_secret_basic
    assert idp.requests_to("/oauth2/certs")  # ID token verified via the JWKS


def test_non_admin_is_logged_in_but_not_authorized(client, idp):
    idp.claims = {"isMemberOf": ["some-other-group"]}
    params = start_login(client, idp)
    assert finish_login(client, params["state"]).status_code == 303
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "admin@example.org" in resp.text  # the not-authorized page


def test_groups_fall_back_to_userinfo(client, idp):
    idp.claims = {}  # no isMemberOf in the ID token
    idp.userinfo = {"isMemberOf": [{"name": ADMIN}]}  # COmanage object form
    params = start_login(client, idp)
    finish_login(client, params["state"])
    resp = client.get("/dashboard")
    assert "admin@example.org" not in resp.text
    [userinfo_req] = idp.requests_to("/oauth2/userinfo")
    assert userinfo_req.headers["authorization"] == f"Bearer {ACCESS_TOKEN}"


def test_userinfo_failure_means_no_groups(client, idp, caplog):
    idp.claims = {}
    idp.userinfo_error = httpx.ConnectError("down")
    params = start_login(client, idp)
    assert finish_login(client, params["state"]).headers["location"] == "/dashboard"
    assert "admin@example.org" in client.get("/dashboard").text
    assert "userinfo group lookup failed" in caplog.text


def test_state_mismatch_is_rejected(client, idp):
    start_login(client, idp)
    resp = finish_login(client, "not-the-state")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert not logged_in(client)
    assert not idp.requests_to("/oauth2/token")  # no code exchange was attempted


def test_callback_without_login_start_is_rejected(client, idp):
    resp = finish_login(client, "anything")
    assert resp.headers["location"] == "/"
    assert not logged_in(client)


def test_state_is_single_use(client, idp):
    params = start_login(client, idp)
    assert finish_login(client, params["state"]).headers["location"] == "/dashboard"
    replay = finish_login(client, params["state"])
    assert replay.headers["location"] == "/"
    assert len(idp.requests_to("/oauth2/token")) == 1  # the replay never got there


def test_nonce_mismatch_is_rejected(client, idp):
    params = start_login(client, idp)
    idp.nonce_override = "attacker-chosen"
    resp = finish_login(client, params["state"])
    assert resp.headers["location"] == "/"
    assert not logged_in(client)


def test_idp_error_is_rejected(client, idp):
    start_login(client, idp)
    resp = client.get(
        "/auth/callback",
        params={"error": "access_denied", "error_description": "no"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert not logged_in(client)
