"""End-to-end browser flow: create -> one-time secret -> token -> recreate -> disable."""

from __future__ import annotations

import json
import re

import jwt
import portal.main as main_mod
from jwt.algorithms import RSAAlgorithm
from portal.auth import UserInfo

ALICE = "http://cilogon.org/serverA/users/11111"  # nebraska in conftest


def _login(monkeypatch, sub=ALICE, email="alice@unl.edu"):
    monkeypatch.setattr(
        main_mod, "current_user", lambda session: UserInfo(sub, email, "Alice")
    )


def _csrf(client):
    html = client.get("/dashboard").text
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _field(html, elem_id):
    return re.search(rf'id="{elem_id}"[^>]*>([^<]+)<', html).group(1)


def _verify(client, token, settings):
    jwks = client.get("/.well-known/jwks.json").json()
    hdr = jwt.get_unverified_header(token)
    jwk = next(k for k in jwks["keys"] if k["kid"] == hdr["kid"])
    return jwt.decode(
        token,
        RSAAlgorithm.from_jwk(json.dumps(jwk)),
        algorithms=["RS256"],
        audience=settings.resource_server_id,
    )


def test_create_use_recreate_disable(client, settings, monkeypatch):
    _login(monkeypatch)
    csrf = _csrf(client)

    # Create shows the secret exactly once + a ready-to-paste snippet.
    resp = client.post("/credentials/create", data={"site": "nebraska", "csrf_token": csrf})
    assert resp.status_code == 200
    assert "copy it now" in resp.text and "token_endpoint" in resp.text
    cid = _field(resp.text, "cid")
    secret = _field(resp.text, "secret")

    # The minted token verifies against JWKS with the exact aud + scope claim.
    tok = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret},
    ).json()
    claims = _verify(client, tok["access_token"], settings)
    assert claims["sub"] == cid
    assert claims["aud"] == settings.resource_server_id
    assert claims[settings.scope_claim] == settings.scope_value

    # Recreate rotates the secret; the old one stops working.
    r2 = client.post(f"/credentials/{cid}/recreate", data={"csrf_token": csrf})
    assert "Secret rotated" in r2.text
    new_secret = _field(r2.text, "secret")
    assert new_secret != secret
    old = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret},
    )
    assert old.status_code == 401

    # Disable revokes the credential entirely.
    client.post(f"/credentials/{cid}/disable", data={"csrf_token": csrf})
    after = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": cid, "client_secret": new_secret},
    )
    assert after.status_code == 401


def test_cannot_create_for_unmanaged_site(client, settings, monkeypatch):
    _login(monkeypatch)  # Alice manages nebraska only
    csrf = _csrf(client)
    resp = client.post(
        "/credentials/create", data={"site": "wisconsin", "csrf_token": csrf}
    )
    # Redirected back to dashboard with a flash; no credential created.
    assert resp.url.path == "/dashboard"
    assert "shoveler-" not in resp.text
