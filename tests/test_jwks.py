"""JWKS publishes active + retired keys; tokens verify against the set."""

from __future__ import annotations

import json

import jwt
from jwt.algorithms import RSAAlgorithm

from portal import keys, tokens


def _verify_against_jwks(token, jwks, audience):
    header = jwt.get_unverified_header(token)
    jwk = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    key = RSAAlgorithm.from_jwk(json.dumps(jwk))
    return jwt.decode(token, key, algorithms=["RS256"], audience=audience)


def test_jwks_includes_active_and_retired(settings):
    key_dir = settings.signing_key_dir
    kid1 = keys.generate_key(key_dir, make_active=True)
    kid2 = keys.generate_key(key_dir, make_active=True)  # rotate; kid1 retired

    store = keys.load_keys(key_dir)
    jwks = store.jwks()
    published = {k["kid"] for k in jwks["keys"]}
    assert kid1 in published and kid2 in published
    assert store.active.kid == kid2

    for k in jwks["keys"]:
        assert k["use"] == "sig"
        assert k["alg"] == "RS256"
        assert k["kty"] == "RSA"
        assert "n" in k and "e" in k


def test_token_signed_by_active_verifies_against_jwks(settings):
    keys.ensure_keys(settings.signing_key_dir)
    store = keys.load_keys(settings.signing_key_dir)
    token = tokens.mint_token(settings, store, "shoveler-abc")
    claims = _verify_against_jwks(token, store.jwks(), settings.resource_server_id)
    assert claims["sub"] == "shoveler-abc"


def test_retired_key_token_still_verifies_after_rotation(settings):
    key_dir = settings.signing_key_dir
    keys.generate_key(key_dir, make_active=True)
    store_before = keys.load_keys(key_dir)
    old_token = tokens.mint_token(settings, store_before, "shoveler-old")

    # Rotate: a new active key, old one retired but still published.
    keys.generate_key(key_dir, make_active=True)
    store_after = keys.load_keys(key_dir)

    claims = _verify_against_jwks(
        old_token, store_after.jwks(), settings.resource_server_id
    )
    assert claims["sub"] == "shoveler-old"


def test_session_secret_generated_once_and_private(settings):
    import os
    import stat

    first = keys.load_or_create_session_secret(settings.signing_key_dir)
    path = os.path.join(settings.signing_key_dir, keys.SESSION_SECRET_FILE)
    assert len(first) >= 48
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    # Reused on later starts, so sessions survive restarts.
    assert keys.load_or_create_session_secret(settings.signing_key_dir) == first


def test_app_without_session_secret_uses_generated_one(settings):
    import dataclasses
    import os

    from fastapi.testclient import TestClient
    from portal.main import create_app

    no_secret = dataclasses.replace(settings, session_secret="")
    client = TestClient(create_app(no_secret), base_url="https://testserver")
    assert client.get("/").status_code == 200
    assert os.path.exists(os.path.join(settings.signing_key_dir, keys.SESSION_SECRET_FILE))



# --- Operator-supplied signing key (SIGNING_KEY_FILE) ------------------------

def _write_pem(path, key, fmt):
    from cryptography.hazmat.primitives import serialization

    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, fmt, serialization.NoEncryption()
        )
    )
    return str(path)


def test_external_key_signs_tokens_rabbitmq_can_verify(settings, tmp_path):
    """The key RabbitMQ already trusts (PKCS#1, as the shoveler's createtoken
    reads it) signs /token's access tokens under the configured kid."""
    import dataclasses
    import os

    from cryptography.hazmat.primitives import serialization
    from fastapi.testclient import TestClient
    from helpers import make_assertion, new_key, seed_client, token_form
    from portal.main import create_app

    rabbit_key = new_key()
    pem = _write_pem(tmp_path / "rabbit.pem", rabbit_key, serialization.PrivateFormat.TraditionalOpenSSL)
    ext = dataclasses.replace(settings, signing_key_file=pem, signing_key_id="xrdshoveler")
    client = TestClient(create_app(ext), base_url="https://testserver")

    # The JWKS publishes only that key, under that kid.
    jwks = client.get("/.well-known/jwks.json").json()
    assert [k["kid"] for k in jwks["keys"]] == ["xrdshoveler"]
    assert jwks["keys"][0]["n"] == keys._b64url_uint(rabbit_key.public_key().public_numbers().n)
    # No keys were generated.
    assert not os.path.exists(os.path.join(settings.signing_key_dir, keys.MANIFEST))

    shoveler_key = seed_client(ext, "shoveler-ext1", key=new_key())
    resp = client.post(
        "/token", data=token_form(make_assertion(shoveler_key, "shoveler-ext1", "https://portal.test/token"))
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    assert jwt.get_unverified_header(token)["kid"] == "xrdshoveler"
    # Verify with the plain public key, as RabbitMQ does with a static key.
    public_pem = rabbit_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    claims = jwt.decode(token, public_pem, algorithms=["RS256"], audience=settings.resource_server_id)
    assert claims[settings.scope_claim] == settings.scope_value


def test_external_key_pkcs8_and_default_kid(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from helpers import new_key

    key = new_key()
    pem = _write_pem(tmp_path / "k.pem", key, serialization.PrivateFormat.PKCS8)
    store = keys.load_external_key(pem)
    assert store.active.kid == keys._thumbprint(key.public_key())


def test_external_key_must_be_rsa(tmp_path):
    import pytest
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = _write_pem(
        tmp_path / "ec.pem", ec.generate_private_key(ec.SECP256R1()), serialization.PrivateFormat.PKCS8
    )
    with pytest.raises(RuntimeError, match="not an RSA private key"):
        keys.load_external_key(pem, "xrdshoveler")
