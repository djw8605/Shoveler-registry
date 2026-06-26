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
