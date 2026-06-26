"""Signing-key generation, loading, JWKS publication, and rotation.

Keys live as PEM files in ``SIGNING_KEY_DIR`` alongside a ``manifest.json``
that records each key's ``kid``/creation time and which one is currently
ACTIVE. All public keys (active + retired) are published in the JWKS so that
tokens signed by a recently-retired key still validate; only the active key
signs new tokens.

Private keys are written ``0600`` and are NEVER logged or returned in any
response.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

log = logging.getLogger("portal.keys")

ALG = "RS256"
MANIFEST = "manifest.json"


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _thumbprint(public_key: RSAPublicKey) -> str:
    """RFC 7638 JWK thumbprint, used as a stable ``kid``."""
    numbers = public_key.public_numbers()
    jwk = {
        "e": _b64url_uint(numbers.e),
        "kty": "RSA",
        "n": _b64url_uint(numbers.n),
    }
    digest = hashlib.sha256(
        json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass(frozen=True)
class SigningKey:
    kid: str
    created_at: str
    private_key: RSAPrivateKey
    public_key: RSAPublicKey

    def jwk(self) -> dict:
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": ALG,
            "kid": self.kid,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


class KeyStore:
    """In-memory view of the on-disk keys, loaded once at startup."""

    def __init__(self, active_kid: str, keys: dict[str, SigningKey]):
        self._active_kid = active_kid
        self._keys = keys

    @property
    def active(self) -> SigningKey:
        return self._keys[self._active_kid]

    def jwks(self) -> dict:
        # Active key first, then the rest (order is cosmetic).
        ordered = [self._keys[self._active_kid]] + [
            k for kid, k in self._keys.items() if kid != self._active_kid
        ]
        return {"keys": [k.jwk() for k in ordered]}


# --- On-disk helpers -----------------------------------------------------

def _manifest_path(key_dir: str) -> str:
    return os.path.join(key_dir, MANIFEST)


def _read_manifest(key_dir: str) -> Optional[dict]:
    path = _manifest_path(key_dir)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_manifest(key_dir: str, manifest: dict) -> None:
    path = _manifest_path(key_dir)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    os.replace(tmp, path)


def generate_key(key_dir: str, *, make_active: bool = True) -> str:
    """Generate a new RSA-2048 signing key, write it 0600, update the manifest.

    Existing keys are never deleted. Returns the new key's ``kid``.
    """
    os.makedirs(key_dir, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = _thumbprint(private_key.public_key())
    filename = f"{kid}.pem"
    path = os.path.join(key_dir, filename)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Create with 0600 from the start; never world/group readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    os.chmod(path, 0o600)

    manifest = _read_manifest(key_dir) or {"active": None, "keys": []}
    created_at = datetime.now(timezone.utc).isoformat()
    manifest["keys"].append({"kid": kid, "file": filename, "created_at": created_at})
    if make_active or manifest.get("active") is None:
        manifest["active"] = kid
    _write_manifest(key_dir, manifest)

    log.info("Generated signing key kid=%s (active=%s)", kid, make_active)
    return kid


def ensure_keys(key_dir: str) -> None:
    """On first start, create an active key if none exists."""
    manifest = _read_manifest(key_dir)
    if manifest and manifest.get("keys"):
        return
    generate_key(key_dir, make_active=True)


def load_keys(key_dir: str) -> KeyStore:
    """Load all keys described by the manifest into a KeyStore."""
    manifest = _read_manifest(key_dir)
    if not manifest or not manifest.get("keys"):
        raise RuntimeError(f"No signing keys found in {key_dir}; run ensure_keys first")

    keys: dict[str, SigningKey] = {}
    for entry in manifest["keys"]:
        path = os.path.join(key_dir, entry["file"])
        with open(path, "rb") as fh:
            private_key = serialization.load_pem_private_key(fh.read(), password=None)
        if not isinstance(private_key, RSAPrivateKey):
            raise RuntimeError(f"Key {entry['kid']} is not an RSA key")
        keys[entry["kid"]] = SigningKey(
            kid=entry["kid"],
            created_at=entry["created_at"],
            private_key=private_key,
            public_key=private_key.public_key(),
        )

    active_kid = manifest.get("active") or manifest["keys"][-1]["kid"]
    if active_kid not in keys:
        raise RuntimeError(f"Active kid {active_kid} not present among loaded keys")
    return KeyStore(active_kid=active_kid, keys=keys)


# --- Rotation CLI --------------------------------------------------------

def _main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    from portal.config import get_settings

    if len(argv) < 2 or argv[1] not in {"generate", "list"}:
        print("usage: python -m portal.keys {generate|list}", file=sys.stderr)
        return 2

    key_dir = get_settings().signing_key_dir
    if argv[1] == "generate":
        kid = generate_key(key_dir, make_active=True)
        print(f"New ACTIVE signing key: {kid}")
        print("Retired keys remain published in JWKS for existing tokens.")
        return 0

    manifest = _read_manifest(key_dir) or {"keys": [], "active": None}
    for entry in manifest["keys"]:
        marker = "* active" if entry["kid"] == manifest.get("active") else ""
        print(f"{entry['kid']}  {entry['created_at']}  {marker}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
