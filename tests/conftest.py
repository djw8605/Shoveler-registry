"""Shared test fixtures: an isolated portal Settings + app per test."""

from __future__ import annotations

import pytest

from portal.config import Settings


@pytest.fixture
def site_admins_file(tmp_path):
    path = tmp_path / "site-admins.yaml"
    path.write_text(
        """
nebraska:
  - sub: "http://cilogon.org/serverA/users/11111"
    email: "alice@unl.edu"
wisconsin:
  - sub: "http://cilogon.org/serverA/users/22222"
    email: "bob@wisc.edu"
""".strip()
    )
    return str(path)


@pytest.fixture
def settings(tmp_path, site_admins_file) -> Settings:
    return Settings(
        cilogon_client_id="portal-test-client",
        cilogon_client_secret="portal-test-secret",
        cilogon_discovery_url="https://cilogon.org/.well-known/openid-configuration",
        portal_base_url="https://portal.test",
        session_secret="x" * 48,
        db_path=str(tmp_path / "portal.db"),
        signing_key_dir=str(tmp_path / "keys"),
        site_admins_file=site_admins_file,
        token_issuer="https://portal.test/",
        resource_server_id="my_rabbit_server",
        token_ttl_seconds=14400,
        scope_claim="extra_scope",
        scope_value="my_rabbit_server.write:*/xrd-shoveled",
        idle_days=30,
        admin_contact="admin@example.org",
        token_rate_limit=1000,
        token_rate_window=60,
    )


@pytest.fixture
def app(settings):
    from portal.main import create_app

    return create_app(settings)


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    # https base URL so the Secure session cookie is sent back (PORTAL_BASE_URL
    # is https, which marks the cookie Secure).
    return TestClient(app, base_url="https://testserver")
