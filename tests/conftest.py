"""Shared test fixtures: an isolated portal Settings + app per test."""

from __future__ import annotations

import pytest

from portal.config import Settings


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        cilogon_client_id="portal-test-client",
        cilogon_client_secret="portal-test-secret",
        cilogon_discovery_url="https://cilogon.org/.well-known/openid-configuration",
        portal_base_url="https://portal.test",
        session_secret="x" * 48,
        db_path=str(tmp_path / "portal.db"),
        signing_key_dir=str(tmp_path / "keys"),
        token_issuer="https://portal.test/",
        resource_server_id="my_rabbit_server",
        token_ttl_seconds=14400,
        scope_claim="scope",
        scope_value="my_rabbit_server.write:xrd-mon/shoveled-xrd",
        idle_days=30,
        admin_contact="admin@example.org",
        token_rate_limit=1000,
        token_rate_window=60,
        registration_token_ttl_seconds=259200,
        register_rate_limit=1000,
        register_rate_window=60,
        assertion_max_lifetime_seconds=300,
        allow_pending_registration=True,
        max_pending_clients=100,
        pending_client_ttl_seconds=604800,
        # Members of this COmanage group are the only users of the portal.
        admin_group="shoveler-admins",
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
