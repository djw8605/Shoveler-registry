"""Storage-level behaviour: token spending, revocation, replay table, schema guard."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from helpers import kid_for, public_jwk, seed_token, shared_key
from portal import db, tokens


def _register(conn, token, client_id, now=None):
    key = shared_key()
    return db.register_client(
        conn,
        token_hash=tokens.hash_registration_token(token),
        now=now or db.utcnow_iso(),
        client_id=client_id,
        client_name="shoveler",
        public_jwk=json.dumps(public_jwk(key)),
        kid=kid_for(key),
        key_thumbprint=kid_for(key),
    )


def test_register_client_spends_token_and_inherits_site_and_owner(settings):
    token = seed_token(settings, site="nebraska", owner_sub="alice", owner_email="a@x")
    conn = db.connect(settings.db_path)
    try:
        assert _register(conn, token, "shoveler-1")
        row = db.get_client(conn, "shoveler-1")
        assert (row["site"], row["owner_sub"], row["owner_email"]) == ("nebraska", "alice", "a@x")
        tok = db.get_registration_token(conn, tokens.hash_registration_token(token))
        assert tok["used_at"] is not None and tok["client_id"] == "shoveler-1"
        # Spent: a second use creates nothing.
        assert not _register(conn, token, "shoveler-2")
        assert db.get_client(conn, "shoveler-2") is None
    finally:
        conn.close()


def test_register_client_rejects_expired_revoked_unknown(settings):
    expired = seed_token(settings, expires_in=-1)
    revoked = seed_token(settings)
    conn = db.connect(settings.db_path)
    try:
        assert db.revoke_registration_token(conn, tokens.hash_registration_token(revoked))
        assert not _register(conn, expired, "shoveler-e")
        assert not _register(conn, revoked, "shoveler-r")
        assert not _register(conn, "never-issued", "shoveler-u")
        assert conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 0
    finally:
        conn.close()


def test_used_token_cannot_be_revoked(settings):
    token = seed_token(settings)
    conn = db.connect(settings.db_path)
    try:
        assert _register(conn, token, "shoveler-1")
        assert not db.revoke_registration_token(conn, tokens.hash_registration_token(token))
    finally:
        conn.close()


def test_iso_timestamps_compare_lexically():
    # expires_at > now is evaluated in SQL on strings; fixed width keeps it right.
    base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    later = base + timedelta(microseconds=1)
    assert db.to_iso(base) < db.to_iso(later)


def test_record_assertion_rejects_replay_and_purges(settings):
    db.init_db(settings.db_path)
    conn = db.connect(settings.db_path)
    try:
        assert db.record_assertion(conn, client_id="c", jti="j1", exp=100, purge_before=0)
        assert not db.record_assertion(conn, client_id="c", jti="j1", exp=100, purge_before=0)
        # Same jti from a different client is a different assertion.
        assert db.record_assertion(conn, client_id="d", jti="j1", exp=100, purge_before=0)
        # Rows past their exp are purged.
        db.record_assertion(conn, client_id="c", jti="j2", exp=500, purge_before=200)
        left = {r["jti"] + r["client_id"] for r in conn.execute("SELECT * FROM used_assertions")}
        assert left == {"j2c"}
    finally:
        conn.close()


def test_init_db_refuses_old_secret_schema(tmp_path):
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE clients (client_id TEXT PRIMARY KEY, secret_hash TEXT)")
    conn.close()
    with pytest.raises(RuntimeError, match="old clients schema"):
        db.init_db(path)


def test_init_db_refuses_schema_without_pending(tmp_path):
    path = str(tmp_path / "pre-pending.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE clients (client_id TEXT PRIMARY KEY, site TEXT NOT NULL)")
    conn.close()
    with pytest.raises(RuntimeError, match="old clients schema"):
        db.init_db(path)


def _pending(conn, client_id, created_at=None):
    key = shared_key()
    db.insert_pending_client(
        conn, client_id=client_id, client_name="shoveler@host", public_jwk=json.dumps(public_jwk(key)),
        kid=kid_for(key), key_thumbprint=kid_for(key), registered_ip="192.0.2.7",
    )
    if created_at:
        conn.execute("UPDATE clients SET created_at = ? WHERE client_id = ?", (created_at, client_id))


def test_pending_client_lifecycle(settings):
    db.init_db(settings.db_path)
    conn = db.connect(settings.db_path)
    try:
        _pending(conn, "shoveler-p1")
        row = db.get_client(conn, "shoveler-p1")
        assert row["pending"] == 1 and row["site"] is None and row["owner_sub"] is None
        assert db.count_pending_clients(conn) == 1
        # Pending clients are in no site list and not in the admin's approved list.
        assert db.list_all_clients(conn) == []
        assert [r["client_id"] for r in db.list_pending_clients(conn)] == ["shoveler-p1"]

        assert db.approve_client(conn, "shoveler-p1", site="nebraska", owner_sub="alice", owner_email="a@x")
        row = db.get_client(conn, "shoveler-p1")
        assert (row["pending"], row["site"], row["owner_sub"]) == (0, "nebraska", "alice")
        # Approving twice, or rejecting an approved client, does nothing.
        assert not db.approve_client(conn, "shoveler-p1", site="wisconsin", owner_sub="bob", owner_email=None)
        assert not db.delete_pending_client(conn, "shoveler-p1")
        assert db.get_client(conn, "shoveler-p1")["site"] == "nebraska"
        assert db.list_known_sites(conn) == ["nebraska"]
    finally:
        conn.close()


def test_reject_and_purge_pending(settings):
    db.init_db(settings.db_path)
    conn = db.connect(settings.db_path)
    try:
        _pending(conn, "shoveler-rej")
        assert db.delete_pending_client(conn, "shoveler-rej")
        assert db.get_client(conn, "shoveler-rej") is None

        old = db.to_iso(datetime.now(timezone.utc) - timedelta(days=10))
        _pending(conn, "shoveler-old", created_at=old)
        _pending(conn, "shoveler-new")
        cutoff = db.to_iso(datetime.now(timezone.utc) - timedelta(days=7))
        assert db.delete_stale_pending_clients(conn, cutoff) == ["shoveler-old"]
        assert [r["client_id"] for r in db.list_pending_clients(conn)] == ["shoveler-new"]
    finally:
        conn.close()


def test_find_client_by_thumbprint(settings):
    db.init_db(settings.db_path)
    conn = db.connect(settings.db_path)
    try:
        assert db.find_client_by_thumbprint(conn, kid_for(shared_key())) is None
        _pending(conn, "shoveler-p1")
        assert db.find_client_by_thumbprint(conn, kid_for(shared_key()))["client_id"] == "shoveler-p1"
    finally:
        conn.close()
