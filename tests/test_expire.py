"""Idle-expiry disables the right rows; Re-enable recovers them."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from helpers import seed_client, seed_pending
from portal import db, expire


def _insert(settings, client_id, *, last_used=None, created=None):
    seed_client(settings, client_id)
    conn = db.connect(settings.db_path)
    try:
        if created is not None:
            conn.execute(
                "UPDATE clients SET created_at = ? WHERE client_id = ?",
                (created, client_id),
            )
        if last_used is not None:
            conn.execute(
                "UPDATE clients SET last_used_at = ? WHERE client_id = ?",
                (last_used, client_id),
            )
    finally:
        conn.close()


def _iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def test_idle_calc_disables_correct_rows(settings):
    _insert(settings, "shoveler-stale", last_used=_iso(40))
    _insert(settings, "shoveler-fresh", last_used=_iso(5))
    # Never used, but created long ago -> uses created_at as reference.
    _insert(settings, "shoveler-old-unused", created=_iso(45))
    # Never used, created recently -> safe.
    _insert(settings, "shoveler-new-unused", created=_iso(2))

    conn = db.connect(settings.db_path)
    try:
        disabled = expire.find_and_disable_idle(conn, settings.idle_days)
    finally:
        conn.close()

    assert set(disabled) == {"shoveler-stale", "shoveler-old-unused"}

    conn = db.connect(settings.db_path)
    try:
        assert db.get_client(conn, "shoveler-stale")["disabled"] == 1
        assert db.get_client(conn, "shoveler-stale")["disabled_reason"] == "idle"
        assert db.get_client(conn, "shoveler-fresh")["disabled"] == 0
        assert db.get_client(conn, "shoveler-old-unused")["disabled"] == 1
        assert db.get_client(conn, "shoveler-new-unused")["disabled"] == 0
    finally:
        conn.close()


def test_naive_timestamp_is_treated_as_utc(settings):
    # A hand-edited/migrated row may have a naive timestamp (no tz offset).
    # The job must treat it as UTC and not crash on aware/naive comparison.
    naive_old = (datetime.now(timezone.utc) - timedelta(days=40)).replace(
        tzinfo=None
    ).isoformat()
    naive_new = (datetime.now(timezone.utc) - timedelta(days=1)).replace(
        tzinfo=None
    ).isoformat()
    _insert(settings, "shoveler-naive-old", last_used=naive_old)
    _insert(settings, "shoveler-naive-new", last_used=naive_new)

    conn = db.connect(settings.db_path)
    try:
        disabled = expire.find_and_disable_idle(conn, settings.idle_days)
        assert "shoveler-naive-old" in disabled
        assert "shoveler-naive-new" not in disabled
    finally:
        conn.close()


def test_already_disabled_rows_untouched(settings):
    _insert(settings, "shoveler-revoked", last_used=_iso(1))
    conn = db.connect(settings.db_path)
    try:
        db.disable_client(conn, "shoveler-revoked", "revoked-by-owner")
        expire.find_and_disable_idle(conn, settings.idle_days)
        # Reason stays as the owner's revocation, not overwritten by "idle".
        assert db.get_client(conn, "shoveler-revoked")["disabled_reason"] == "revoked-by-owner"
    finally:
        conn.close()


def test_reenable_recovers_idle_client(settings):
    _insert(settings, "shoveler-stale", last_used=_iso(40))
    conn = db.connect(settings.db_path)
    try:
        expire.find_and_disable_idle(conn, settings.idle_days)
        assert db.get_client(conn, "shoveler-stale")["disabled"] == 1
        # Re-enable clears the disabled flag; the client keeps its key.
        db.enable_client(conn, "shoveler-stale")
        row = db.get_client(conn, "shoveler-stale")
        assert row["disabled"] == 0
        assert row["disabled_reason"] is None
    finally:
        conn.close()


def test_pending_clients_are_not_idle_disabled_but_purged(settings):
    seed_pending(settings, "shoveler-pend-old")
    seed_pending(settings, "shoveler-pend-new", key=__import__("helpers").new_key())
    conn = db.connect(settings.db_path)
    try:
        conn.execute(
            "UPDATE clients SET created_at = ? WHERE client_id = ?",
            (_iso(40), "shoveler-pend-old"),
        )
        # Idle-expiry leaves pending clients alone (they have no site to idle in)...
        assert expire.find_and_disable_idle(conn, settings.idle_days) == []
        # ...the pending TTL removes the ones nobody approved.
        assert expire.purge_stale_pending(conn, settings.pending_client_ttl_seconds) == [
            "shoveler-pend-old"
        ]
        assert db.get_client(conn, "shoveler-pend-new")["pending"] == 1
    finally:
        conn.close()

