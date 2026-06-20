"""Idle-expiry disables the right rows; Recreate recovers them."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from portal import db, expire, tokens


def _insert(settings, client_id, *, last_used=None, created=None):
    db.init_db(settings.db_path)
    conn = db.connect(settings.db_path)
    try:
        db.insert_client(
            conn, client_id=client_id, secret_hash=tokens.hash_secret("x"),
            site="nebraska", owner_sub="sub", owner_email=None,
        )
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


def test_recreate_recovers_idle_client(settings):
    _insert(settings, "shoveler-stale", last_used=_iso(40))
    conn = db.connect(settings.db_path)
    try:
        expire.find_and_disable_idle(conn, settings.idle_days)
        assert db.get_client(conn, "shoveler-stale")["disabled"] == 1
        # Recreate rotates the secret AND clears the disabled flag.
        db.rotate_secret(conn, "shoveler-stale", tokens.hash_secret("new"))
        row = db.get_client(conn, "shoveler-stale")
        assert row["disabled"] == 0
        assert row["disabled_reason"] is None
    finally:
        conn.close()
