"""SQLite storage (stdlib sqlite3, WAL mode, no ORM).

Signing keys are NOT stored here; they live on disk (see keys.py).
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Iterable, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id       TEXT PRIMARY KEY,
    secret_hash     TEXT NOT NULL,
    site            TEXT NOT NULL,
    owner_sub       TEXT NOT NULL,
    owner_email     TEXT,
    created_at      TEXT NOT NULL,
    last_used_at    TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0,
    disabled_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_clients_site ON clients(site);
"""


def utcnow_iso() -> str:
    """Current UTC time as a timezone-aware ISO8601 string."""
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with WAL enabled and dict-like rows."""
    parent = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(db_path: str) -> None:
    """Create the schema if it does not already exist."""
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


# --- Queries -------------------------------------------------------------

def insert_client(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    secret_hash: str,
    site: str,
    owner_sub: str,
    owner_email: Optional[str],
) -> None:
    conn.execute(
        """INSERT INTO clients
           (client_id, secret_hash, site, owner_sub, owner_email, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (client_id, secret_hash, site, owner_sub, owner_email, utcnow_iso()),
    )


def get_client(conn: sqlite3.Connection, client_id: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
    return cur.fetchone()


def list_clients_for_sites(
    conn: sqlite3.Connection, sites: Iterable[str]
) -> list[sqlite3.Row]:
    sites = list(sites)
    if not sites:
        return []
    placeholders = ",".join("?" for _ in sites)
    cur = conn.execute(
        f"SELECT * FROM clients WHERE site IN ({placeholders}) "
        f"ORDER BY site, created_at DESC",
        sites,
    )
    return cur.fetchall()


def rotate_secret(conn: sqlite3.Connection, client_id: str, secret_hash: str) -> None:
    """Set a new secret hash and clear any disabled state (Recreate)."""
    conn.execute(
        """UPDATE clients
           SET secret_hash = ?, disabled = 0, disabled_reason = NULL
           WHERE client_id = ?""",
        (secret_hash, client_id),
    )


def disable_client(conn: sqlite3.Connection, client_id: str, reason: str) -> None:
    conn.execute(
        "UPDATE clients SET disabled = 1, disabled_reason = ? WHERE client_id = ?",
        (reason, client_id),
    )


def touch_last_used(conn: sqlite3.Connection, client_id: str) -> None:
    conn.execute(
        "UPDATE clients SET last_used_at = ? WHERE client_id = ?",
        (utcnow_iso(), client_id),
    )
