"""SQLite storage (stdlib sqlite3, WAL mode, no ORM).

Signing keys are NOT stored here; they live on disk (see keys.py).

Clients authenticate with their own RSA key (``private_key_jwt``); only the
PUBLIC key is stored. Registration tokens are stored as a SHA-256 hash.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Iterable, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id       TEXT PRIMARY KEY,
    site            TEXT NOT NULL,
    owner_sub       TEXT NOT NULL,
    owner_email     TEXT,
    client_name     TEXT,
    public_jwk      TEXT NOT NULL,
    kid             TEXT NOT NULL,
    key_thumbprint  TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    last_used_at    TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0,
    disabled_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_clients_site ON clients(site);

CREATE TABLE IF NOT EXISTS registration_tokens (
    token_hash  TEXT PRIMARY KEY,
    site        TEXT NOT NULL,
    owner_sub   TEXT NOT NULL,
    owner_email TEXT,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    client_id   TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_registration_tokens_site ON registration_tokens(site);

CREATE TABLE IF NOT EXISTS used_assertions (
    client_id TEXT NOT NULL,
    jti       TEXT NOT NULL,
    exp       INTEGER NOT NULL,
    PRIMARY KEY (client_id, jti)
);
"""


def to_iso(dt: datetime) -> str:
    """UTC ISO8601 with fixed microsecond precision.

    The fixed width keeps stored timestamps lexically ordered, so SQL can
    compare them as strings (e.g. ``expires_at > ?``).
    """
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def utcnow_iso() -> str:
    """Current UTC time as a timezone-aware ISO8601 string."""
    return to_iso(datetime.now(timezone.utc))


def parse_ts(value: str) -> datetime:
    """Parse an ISO8601 timestamp, assuming UTC if the value is naive.

    All timestamps this service writes are tz-aware (see utcnow_iso), but a
    hand-edited or migrated row could be naive; normalising here keeps later
    aware/naive comparisons from raising TypeError.
    """
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


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
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(clients)")}
        if "secret_hash" in cols:
            # CREATE TABLE IF NOT EXISTS would silently keep the old table.
            raise RuntimeError(
                f"{db_path} has the old client-secret schema; there is no "
                "migration. Move it aside and restart to create a fresh database."
            )
        conn.executescript(SCHEMA)
    finally:
        conn.close()


# --- Clients -------------------------------------------------------------

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


def list_all_clients(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every client across all sites (registry-admin view)."""
    cur = conn.execute(
        "SELECT * FROM clients ORDER BY site, last_used_at DESC, created_at DESC"
    )
    return cur.fetchall()


def disable_client(conn: sqlite3.Connection, client_id: str, reason: str) -> None:
    conn.execute(
        "UPDATE clients SET disabled = 1, disabled_reason = ? WHERE client_id = ?",
        (reason, client_id),
    )


def enable_client(conn: sqlite3.Connection, client_id: str) -> None:
    """Clear the disabled state (owner Re-enable)."""
    conn.execute(
        "UPDATE clients SET disabled = 0, disabled_reason = NULL WHERE client_id = ?",
        (client_id,),
    )


def touch_last_used(conn: sqlite3.Connection, client_id: str) -> None:
    conn.execute(
        "UPDATE clients SET last_used_at = ? WHERE client_id = ?",
        (utcnow_iso(), client_id),
    )


# --- Registration tokens -------------------------------------------------

def insert_registration_token(
    conn: sqlite3.Connection,
    *,
    token_hash: str,
    site: str,
    owner_sub: str,
    owner_email: Optional[str],
    expires_at: str,
) -> None:
    conn.execute(
        """INSERT INTO registration_tokens
           (token_hash, site, owner_sub, owner_email, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (token_hash, site, owner_sub, owner_email, utcnow_iso(), expires_at),
    )


def get_registration_token(
    conn: sqlite3.Connection, token_hash: str
) -> Optional[sqlite3.Row]:
    cur = conn.execute(
        "SELECT * FROM registration_tokens WHERE token_hash = ?", (token_hash,)
    )
    return cur.fetchone()


def list_registration_tokens_for_sites(
    conn: sqlite3.Connection, sites: Iterable[str]
) -> list[sqlite3.Row]:
    sites = list(sites)
    if not sites:
        return []
    placeholders = ",".join("?" for _ in sites)
    cur = conn.execute(
        f"SELECT * FROM registration_tokens WHERE site IN ({placeholders}) "
        f"ORDER BY site, created_at DESC",
        sites,
    )
    return cur.fetchall()


def revoke_registration_token(conn: sqlite3.Connection, token_hash: str) -> bool:
    """Revoke a token that has not been used yet. Returns True if one was."""
    cur = conn.execute(
        """UPDATE registration_tokens SET revoked = 1
           WHERE token_hash = ? AND used_at IS NULL AND revoked = 0""",
        (token_hash,),
    )
    return cur.rowcount == 1


def register_client(
    conn: sqlite3.Connection,
    *,
    token_hash: str,
    now: str,
    client_id: str,
    client_name: Optional[str],
    public_jwk: str,
    kid: str,
    key_thumbprint: str,
) -> bool:
    """Atomically spend a registration token and create its client.

    The client inherits the token's site and owner. Returns False (and changes
    nothing) unless the token exists, is unused, unrevoked and unexpired at
    ``now``; of two concurrent callers, exactly one can succeed.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            """UPDATE registration_tokens SET used_at = ?, client_id = ?
               WHERE token_hash = ? AND used_at IS NULL AND revoked = 0
                 AND expires_at > ?""",
            (now, client_id, token_hash, now),
        )
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            return False
        conn.execute(
            """INSERT INTO clients
               (client_id, site, owner_sub, owner_email, client_name,
                public_jwk, kid, key_thumbprint, created_at)
               SELECT ?, site, owner_sub, owner_email, ?, ?, ?, ?, ?
               FROM registration_tokens WHERE token_hash = ?""",
            (client_id, client_name, public_jwk, kid, key_thumbprint, now, token_hash),
        )
        conn.execute("COMMIT")
        return True
    except BaseException:
        conn.execute("ROLLBACK")
        raise


# --- Client-assertion replay protection ----------------------------------

def record_assertion(
    conn: sqlite3.Connection, *, client_id: str, jti: str, exp: int, purge_before: int
) -> bool:
    """Remember a client assertion's jti. Returns False if it was already used.

    Rows whose ``exp`` is before ``purge_before`` can no longer be replayed
    (the assertion itself would be rejected as expired), so they are deleted
    opportunistically here.
    """
    conn.execute("DELETE FROM used_assertions WHERE exp < ?", (purge_before,))
    try:
        conn.execute(
            "INSERT INTO used_assertions (client_id, jti, exp) VALUES (?, ?, ?)",
            (client_id, jti, exp),
        )
    except sqlite3.IntegrityError:
        return False
    return True
