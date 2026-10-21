"""SQLite storage (stdlib sqlite3, WAL mode, no ORM).

Signing keys are NOT stored here; they live on disk (see keys.py).

Clients authenticate with their own RSA key (``private_key_jwt``); only the
PUBLIC key is stored. Registration tokens are stored as a SHA-256 hash.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id       TEXT PRIMARY KEY,
    -- site is a display label set by an admin; owner_* records the admin who
    -- approved it or minted its registration token. Both are NULL while a
    -- token-less registration is pending.
    site            TEXT,
    owner_sub       TEXT,
    owner_email     TEXT,
    client_name     TEXT,
    public_jwk      TEXT NOT NULL,
    kid             TEXT NOT NULL,
    key_thumbprint  TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    last_used_at    TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0,
    disabled_reason TEXT,
    pending         INTEGER NOT NULL DEFAULT 0,
    registered_ip   TEXT
);
CREATE INDEX IF NOT EXISTS idx_clients_site ON clients(site);
CREATE INDEX IF NOT EXISTS idx_clients_thumbprint ON clients(key_thumbprint);

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

-- Health reports shovelers POST to /report (see health.py): counters since
-- the shoveler process started at started_at, plus its queue size. Kept for
-- METRICS_RETENTION_HOURS, except each client's latest report.
CREATE TABLE IF NOT EXISTS client_reports (
    client_id           TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    received_at         TEXT NOT NULL,
    started_at          TEXT NOT NULL,
    interval_seconds    INTEGER NOT NULL,
    version             TEXT,
    packets_received    INTEGER,
    validations_failed  INTEGER,
    messages_published  INTEGER,
    rabbitmq_reconnects INTEGER,
    queue_size          INTEGER,
    PRIMARY KEY (client_id, received_at)
);
CREATE INDEX IF NOT EXISTS idx_client_reports_received ON client_reports(received_at);

CREATE TABLE IF NOT EXISTS used_assertions (
    client_id TEXT NOT NULL,
    jti       TEXT NOT NULL,
    exp       INTEGER NOT NULL,
    PRIMARY KEY (client_id, jti)
);
"""


# The metric columns of client_reports; a report may omit any of them (NULL).
REPORT_METRICS = (
    "packets_received",
    "validations_failed",
    "messages_published",
    "rabbitmq_reconnects",
    "queue_size",
)


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
        if cols and ("secret_hash" in cols or "pending" not in cols):
            # CREATE TABLE IF NOT EXISTS would silently keep the old table.
            raise RuntimeError(
                f"{db_path} has an old clients schema; there is no migration. "
                "Move it aside and restart to create a fresh database."
            )
        conn.executescript(SCHEMA)
    finally:
        conn.close()


# --- Clients -------------------------------------------------------------

def get_client(conn: sqlite3.Connection, client_id: str) -> Optional[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
    return cur.fetchone()


def list_all_clients(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every approved client across all sites (registry-admin view)."""
    cur = conn.execute(
        "SELECT * FROM clients WHERE pending = 0 "
        "ORDER BY site, last_used_at DESC, created_at DESC"
    )
    return cur.fetchall()


def list_known_sites(conn: sqlite3.Connection) -> list[str]:
    """Sites that have at least one client (suggestions for admin approval)."""
    cur = conn.execute(
        "SELECT DISTINCT site FROM clients WHERE site IS NOT NULL ORDER BY site"
    )
    return [r["site"] for r in cur.fetchall()]


def find_client_by_thumbprint(
    conn: sqlite3.Connection, key_thumbprint: str
) -> Optional[sqlite3.Row]:
    """The most recently registered client with this public key, if any."""
    cur = conn.execute(
        "SELECT * FROM clients WHERE key_thumbprint = ? "
        "ORDER BY created_at DESC LIMIT 1",
        (key_thumbprint,),
    )
    return cur.fetchone()


# --- Pending clients (registered without a token) ------------------------

def insert_pending_client(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    client_name: Optional[str],
    public_jwk: str,
    kid: str,
    key_thumbprint: str,
    registered_ip: Optional[str],
) -> None:
    conn.execute(
        """INSERT INTO clients
           (client_id, client_name, public_jwk, kid, key_thumbprint,
            created_at, pending, registered_ip)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
        (client_id, client_name, public_jwk, kid, key_thumbprint, utcnow_iso(),
         registered_ip),
    )


def count_pending_clients(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM clients WHERE pending = 1").fetchone()[0]


def list_pending_clients(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    cur = conn.execute(
        "SELECT * FROM clients WHERE pending = 1 ORDER BY created_at DESC"
    )
    return cur.fetchall()


def approve_client(
    conn: sqlite3.Connection,
    client_id: str,
    *,
    site: str,
    owner_sub: str,
    owner_email: Optional[str],
) -> bool:
    """Approve a pending client, labelling its site and recording the approver.

    Returns False if the client isn't pending (already approved or rejected).
    """
    cur = conn.execute(
        """UPDATE clients SET pending = 0, site = ?, owner_sub = ?, owner_email = ?
           WHERE client_id = ? AND pending = 1""",
        (site, owner_sub, owner_email, client_id),
    )
    return cur.rowcount == 1


def delete_pending_client(conn: sqlite3.Connection, client_id: str) -> bool:
    """Reject a pending client. It never had access, so nothing is kept."""
    cur = conn.execute(
        "DELETE FROM clients WHERE client_id = ? AND pending = 1", (client_id,)
    )
    return cur.rowcount == 1


def delete_stale_pending_clients(conn: sqlite3.Connection, before: str) -> list[str]:
    """Delete pending clients registered before ``before``; returns their ids."""
    cur = conn.execute(
        "SELECT client_id FROM clients WHERE pending = 1 AND created_at < ?",
        (before,),
    )
    ids = [r["client_id"] for r in cur.fetchall()]
    conn.execute(
        "DELETE FROM clients WHERE pending = 1 AND created_at < ?", (before,)
    )
    return ids


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


def list_registration_tokens(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    cur = conn.execute("SELECT * FROM registration_tokens ORDER BY created_at DESC")
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


# --- Health reports ------------------------------------------------------

def insert_report(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    received_at: str,
    started_at: str,
    interval_seconds: int,
    version: Optional[str],
    metrics: dict[str, int],
    purge_before: str,
) -> None:
    """Store a report and drop this client's reports from before ``purge_before``.

    ``metrics`` maps names in REPORT_METRICS to values; missing ones are NULL.
    """
    cols = ", ".join(REPORT_METRICS)
    marks = ", ".join("?" for _ in REPORT_METRICS)
    conn.execute(
        f"""INSERT OR REPLACE INTO client_reports
            (client_id, received_at, started_at, interval_seconds, version, {cols})
            VALUES (?, ?, ?, ?, ?, {marks})""",
        (client_id, received_at, started_at, interval_seconds, version,
         *(metrics.get(name) for name in REPORT_METRICS)),
    )
    conn.execute(
        "DELETE FROM client_reports WHERE client_id = ? AND received_at < ?",
        (client_id, purge_before),
    )


def list_reports(
    conn: sqlite3.Connection, since: str, client_id: Optional[str] = None
) -> list[sqlite3.Row]:
    """Reports received at or after ``since``, oldest first (one client or all)."""
    if client_id is None:
        cur = conn.execute(
            "SELECT * FROM client_reports WHERE received_at >= ? "
            "ORDER BY client_id, received_at",
            (since,),
        )
    else:
        cur = conn.execute(
            "SELECT * FROM client_reports WHERE client_id = ? AND received_at >= ? "
            "ORDER BY received_at",
            (client_id, since),
        )
    return cur.fetchall()


def report_buckets(
    conn: sqlite3.Connection,
    since: str,
    width_seconds: int,
    max_missed: int,
    client_id: Optional[str] = None,
) -> list[sqlite3.Row]:
    """Each client's reports since ``since`` summed into time buckets.

    Per client and ``bucket`` (0 starts at ``since``): how many reports
    arrived, the latest and its interval, and the packets received and
    messages published since each one's previous report. Steps across a
    restart, a counter reset, or more than ``max_missed`` report intervals
    count no packets (NULL when no step in the bucket counts).
    """
    cur = conn.execute(
        """WITH steps AS (
             SELECT client_id, received_at, interval_seconds,
                    packets_received - LAG(packets_received) OVER w AS packets,
                    messages_published - LAG(messages_published) OVER w AS published,
                    started_at = LAG(started_at) OVER w
                      AND (julianday(received_at) - julianday(LAG(received_at) OVER w))
                          * 86400 <= :max_missed * LAG(interval_seconds) OVER w AS valid
             FROM client_reports
             WHERE received_at >= :since
               AND (:client_id IS NULL OR client_id = :client_id)
             WINDOW w AS (PARTITION BY client_id ORDER BY received_at))
           SELECT client_id,
                  -- Whole seconds first: julianday's float error would put a
                  -- report exactly on a bucket edge into the bucket before.
                  CAST(ROUND((julianday(received_at) - julianday(:since)) * 86400)
                       AS INTEGER) / :width AS bucket,
                  COUNT(*) AS reports,
                  MAX(received_at) AS latest,
                  MAX(interval_seconds) AS interval_seconds,
                  SUM(CASE WHEN valid AND packets >= 0 THEN packets END) AS packets,
                  SUM(CASE WHEN valid AND published >= 0 THEN published END) AS published
           FROM steps
           GROUP BY client_id, bucket""",
        {"since": since, "width": width_seconds, "max_missed": max_missed,
         "client_id": client_id},
    )
    return cur.fetchall()


def latest_report(conn: sqlite3.Connection, client_id: str) -> Optional[sqlite3.Row]:
    cur = conn.execute(
        "SELECT * FROM client_reports WHERE client_id = ? "
        "ORDER BY received_at DESC LIMIT 1",
        (client_id,),
    )
    return cur.fetchone()


def latest_reports(conn: sqlite3.Connection) -> dict[str, sqlite3.Row]:
    """Each client's most recent report, however old, keyed by client_id."""
    cur = conn.execute(
        """SELECT r.* FROM client_reports r
           JOIN (SELECT client_id, MAX(received_at) AS latest
                 FROM client_reports GROUP BY client_id) l
             ON r.client_id = l.client_id AND r.received_at = l.latest"""
    )
    return {r["client_id"]: r for r in cur.fetchall()}


def purge_reports(conn: sqlite3.Connection, before: str) -> int:
    """Delete reports received before ``before``, except each client's latest."""
    cur = conn.execute(
        """DELETE FROM client_reports
           WHERE received_at < ?
             AND received_at < (SELECT MAX(r.received_at) FROM client_reports r
                                WHERE r.client_id = client_reports.client_id)""",
        (before,),
    )
    return cur.rowcount
