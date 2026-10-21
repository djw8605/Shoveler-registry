"""Idle-expiry job: disable credentials unused for IDLE_DAYS, delete
pending (token-less) registrations nobody approved within
PENDING_CLIENT_TTL_SECONDS, and drop health reports older than
METRICS_RETENTION_HOURS (keeping each shoveler's latest).

Run from cron or a Kubernetes CronJob:

    python -m portal.expire

The reference time is ``last_used_at`` (or ``created_at`` if a credential was
never used). Only currently-enabled, approved rows are affected. Rows are never deleted
(audit + recovery); recovery is self-service via the dashboard's Re-enable
button, which clears the disabled flag. The shoveler keeps its key and
client_id, so nothing needs to change on the shoveler side.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

from . import db
from .config import get_settings

log = logging.getLogger("portal.expire")


def find_and_disable_idle(
    conn: sqlite3.Connection, idle_days: int, now: datetime | None = None
) -> list[str]:
    """Disable enabled clients idle for >= idle_days. Returns disabled ids."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=idle_days)
    disabled: list[str] = []

    cur = conn.execute(
        "SELECT client_id, created_at, last_used_at FROM clients "
        "WHERE disabled = 0 AND pending = 0"
    )
    for row in cur.fetchall():
        ref = row["last_used_at"] or row["created_at"]
        try:
            ref_dt = db.parse_ts(ref)
        except (ValueError, TypeError):
            log.warning("Skipping %s: unparseable timestamp %r", row["client_id"], ref)
            continue
        if ref_dt <= cutoff:
            disabled.append(row["client_id"])

    for client_id in disabled:
        db.disable_client(conn, client_id, "idle")
        log.info("Disabled idle client %s", client_id)
    return disabled


def purge_stale_pending(
    conn: sqlite3.Connection, ttl_seconds: int, now: datetime | None = None
) -> list[str]:
    """Delete pending clients registered more than ttl_seconds ago."""
    now = now or datetime.now(timezone.utc)
    deleted = db.delete_stale_pending_clients(
        conn, db.to_iso(now - timedelta(seconds=ttl_seconds))
    )
    for client_id in deleted:
        log.info("Deleted unapproved pending client %s", client_id)
    return deleted


def purge_old_reports(
    conn: sqlite3.Connection, retention_hours: int, now: datetime | None = None
) -> int:
    """Delete health reports past retention, except each client's latest.

    /report already trims a shoveler's own old reports as new ones arrive;
    this catches the ones that stopped reporting.
    """
    now = now or datetime.now(timezone.utc)
    return db.purge_reports(conn, db.to_iso(now - timedelta(hours=retention_hours)))


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    settings = get_settings()
    db.init_db(settings.db_path)
    conn = db.connect(settings.db_path)
    try:
        disabled = find_and_disable_idle(conn, settings.idle_days)
        purged = purge_stale_pending(conn, settings.pending_client_ttl_seconds)
        reports = purge_old_reports(conn, settings.metrics_retention_hours)
    finally:
        conn.close()
    log.info(
        "Idle-expiry complete: disabled %d client(s), deleted %d stale pending, "
        "%d old health report(s)",
        len(disabled),
        len(purged),
        reports,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
