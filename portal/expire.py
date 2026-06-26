"""Idle-expiry job: disable credentials unused for IDLE_DAYS.

Run from cron or a Kubernetes CronJob:

    python -m portal.expire

The reference time is ``last_used_at`` (or ``created_at`` if a credential was
never used). Only currently-enabled rows are affected. Rows are never deleted
(audit + recovery); recovery is self-service via the dashboard's Recreate
button, which clears the disabled flag.
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
        "SELECT client_id, created_at, last_used_at FROM clients WHERE disabled = 0"
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


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    settings = get_settings()
    db.init_db(settings.db_path)
    conn = db.connect(settings.db_path)
    try:
        disabled = find_and_disable_idle(conn, settings.idle_days)
    finally:
        conn.close()
    log.info("Idle-expiry complete: disabled %d client(s)", len(disabled))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
