"""Health from reports: rates, restarts, gaps, sparklines and the status rules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from helpers import seed_client
from portal import db, health

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


def row(minutes_ago, *, started_min_ago=600, interval=60, **metrics):
    """A client_reports row as a dict (what sqlite3.Row offers by name)."""
    base = {name: None for name in db.REPORT_METRICS}
    base.update(metrics)
    return {
        "received_at": db.to_iso(NOW - timedelta(minutes=minutes_ago)),
        "started_at": db.to_iso(NOW - timedelta(minutes=started_min_ago)),
        "interval_seconds": interval,
        **base,
    }


def traffic(minutes, *, per_min=600, published=True, started_min_ago=600, queue=0):
    """One report a minute over the last ``minutes``, oldest first."""
    rows = []
    for i, m in enumerate(range(minutes, -1, -1)):
        n = (started_min_ago - m) * per_min
        rows.append(row(m, started_min_ago=started_min_ago, packets_received=n,
                        messages_published=n if published else 0,
                        validations_failed=i, rabbitmq_reconnects=0, queue_size=queue))
    return rows


def test_parse_report_normalizes():
    report = health.parse_report({
        "started_at": "2026-10-21T01:00:00-05:00",
        "interval_seconds": 60,
        "metrics": {"packets_received": 12.0, "queue_size": 0, "extra": "ignored"},
    })
    assert report.started_at == "2026-10-21T06:00:00.000000+00:00"
    assert report.version is None
    assert report.metrics == {"packets_received": 12, "queue_size": 0}


def test_series_rates_and_breaks():
    rows = [
        row(10, packets_received=0, messages_published=0, validations_failed=0),
        row(9, packets_received=600, messages_published=590, validations_failed=6),
        # Restart: a new process; no rate across it.
        row(8, started_min_ago=8.5, packets_received=30, messages_published=30,
            validations_failed=0),
        row(7, started_min_ago=8.5, packets_received=90, messages_published=90,
            validations_failed=0),
        # Five missed reports, then the same process again.
        row(1, started_min_ago=8.5, packets_received=450, messages_published=450,
            validations_failed=0),
        row(0, started_min_ago=8.5, packets_received=510, messages_published=510,
            validations_failed=0),
    ]
    s = health.series(rows)
    t0 = int((NOW - timedelta(minutes=10)).timestamp())
    assert s["t"] == [t0, t0 + 60, t0 + 120, t0 + 180, t0 + 240, t0 + 540, t0 + 600]
    assert s["received"] == [None, 10.0, None, 1.0, None, None, 1.0]
    assert s["published"] == [None, 9.833, None, 1.0, None, None, 1.0]
    assert s["failed"] == [None, 6.0, None, 0.0, None, None, 0.0]


def test_series_counter_reset_without_new_start_breaks_the_line():
    rows = [row(2, packets_received=100), row(1, packets_received=40),
            row(0, packets_received=100)]
    assert health.series(rows)["received"] == [None, None, 1.0]


def _sparklines(settings, rows_by_client, hours=2):
    conn = db.connect(settings.db_path)
    try:
        for cid, rows in rows_by_client.items():
            seed_client(settings, cid)
            for r in rows:
                db.insert_report(
                    conn, client_id=cid, received_at=r["received_at"],
                    started_at=r["started_at"], interval_seconds=r["interval_seconds"],
                    version=None, metrics={k: r[k] for k in db.REPORT_METRICS},
                    purge_before="")
        return health.sparklines(conn, NOW, hours)
    finally:
        conn.close()


def test_sparklines_bucket_rates(settings):
    db.init_db(settings.db_path)
    spark = _sparklines(settings, {"shoveler-a": traffic(60, per_min=120)})
    assert spark == {"shoveler-a": [None] * 4 + [2.0] * 4}  # 2 packets/s for the last hour


def test_sparklines_skip_restarts_resets_and_gaps(settings):
    db.init_db(settings.db_path)
    rows = [
        row(70, packets_received=0), row(69, packets_received=600),   # 10/s
        row(68, started_min_ago=68.5, packets_received=0),            # restart
        row(67, started_min_ago=68.5, packets_received=60),           # 1/s
        row(66, started_min_ago=68.5, packets_received=10),           # counter reset
        row(50, started_min_ago=68.5, packets_received=9999),         # after missed reports
        row(49, started_min_ago=68.5, packets_received=10119),        # 2/s
    ]
    spark = _sparklines(settings, {"shoveler-a": rows})["shoveler-a"]
    assert spark == [
        None, None, None,
        5.5,   # 10:45-11:00: 600 + 60 packets over two 60 s steps
        2.0,   # 11:00-11:15: only the pair after the missed reports
        None, None, None,
    ]


def test_totals_and_restarts():
    rows = [
        row(3, validations_failed=10, packets_received=100),
        row(2, validations_failed=15, packets_received=200),
        row(1, started_min_ago=1.5, validations_failed=2, packets_received=50),
        row(0, started_min_ago=1.5, validations_failed=3, packets_received=90),
    ]
    assert health.restarts(rows) == 1
    totals = health.totals(rows)
    # Growth within each process, plus what the new one counted from 0.
    assert totals["validations_failed"] == 5 + 2 + 1
    assert totals["packets_received"] == 100 + 50 + 40


def test_assess_never_reported():
    assert health.assess(None, [], NOW).status == "no-reports"


@pytest.mark.parametrize("minutes_ago,interval,status", [
    (2, 60, "healthy"),
    (4, 60, "not-reporting"),      # 3 missed reports
    (25, 600, "healthy"),          # long interval: 3 x 10 min not yet up
    (31, 600, "not-reporting"),
])
def test_assess_staleness(minutes_ago, interval, status):
    latest = row(minutes_ago, interval=interval, packets_received=10)
    assert health.assess(latest, [], NOW).status == status


def test_assess_not_reporting_says_since_when():
    h = health.assess(row(180, packets_received=1), [], NOW)
    assert (h.label, h.detail) == ("Not reporting", "Last report 3 h ago.")


def test_assess_healthy_traffic():
    rows = traffic(15)
    assert health.assess(rows[-1], rows, NOW).status == "healthy"


def test_assess_no_packets():
    rows = traffic(15, per_min=0)
    h = health.assess(rows[-1], rows, NOW)
    assert h.status == "no-packets"
    assert h.detail.startswith("No packets received in the last 15 min.")


def test_assess_not_publishing():
    rows = traffic(15, published=False, queue=900)
    h = health.assess(rows[-1], rows, NOW)
    assert h.status == "not-publishing"
    assert h.detail == ("Received 9,000 packets in the last 15 min but published "
                        "none to the message bus.")


def test_assess_needs_enough_evidence():
    # Just restarted, nothing received yet: too early to call it.
    rows = traffic(3, per_min=0, started_min_ago=3.5)
    assert health.assess(rows[-1], rows, NOW).status == "healthy"
    # Started 8 minutes ago and silent since: counted from its start.
    rows = traffic(7, per_min=0, started_min_ago=8)
    h = health.assess(rows[-1], rows, NOW)
    assert (h.status, h.detail[:37]) == ("no-packets", "No packets received in the last 8 min")


def test_assess_older_shoveler_without_publish_counter():
    rows = [row(m, packets_received=1000 - m) for m in range(15, -1, -1)]
    assert health.assess(rows[-1], rows, NOW).status == "healthy"


@pytest.mark.parametrize("seconds,text", [
    (5, "5 s"), (89, "89 s"), (90, "2 min"), (3000, "50 min"), (5400, "2 h"),
    (86400, "24 h"), (3 * 86400, "3 d"),
])
def test_ago(seconds, text):
    assert health.ago(timedelta(seconds=seconds)) == text


def test_current_rates():
    rows = traffic(2, per_min=120)
    assert health.current(rows) == {"received": 2.0, "published": 2.0}
    assert health.current(rows[:1]) == {"received": None, "published": None}
    # Across missed reports there is no "current" rate.
    gap = [row(10, packets_received=0), row(0, packets_received=600)]
    assert health.current(gap) == {"received": None, "published": None}


def test_tracker_states():
    rows = (
        traffic(120, started_min_ago=200)[:46]          # 10:00 .. 10:45, flowing
        + traffic(44, per_min=0, started_min_ago=44)[:15]  # restart; 11:16 .. 11:30, idle
    )
    blocks = health.tracker(rows, NOW, 3)
    assert [b.state for b in blocks] == (
        ["none"] * 4                        # 09:00 .. 10:00, before the first report
        + ["ok"] * 4                        # 10:00 .. 11:00
        + ["missing"]                       # 11:00 .. 11:15, between processes
        + ["warn"] * 2                      # 11:15 .. 11:45, reporting, no packets
        + ["missing"]                       # 11:45 .. 12:00
    )
    assert blocks[5].title == "10:15–10:30 UTC: 9,000 packets"
    assert blocks[9].title == "11:15–11:30 UTC: no packets received"
    assert blocks[-1].title == "11:45–12:00 UTC: no reports"
