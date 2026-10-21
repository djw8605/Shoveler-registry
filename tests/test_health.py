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


def _start(minutes):
    return NOW - timedelta(minutes=minutes)


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
    s = health.series(rows, _start(10), NOW)
    t0 = int(_start(10).timestamp())
    assert s["t"] == [t0, t0 + 60, t0 + 120, t0 + 180, t0 + 240, t0 + 540, t0 + 600]
    assert s["received"] == [None, 10.0, None, 1.0, None, None, 1.0]
    assert s["published"] == [None, 9.833, None, 1.0, None, None, 1.0]
    assert s["failed"] == [None, 6.0, None, 0.0, None, None, 0.0]


def test_series_counter_reset_without_new_start_breaks_the_line():
    rows = [row(2, packets_received=100), row(1, packets_received=40),
            row(0, packets_received=100)]
    assert health.series(rows, _start(2), NOW)["received"] == [None, None, 1.0]


def test_series_spans_the_whole_window():
    # A shoveler that went quiet 30 min ago: the charts still run to now.
    rows = [row(32, packets_received=0), row(31, packets_received=60)]
    s = health.series(rows, _start(60), NOW)
    assert s["t"][0] == int(_start(60).timestamp())
    assert s["t"][-1] == int(NOW.timestamp())
    assert s["received"] == [None, None, 1.0, None, None]
    assert health.series([], _start(60), NOW)["t"] == [
        int(_start(60).timestamp()), int(NOW.timestamp())]


def test_hourly():
    rows = traffic(90, per_min=120)
    hours = health.hourly(rows, NOW, 2)
    assert [h["start"].strftime("%H:%M") for h in hours] == ["11:00", "10:00"]
    assert hours[0]["received_rate"] == 2.0 and hours[0]["reports"] == 60
    assert hours[1]["reports"] == 30
    assert hours[0]["failed"] == 60


def test_totals_and_restarts():
    rows = [
        row(3, validations_failed=10, packets_received=100),
        row(2, validations_failed=15, packets_received=200),
        row(1, started_min_ago=1.5, validations_failed=2, packets_received=50),
        row(0, started_min_ago=1.5, validations_failed=3, packets_received=90),
    ]
    assert health.restarts(rows) == [NOW - timedelta(minutes=1.5)]
    totals = health.totals(rows)
    # Growth within each process, plus what the new one counted from 0.
    assert totals["validations_failed"] == 5 + 2 + 1
    assert totals["packets_received"] == 100 + 50 + 40


def test_assess_never_reported():
    h = health.assess(None, [], NOW)
    assert (h.status, h.label, h.summary) == ("no-reports", "No reports", "Never reported.")


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
    assert (h.label, h.summary) == ("Not reporting", "No report since 09:00 UTC (3 h ago).")
    assert h.since == NOW - timedelta(hours=3)
    # Days ago: with the date.
    h = health.assess(row(3 * 1440, packets_received=1), [], NOW)
    assert h.summary == "No report since 2026-10-18 12:00 UTC (3 d ago)."


def test_assess_healthy_traffic():
    rows = traffic(15)
    h = health.assess(rows[-1], rows, NOW)
    assert (h.status, h.summary, h.advice) == ("healthy", "Last report 0 s ago.", "")


def test_assess_no_packets_since_the_process_started():
    rows = traffic(15, per_min=0)
    h = health.assess(rows[-1], rows, NOW)
    assert h.status == "no-packets"
    # The counter is still 0, so it has been idle since it started, 10 h ago.
    assert h.summary == "No packets received since 02:00 UTC (10 h ago)."
    assert h.advice.startswith("Check that XRootD")


def test_assess_not_publishing_dates_the_onset():
    rows = []
    for m in range(40, -1, -1):
        n = (600 - m) * 60
        published = (600 - max(m, 25)) * 60  # stopped growing 25 min ago
        rows.append(row(m, packets_received=n, messages_published=published,
                        validations_failed=0, rabbitmq_reconnects=0, queue_size=0))
    h = health.assess(rows[-1], rows, NOW)
    assert h.status == "not-publishing"
    assert h.summary == ("Nothing published since 11:35 UTC (25 min ago), "
                         "though 1,500 packets arrived.")
    assert h.since == NOW - timedelta(minutes=25)


def test_assess_onset_before_the_reports_we_have():
    rows = traffic(15, published=False)
    # Hide its zero counter: it was flat before the oldest report we hold.
    for r in rows:
        r["messages_published"] = 7
    h = health.assess(rows[-1], rows, NOW)
    assert h.summary.startswith("Nothing published since before 11:45 UTC, ")


def test_assess_needs_enough_evidence():
    # Just restarted, nothing received yet: too early to call it.
    rows = traffic(3, per_min=0, started_min_ago=3.5)
    assert health.assess(rows[-1], rows, NOW).status == "healthy"
    # Started 8 minutes ago and silent since: counted from its start.
    rows = traffic(7, per_min=0, started_min_ago=8)
    h = health.assess(rows[-1], rows, NOW)
    assert (h.status, h.summary) == ("no-packets",
                                     "No packets received since 11:52 UTC (8 min ago).")


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


# --- Tracker (bucketed in SQL) ----------------------------------------------

def _trackers(settings, rows_by_client, hours=3):
    db.init_db(settings.db_path)
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
        return health.trackers(conn, NOW, hours, db.latest_reports(conn))
    finally:
        conn.close()


def test_tracker_states(settings):
    rows = (
        traffic(120, started_min_ago=200)[:46]          # 10:00 .. 10:45, flowing
        + traffic(44, per_min=0, started_min_ago=44)[:15]  # restart; 11:16 .. 11:30, idle
    )
    blocks = _trackers(settings, {"shoveler-a": rows})["shoveler-a"]
    assert [b.state for b in blocks] == (
        ["no-data"] * 4                     # 09:00 .. 10:00, before the first report
        + ["healthy"] * 4                   # 10:00 .. 11:00
        + ["not-reporting"]                 # 11:00 .. 11:15, between processes
        + ["no-packets"] * 2                # 11:15 .. 11:45, reporting, no packets
        + ["not-reporting"]                 # 11:45 .. 12:00
    )
    assert blocks[5].title == "10:15–10:30 UTC: 9,000 packets"
    assert blocks[9].title == "11:15–11:30 UTC: no packets received"
    assert blocks[-1].title == "11:45–12:00 UTC: no reports"


def test_tracker_not_publishing_and_long_intervals(settings):
    stuck = traffic(60, published=False)
    # Reports every 30 min: an empty block between two isn't "not reporting".
    slow = [row(m, interval=1800, packets_received=(600 - m) * 10,
                messages_published=(600 - m) * 10) for m in (100, 70, 40, 10)]
    trackers = _trackers(settings, {"shoveler-stuck": stuck, "shoveler-slow": slow}, 2)
    assert [b.state for b in trackers["shoveler-stuck"]][-4:] == ["not-publishing"] * 4
    assert trackers["shoveler-stuck"][-1].title.endswith("packets received, none published")
    assert [b.state for b in trackers["shoveler-slow"]] == ["no-data"] + ["healthy"] * 7
    assert trackers["shoveler-slow"][2].title == "10:30–10:45 UTC: between reports"


def test_tracker_skips_restarts_resets_and_gaps(settings):
    rows = [
        row(70, packets_received=0), row(69, packets_received=600),   # 600
        row(68, started_min_ago=68.5, packets_received=0),            # restart
        row(67, started_min_ago=68.5, packets_received=60),           # 60
        row(66, started_min_ago=68.5, packets_received=10),           # counter reset
        row(50, started_min_ago=68.5, packets_received=9999),         # after missed reports
        row(49, started_min_ago=68.5, packets_received=10119),        # 120
    ]
    blocks = _trackers(settings, {"shoveler-a": rows}, 2)["shoveler-a"]
    assert blocks[3].title == "10:45–11:00 UTC: 660 packets"
    assert blocks[4].title == "11:00–11:15 UTC: 120 packets"


def test_tracker_of_a_shoveler_quiet_since_before_the_window(settings):
    blocks = _trackers(settings, {"shoveler-a": [row(600, packets_received=5)]}, 2)["shoveler-a"]
    assert {b.state for b in blocks} == {"not-reporting"}


def test_runs_pin_onset_and_describe():
    start = NOW - timedelta(hours=1)
    blocks = [health.Block("healthy", start + i * health.BUCKET, "") for i in range(3)]
    blocks.append(health.Block("not-publishing", start + 3 * health.BUCKET, ""))
    runs = health.runs(blocks)
    assert [(r.state, r.blocks) for r in runs] == [("healthy", 3), ("not-publishing", 1)]
    onset = NOW - timedelta(minutes=22)
    h = health.Health("not-publishing", "", since=onset)
    pinned = health.pin_onset(runs, h)
    assert pinned[-1].start == onset and pinned[-2].end == onset
    assert [w for _, w in health.changes(pinned, NOW)] == [
        "Since 11:38 UTC", "11:00 – 11:38 UTC"]
    # A run that began before today carries its date.
    old = [health.Run("no-data", NOW - timedelta(hours=23), NOW - timedelta(hours=13), 40),
           health.Run("healthy", NOW - timedelta(hours=13), NOW, 52)]
    assert [w for _, w in health.changes(old, NOW)] == [
        "Since 2026-10-20 23:00 UTC", "2026-10-20 13:00 – 2026-10-20 23:00 UTC"]
    assert health.describe(pinned, NOW) == (
        "Healthy from 11:00 UTC to 11:38 UTC; Not publishing from 11:38 UTC to now.")
    # A different state, or an onset far from the run, leaves the runs alone.
    assert health.pin_onset(runs, health.Health("no-packets", "", since=onset)) == runs
    far = health.Health("not-publishing", "", since=NOW - timedelta(hours=5))
    assert health.pin_onset(runs, far) == runs
