"""Shoveler health reports: validating POST /report bodies, and the rates and
health status the dashboard shows.

Every ``interval_seconds`` a shoveler POSTs its counters since its process
started (``started_at``) and its current queue size. Within one process the
counters only grow, so the rate between two reports is their difference over
the time between them. A restart (a new ``started_at``, or a counter going
down) or a run of missed reports breaks the line instead of averaging over it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from . import db

COUNTERS = ("packets_received", "validations_failed", "messages_published",
            "rabbitmq_reconnects")
GAUGES = ("queue_size",)
assert set(COUNTERS + GAUGES) == set(db.REPORT_METRICS)

MIN_INTERVAL_SECONDS = 10
MAX_INTERVAL_SECONDS = 3600
VERSION_MAX = 64
# Largest value a JSON number carries exactly (2**53).
MAX_VALUE = 9007199254740992

# A shoveler is "not reporting" once it has missed this many reports, and a
# gap of that many intervals breaks its charts.
MISSED_REPORTS = 3
# ... but never sooner than this after its last report.
STALE_AFTER_MIN = timedelta(minutes=3)
# Health judges the traffic over this trailing window, once it has at least
# EVIDENCE_MIN of it from the running process.
WINDOW = timedelta(minutes=15)
EVIDENCE_MIN = timedelta(minutes=5)
# The dashboard sparklines' bucket width.
SPARK_BUCKET = timedelta(minutes=15)


class ReportError(Exception):
    """A malformed report: 400 invalid_request."""

    def __init__(self, description: str):
        self.description = description
        super().__init__(description)

    def as_dict(self) -> dict:
        return {"error": "invalid_request", "error_description": self.description}


@dataclass(frozen=True)
class Report:
    started_at: str
    interval_seconds: int
    version: Optional[str]
    metrics: dict[str, int]


def _count(name: str, value) -> int:
    # bool is an int subclass; JSON true/false is not a count.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"metrics.{name} must be a number")
    if not math.isfinite(value) or value < 0 or value > MAX_VALUE:
        raise ReportError(f"metrics.{name} is out of range")
    return int(value)


def parse_report(body) -> Report:
    """Validate a /report body. Unknown metrics are ignored (newer shovelers)."""
    if not isinstance(body, dict):
        raise ReportError("request body must be a JSON object")

    started = body.get("started_at")
    try:
        if not isinstance(started, str) or len(started) > 64:
            raise ValueError
        started_at = db.to_iso(db.parse_ts(started))
    except (ValueError, OverflowError):
        raise ReportError("started_at must be an RFC 3339 timestamp") from None

    interval = body.get("interval_seconds")
    if (
        isinstance(interval, bool)
        or not isinstance(interval, int)
        or not MIN_INTERVAL_SECONDS <= interval <= MAX_INTERVAL_SECONDS
    ):
        raise ReportError(
            f"interval_seconds must be an integer from {MIN_INTERVAL_SECONDS} "
            f"to {MAX_INTERVAL_SECONDS}"
        )

    version = body.get("version")
    if version is not None and not isinstance(version, str):
        raise ReportError("version must be a string")
    version = (version or "").strip()[:VERSION_MAX] or None

    raw = body.get("metrics")
    if not isinstance(raw, dict):
        raise ReportError("metrics must be a JSON object")
    metrics = {
        name: _count(name, raw[name]) for name in db.REPORT_METRICS if name in raw
    }
    if not metrics:
        raise ReportError("metrics has none of: " + ", ".join(db.REPORT_METRICS))
    return Report(started_at, interval, version, metrics)


# --- Reading reports back ------------------------------------------------

def _ts(row) -> datetime:
    return db.parse_ts(row["received_at"])


def _gap(row) -> timedelta:
    """A wider spacing than this between two reports means some were missed."""
    return timedelta(seconds=MISSED_REPORTS * row["interval_seconds"])


def _delta(prev, cur, name: str) -> Optional[int]:
    """How much counter ``name`` grew from ``prev`` to ``cur`` (same process)."""
    if prev["started_at"] != cur["started_at"]:
        return None
    a, b = prev[name], cur[name]
    if a is None or b is None or b < a:
        return None
    return b - a


def series(rows) -> dict:
    """Chart data for one client's reports (oldest first), in uPlot's layout.

    ``t`` is unix seconds; counters become per-second rates (errors per
    minute) between consecutive reports, None where the line must break.
    """
    out = {k: [] for k in ("t", "received", "published", "failed", "reconnects",
                           "queue")}

    def gap_point(at: datetime) -> None:
        out["t"].append(int(at.timestamp()))
        for k in ("received", "published", "failed", "reconnects", "queue"):
            out[k].append(None)

    prev = None
    for row in rows:
        at = _ts(row)
        if prev is not None and at - _ts(prev) > _gap(prev):
            # Missed reports: an explicit null so the line doesn't bridge them.
            gap_point(_ts(prev) + timedelta(seconds=prev["interval_seconds"]))
            prev = None
        seconds = (at - _ts(prev)).total_seconds() if prev is not None else 0

        def rate(name: str, per: float = 1.0) -> Optional[float]:
            if prev is None or seconds <= 0:
                return None
            d = _delta(prev, row, name)
            return None if d is None else round(d * per / seconds, 3)

        out["t"].append(int(at.timestamp()))
        out["received"].append(rate("packets_received"))
        out["published"].append(rate("messages_published"))
        out["failed"].append(rate("validations_failed", 60))
        out["reconnects"].append(rate("rabbitmq_reconnects", 60))
        out["queue"].append(row["queue_size"])
        prev = row
    return out


def sparklines(conn, now: datetime, hours: int) -> dict[str, list[Optional[float]]]:
    """Packets/s per SPARK_BUCKET over the last ``hours`` (None = no data),
    keyed by client_id. Bucketed in SQL: the dashboard draws every shoveler."""
    width = int(SPARK_BUCKET.total_seconds())
    n = math.ceil(timedelta(hours=hours) / SPARK_BUCKET)
    since = db.to_iso(now - n * SPARK_BUCKET)
    sums: dict[str, tuple[list[int], list[float]]] = {}
    for b in db.report_buckets(conn, since, width, MISSED_REPORTS):
        if 0 <= b["bucket"] < n:
            packets, seconds = sums.setdefault(b["client_id"], ([0] * n, [0.0] * n))
            packets[b["bucket"]] += b["packets"]
            seconds[b["bucket"]] += b["seconds"]
    return {
        cid: [round(p / s, 2) if s else None for p, s in zip(packets, seconds)]
        for cid, (packets, seconds) in sums.items()
    }


def totals(rows) -> dict[str, int]:
    """Each counter's growth across ``rows``, summed over process restarts."""
    sums = {name: 0 for name in COUNTERS}
    for prev, cur in zip(rows, rows[1:]):
        restarted = prev["started_at"] != cur["started_at"]
        for name in COUNTERS:
            # After a restart the counter grew from 0.
            sums[name] += (cur[name] if restarted else _delta(prev, cur, name)) or 0
    return sums


def restarts(rows) -> int:
    return sum(1 for a, b in zip(rows, rows[1:]) if a["started_at"] != b["started_at"])


@dataclass(frozen=True)
class Health:
    status: str  # healthy | no-packets | not-publishing | not-reporting | no-reports
    label: str
    detail: str


def ago(delta: timedelta) -> str:
    """'45 s', '12 min', '3 h', '2 d'."""
    s = max(0, int(delta.total_seconds()))
    if s < 90:
        return f"{s} s"
    if s < 90 * 60:
        return f"{round(s / 60)} min"
    if s < 36 * 3600:
        return f"{round(s / 3600)} h"
    return f"{round(s / 86400)} d"


def assess(latest, recent, now: Optional[datetime] = None) -> Health:
    """Health from a client's latest report and its reports over WINDOW.

    ``recent`` is the client's reports from the last WINDOW (oldest first);
    ``latest`` its newest report however old, or None if it never reported.
    """
    now = now or datetime.now(timezone.utc)
    if latest is None:
        return Health("no-reports", "No reports",
                      "This shoveler has never reported. It may predate health "
                      "reporting or not have registry.report_url set.")
    age = now - _ts(latest)
    if age > max(STALE_AFTER_MIN, _gap(latest)):
        return Health("not-reporting", "Not reporting",
                      f"Last report {ago(age)} ago.")

    # Judge the running process over the window: from its first report in
    # the window, or from its start (counters were 0) if it started since.
    proc = [r for r in recent if r["started_at"] == latest["started_at"]]
    started = db.parse_ts(latest["started_at"])
    if started >= now - WINDOW:
        base = {name: 0 for name in COUNTERS}
        since = started
    elif proc:
        base, since = proc[0], _ts(proc[0])
    else:
        base, since = latest, _ts(latest)
    if _ts(latest) - since >= EVIDENCE_MIN:
        minutes = round((_ts(latest) - since).total_seconds() / 60)
        received = _grew(base, latest, "packets_received")
        published = _grew(base, latest, "messages_published")
        if received == 0:
            return Health("no-packets", "No packets",
                          f"No packets received in the last {minutes} min. "
                          "Check that XRootD sends its monitoring stream here.")
        if received and published == 0:
            return Health("not-publishing", "Not publishing",
                          f"Received {received:,} packets in the last {minutes} min "
                          "but published none to the message bus.")
    return Health("healthy", "Healthy", f"Last report {ago(age)} ago.")


def _grew(base, latest, name: str) -> Optional[int]:
    a, b = base[name], latest[name]
    if a is None or b is None or b < a:
        return None
    return b - a


def current(rows) -> dict[str, Optional[float]]:
    """Packets/s received and published between the last two reports."""
    rates = {"received": None, "published": None}
    if len(rows) >= 2:
        prev, cur = rows[-2], rows[-1]
        seconds = (_ts(cur) - _ts(prev)).total_seconds()
        if 0 < seconds and _ts(cur) - _ts(prev) <= _gap(prev):
            for key, name in (("received", "packets_received"),
                              ("published", "messages_published")):
                d = _delta(prev, cur, name)
                rates[key] = None if d is None else d / seconds
    return rates


@dataclass(frozen=True)
class Block:
    state: str  # ok | warn | missing | none
    start: datetime
    title: str


def tracker(rows, now: datetime, hours: int) -> list[Block]:
    """One block per SPARK_BUCKET over the last ``hours``, oldest first.

    ``ok``: reports with packets flowing and published; ``warn``: reports, but
    no packets or none published; ``missing``: no report in the block since
    the shoveler first reported; ``none``: before that.
    """
    start = now - timedelta(hours=hours)
    n = math.ceil(timedelta(hours=hours) / SPARK_BUCKET)
    seen = [False] * n
    received: list[Optional[int]] = [None] * n
    published: list[Optional[int]] = [None] * n

    def index(at: datetime) -> int:
        return int((at - start) / SPARK_BUCKET)

    for row in rows:
        if 0 <= index(_ts(row)) < n:
            seen[index(_ts(row))] = True
    for prev, cur in zip(rows, rows[1:]):
        i = index(_ts(cur))
        if not 0 <= i < n or _ts(cur) - _ts(prev) > _gap(prev):
            continue
        for sums, name in ((received, "packets_received"),
                           (published, "messages_published")):
            d = _delta(prev, cur, name)
            if d is not None:
                sums[i] = (sums[i] or 0) + d

    first = index(_ts(rows[0])) if rows else n
    blocks = []
    for i in range(n):
        at = start + i * SPARK_BUCKET
        when = f"{at:%H:%M}–{at + SPARK_BUCKET:%H:%M} UTC"
        if not seen[i]:
            state = "none" if i < first else "missing"
            title = f"{when}: no reports"
        elif received[i] == 0:
            state, title = "warn", f"{when}: no packets received"
        elif received[i] and published[i] == 0:
            state, title = "warn", f"{when}: {received[i]:,} packets, none published"
        else:
            state = "ok"
            title = f"{when}: {received[i]:,} packets" if received[i] else f"{when}: reporting"
        blocks.append(Block(state, at, title))
    return blocks
