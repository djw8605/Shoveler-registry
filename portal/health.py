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
# One tracker block (and hourly-table row) covers this long.
BUCKET = timedelta(minutes=15)

# Badge labels, worst first; the tracker adds "no-data" (before any report).
LABELS = {
    "not-publishing": "Not publishing",
    "not-reporting": "Not reporting",
    "no-packets": "No packets",
    "healthy": "Healthy",
    "no-reports": "No reports",
    "no-data": "No data",
}


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


def clock(at: datetime, now: datetime) -> str:
    """'02:15 UTC', with the date when it isn't today."""
    at = at.astimezone(timezone.utc)
    same_day = at.date() == now.astimezone(timezone.utc).date()
    return f"{at:%H:%M} UTC" if same_day else f"{at:%Y-%m-%d %H:%M} UTC"


def series(rows, start: datetime, end: datetime) -> dict:
    """Chart data for one client's reports (oldest first), in uPlot's layout.

    ``t`` is unix seconds; counters become per-second rates (errors per
    minute) between consecutive reports, None where the line must break.
    Empty points at ``start`` and ``end`` make the charts span that window
    whatever the reports cover.
    """
    keys = ("received", "published", "failed", "reconnects", "queue")
    out = {"t": [], **{k: [] for k in keys}}

    def gap_point(at: datetime) -> None:
        out["t"].append(int(at.timestamp()))
        for k in keys:
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
    if prev is not None and end - _ts(prev) > _gap(prev):
        # Silent since: leave the rest of the window empty.
        gap_point(_ts(prev) + timedelta(seconds=prev["interval_seconds"]))
    if not out["t"] or out["t"][0] > start.timestamp():
        gap_point(start)
        for k in out:
            out[k].insert(0, out[k].pop())
    if out["t"][-1] < int(end.timestamp()):
        gap_point(end)
    return out


def hourly(rows, now: datetime, hours: int) -> list[dict]:
    """Per-hour figures (newest first): the charts as a table."""
    start = now - timedelta(hours=hours)
    out = [{"start": start + timedelta(hours=h), "reports": 0, "packets": 0,
            "published": 0, "seconds": 0.0, "failed": 0, "reconnects": 0,
            "queue": None} for h in range(hours)]
    for k, row in enumerate(rows):
        h = int((_ts(row) - start) / timedelta(hours=1))
        if not 0 <= h < hours:
            continue
        cell = out[h]
        cell["reports"] += 1
        if row["queue_size"] is not None:
            cell["queue"] = max(cell["queue"] or 0, row["queue_size"])
        prev = rows[k - 1] if k else None
        if prev is None or _ts(row) - _ts(prev) > _gap(prev):
            continue
        d = _delta(prev, row, "packets_received")
        if d is not None:
            cell["packets"] += d
            cell["seconds"] += (_ts(row) - _ts(prev)).total_seconds()
        for key, name in (("published", "messages_published"),
                          ("failed", "validations_failed"),
                          ("reconnects", "rabbitmq_reconnects")):
            cell[key] += _delta(prev, row, name) or 0
    for cell in out:
        s = cell.pop("seconds")
        cell["received_rate"] = cell["packets"] / s if s else None
        cell["published_rate"] = cell["published"] / s if s else None
    return out[::-1]


def totals(rows) -> dict[str, int]:
    """Each counter's growth across ``rows``, summed over process restarts."""
    sums = {name: 0 for name in COUNTERS}
    for prev, cur in zip(rows, rows[1:]):
        restarted = prev["started_at"] != cur["started_at"]
        for name in COUNTERS:
            # After a restart the counter grew from 0.
            sums[name] += (cur[name] if restarted else _delta(prev, cur, name)) or 0
    return sums


def restarts(rows) -> list[datetime]:
    """When each process seen in ``rows`` after the first one started."""
    return [db.parse_ts(b["started_at"])
            for a, b in zip(rows, rows[1:]) if a["started_at"] != b["started_at"]]


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


# --- Health ----------------------------------------------------------------

@dataclass(frozen=True)
class Health:
    status: str  # a key of LABELS other than no-data
    summary: str  # what is wrong and since when
    advice: str = ""  # what to check
    since: Optional[datetime] = None  # when this state began, if known

    @property
    def label(self) -> str:
        return LABELS[self.status]


def _since(at: datetime, now: datetime, known: bool = True) -> str:
    when = clock(at, now)
    return f"{when} ({ago(now - at)} ago)" if known else f"before {when}"


def _flat_since(rows, latest, name: str):
    """When counter ``name`` last grew in ``latest``'s process.

    Returns (time, the report it last grew by or None if never, known):
    ``known`` is False when it was already flat at the oldest report we have.
    """
    proc = [r for r in rows if r["started_at"] == latest["started_at"]
            and r[name] is not None and _ts(r) <= _ts(latest)]
    for k in range(len(proc) - 1, 0, -1):
        if proc[k - 1][name] < proc[k][name]:
            return _ts(proc[k]), proc[k], True
    if not latest[name]:
        # Still 0: it never grew since the process started.
        return db.parse_ts(latest["started_at"]), None, True
    first = proc[0] if proc else latest
    whole = bool(rows) and db.parse_ts(latest["started_at"]) >= _ts(rows[0])
    return _ts(first), first, whole


def assess(latest, rows, now: Optional[datetime] = None) -> Health:
    """Health from a client's latest report and its recent reports.

    ``rows`` are the client's reports, oldest first, covering at least WINDOW
    (more lets the onset of a problem be dated further back); ``latest`` is
    its newest report however old, or None if it never reported.
    """
    now = now or datetime.now(timezone.utc)
    if latest is None:
        return Health("no-reports", "Never reported.",
                      "It may predate health reporting, or have "
                      "amqp.oauth.report_health turned off.")
    age = now - _ts(latest)
    if age > max(STALE_AFTER_MIN, _gap(latest)):
        return Health("not-reporting", f"No report since {_since(_ts(latest), now)}.",
                      "Check that the shoveler is running and can reach this registry.",
                      _ts(latest))

    # Judge the running process over the window: from its first report in
    # the window, or from its start (counters were 0) if it started since.
    proc = [r for r in rows if r["started_at"] == latest["started_at"]
            and _ts(r) >= now - WINDOW]
    started = db.parse_ts(latest["started_at"])
    if started >= now - WINDOW:
        base = {name: 0 for name in COUNTERS}
        since = started
    elif proc:
        base, since = proc[0], _ts(proc[0])
    else:
        base, since = latest, _ts(latest)
    if _ts(latest) - since >= EVIDENCE_MIN:
        received = _grew(base, latest, "packets_received")
        published = _grew(base, latest, "messages_published")
        if received == 0:
            at, _, known = _flat_since(rows, latest, "packets_received")
            return Health("no-packets",
                          f"No packets received since {_since(at, now, known)}.",
                          "Check that XRootD's monitoring stream is sent to this "
                          "shoveler.", at)
        if received and published == 0:
            at, row, known = _flat_since(rows, latest, "messages_published")
            got = latest["packets_received"] - (row["packets_received"] if row else 0)
            return Health("not-publishing",
                          f"Nothing published since {_since(at, now, known)}, "
                          f"though {got:,} packets arrived.",
                          "Check that the shoveler can reach RabbitMQ and that "
                          "RabbitMQ accepts its token.", at)
    return Health("healthy", f"Last report {ago(age)} ago.")


def _grew(base, latest, name: str) -> Optional[int]:
    a, b = base[name], latest[name]
    if a is None or b is None or b < a:
        return None
    return b - a


# --- The 24-hour tracker ---------------------------------------------------

@dataclass(frozen=True)
class Block:
    state: str  # a key of LABELS
    start: datetime
    title: str


@dataclass(frozen=True)
class Run:
    """Consecutive blocks in one state."""
    state: str
    start: datetime
    end: datetime
    blocks: int

    @property
    def label(self) -> str:
        return LABELS[self.state]


def trackers(conn, now: datetime, hours: int, latest: dict,
             client_id: Optional[str] = None) -> dict[str, list[Block]]:
    """Each client's blocks over the last ``hours``, oldest first.

    ``latest`` maps client_id to its newest report (db.latest_reports), so a
    shoveler that went quiet before the window still shows as not reporting.
    The aggregation runs in SQL: the dashboard draws every shoveler.
    """
    n = math.ceil(timedelta(hours=hours) / BUCKET)
    start = now - n * BUCKET
    buckets: dict[str, dict[int, dict]] = {}
    for b in db.report_buckets(conn, db.to_iso(start), int(BUCKET.total_seconds()),
                               MISSED_REPORTS, client_id):
        if 0 <= b["bucket"] < n:
            buckets.setdefault(b["client_id"], {})[b["bucket"]] = b
    ids = [client_id] if client_id else set(latest) | set(buckets)
    return {cid: _blocks(buckets.get(cid, {}), latest.get(cid), start, n)
            for cid in ids}


def _blocks(buckets: dict, latest, start: datetime, n: int) -> list[Block]:
    # The last report seen so far, and its interval: seeded from before the
    # window when the shoveler's latest report is older than it.
    last = None
    if latest is not None and _ts(latest) < start:
        last = (_ts(latest), latest["interval_seconds"])
    state = "no-data"
    blocks = []
    for i in range(n):
        at = start + i * BUCKET
        end = at + BUCKET
        when = f"{at:%H:%M}–{end:%H:%M} UTC"
        b = buckets.get(i)
        if b is None:
            if last is None:
                state, title = "no-data", f"{when}: no reports yet"
            elif end - last[0] > timedelta(seconds=MISSED_REPORTS * last[1]):
                state, title = "not-reporting", f"{when}: no reports"
            else:
                title = f"{when}: between reports"  # long interval: keep the state
        else:
            last = (db.parse_ts(b["latest"]), b["interval_seconds"])
            packets, published = b["packets"], b["published"]
            if packets == 0:
                state, title = "no-packets", f"{when}: no packets received"
            elif packets and published == 0:
                state = "not-publishing"
                title = f"{when}: {packets:,} packets received, none published"
            else:
                state = "healthy"
                title = f"{when}: {packets:,} packets" if packets else f"{when}: reporting"
        blocks.append(Block(state, at, title))
    return blocks


def runs(blocks: list[Block]) -> list[Run]:
    """The tracker as runs of one state, oldest first."""
    out: list[Run] = []
    for b in blocks:
        if out and out[-1].state == b.state:
            last = out[-1]
            out[-1] = Run(last.state, last.start, b.start + BUCKET, last.blocks + 1)
        else:
            out.append(Run(b.state, b.start, b.start + BUCKET, 1))
    return out


def pin_onset(runs: list[Run], health: Health) -> list[Run]:
    """Start the newest run at the exact onset the reports give, when it is
    the health state and the onset falls within a block of the run's start
    (blocks only know 15-minute edges)."""
    if not runs or health.since is None or runs[-1].state != health.status:
        return runs
    last = runs[-1]
    if not last.start - BUCKET <= health.since <= last.start + BUCKET:
        return runs
    pinned = [Run(last.state, health.since, last.end, last.blocks)]
    if len(runs) > 1:
        prev = runs[-2]
        pinned.insert(0, Run(prev.state, prev.start, health.since, prev.blocks))
    return runs[:-2] + pinned if len(runs) > 1 else pinned


def changes(runs: list[Run], now: datetime) -> list[tuple[Run, str]]:
    """The runs newest first, each with when it held: "Since 13:26 UTC" for
    the current one, a date on times before today."""
    def at(t: datetime) -> str:
        same_day = t.date() == now.astimezone(timezone.utc).date()
        return f"{t:%H:%M}" if same_day else f"{t:%Y-%m-%d %H:%M}"

    out = []
    for i, r in enumerate(reversed(runs)):
        when = f"Since {at(r.start)} UTC" if i == 0 else f"{at(r.start)} – {at(r.end)} UTC"
        out.append((r, when))
    return out


def describe(runs: list[Run], now: datetime) -> str:
    """The tracker in words, e.g. for a screen reader."""
    parts = []
    for i, r in enumerate(runs):
        end = "now" if i == len(runs) - 1 else clock(r.end, now)
        parts.append(f"{r.label} from {clock(r.start, now)} to {end}")
    return "; ".join(parts) + "."
