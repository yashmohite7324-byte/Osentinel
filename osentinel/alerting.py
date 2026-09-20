"""Alerting: getting the harm message to a human when a threat lands.

Everything else in this system answers "is this a threat". This module answers
the question that only matters once the answer is yes: does anyone actually
find out, and in time. A detection that reaches a dashboard nobody is looking
at is, operationally, a detection that did not happen.

An alert is not the same object as an incident. An incident is the analytical
record - every detection, every score, the full evidence. An alert is the
human-facing distillation of it: what happened, how bad, on what, and what to
do in the next sixty seconds, phrased so a person reading it on their phone
understands it without opening a console. The two are deliberately separate,
because the incident is for investigation and the alert is for interruption,
and interrupting well is its own discipline.

    incident ──▶ should this interrupt a human? ──▶ compose harm message ──▶ fan out
                  │  severity gate                    │ severity, entity,      │ console
                  │  dedup (same threat, once)         │ what happened,         │ log file
                  │  throttle (no alert storms)        │ what to do now         │ webhook
                  └────────────────────────────────────┴────────────────────────┘

The discipline is mostly in what it refuses to send. A monitoring tool that
pages on everything trains its operator to ignore it, and an ignored alert
channel is worse than none because it is trusted to be silent when things are
fine. So the gate is strict by default, identical threats collapse to one
alert, and a burst of activity is rate-limited into a single "multiple
incidents" summary rather than a hundred separate buzzes.

Channels are pluggable and each fails independently. A broken webhook must not
stop the console alert, and no channel blocking on the network may ever stall
detection - delivery runs on its own thread, off the analysis path entirely.
"""

from __future__ import annotations

import json
import queue
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

# ── severity language ────────────────────────────────────────────────────
# The one-line human verdict per band. Written to be read cold, on a lock
# screen, by someone who was doing something else a second ago.
_HEADLINE = {
    "critical": "CRITICAL — active threat on this host",
    "high":     "HIGH — likely intrusion in progress",
    "medium":   "MEDIUM — suspicious activity worth a look",
    "low":      "LOW — minor anomaly noted",
}

# What to do first, per band. Deliberately one action, not a checklist - a
# person reacting to an alert can hold one instruction, not five.
_FIRST_MOVE = {
    "critical": "Contain the process now and preserve its memory; treat the host as compromised.",
    "high":     "Isolate the host from the network and investigate the named process immediately.",
    "medium":   "Review the process and its parent before it does anything further.",
    "low":      "No immediate action needed; note it in case it recurs.",
}


@dataclass
class Alert:
    incident_id: str
    severity: str
    score: float
    entity: str
    title: str
    headline: str
    body: str
    first_move: str
    mitre: list[str] = field(default_factory=list)
    ts: float = field(default_factory=time.time)
    fingerprint: str = ""
    count: int = 1                 # how many incidents this alert represents

    def to_dict(self) -> dict:
        return {"incident_id": self.incident_id, "severity": self.severity,
                "score": round(self.score, 1), "entity": self.entity,
                "title": self.title, "headline": self.headline, "body": self.body,
                "first_move": self.first_move, "mitre": self.mitre,
                "ts": self.ts, "fingerprint": self.fingerprint, "count": self.count}

    def as_text(self) -> str:
        """Plain-text harm message, the form every channel can carry."""
        lines = [self.headline,
                 f"What: {self.title}",
                 f"Where: {self.entity}  (risk {self.score:.0f}/100)"]
        if self.mitre:
            lines.append(f"Technique: {', '.join(self.mitre)}")
        if self.count > 1:
            lines.append(f"Note: {self.count} related incidents in a short window.")
        lines.append(f"Do now: {self.first_move}")
        return "\n".join(lines)


# ── channels ─────────────────────────────────────────────────────────────

class Channel:
    name = "base"
    def deliver(self, alert: Alert) -> None:            # pragma: no cover
        raise NotImplementedError
    def status(self) -> dict:
        return {"name": self.name}


class ConsoleChannel(Channel):
    """Pushes the alert over the same websocket the dashboard already uses, so
    an open console flashes the harm message without a poll."""
    name = "console"

    def __init__(self, broadcast):
        self._broadcast = broadcast
        self.sent = 0

    def deliver(self, alert: Alert) -> None:
        self._broadcast({"type": "alert", "data": alert.to_dict()})
        self.sent += 1

    def status(self) -> dict:
        return {"name": self.name, "sent": self.sent}


class LogChannel(Channel):
    """Appends every alert as one JSON line. This is the channel that is always
    on, needs no configuration, and gives you an after-the-fact record even
    when nobody was watching and no webhook was set."""
    name = "log"

    def __init__(self, path: str = "data/alerts.log.jsonl"):
        self.path = path
        self.sent = 0
        self.last_error = ""
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    def deliver(self, alert: Alert) -> None:
        try:
            with open(self.path, "a") as fh:
                fh.write(json.dumps(alert.to_dict(), default=str) + "\n")
            self.sent += 1
        except OSError as exc:
            self.last_error = str(exc)

    def status(self) -> dict:
        return {"name": self.name, "path": self.path, "sent": self.sent,
                "last_error": self.last_error or None}


class WebhookChannel(Channel):
    """POSTs the alert as JSON to a URL. Works with Slack and Discord incoming
    webhooks (it sends a `text` field they both render) and with any custom
    endpoint or email gateway. Off unless a URL is configured."""
    name = "webhook"

    def __init__(self, url: str = "", timeout: float = 8.0):
        self.url = url
        self.timeout = timeout
        self.sent = 0
        self.failures = 0
        self.last_error = ""

    @property
    def configured(self) -> bool:
        return bool(self.url)

    def deliver(self, alert: Alert) -> None:
        if not self.url:
            return
        # `text` satisfies Slack and Discord; `alert` carries the structured
        # form for anything custom parsing the same payload.
        payload = json.dumps({"text": alert.as_text(), "alert": alert.to_dict()}).encode()
        req = urllib.request.Request(self.url, data=payload, method="POST",
                                     headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout):
                self.sent += 1
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.failures += 1
            self.last_error = f"{type(exc).__name__}"

    def status(self) -> dict:
        return {"name": self.name, "configured": self.configured,
                "sent": self.sent, "failures": self.failures,
                "last_error": self.last_error or None}


# ── manager ──────────────────────────────────────────────────────────────

class AlertManager:
    def __init__(self, enabled: bool = True, min_severity: str = "high",
                 broadcast=None, webhook_url: str = "",
                 log_path: str = "data/alerts.log.jsonl",
                 throttle_window_s: float = 60.0, throttle_max: int = 5,
                 dedup_ttl_s: float = 900.0):
        self.enabled = enabled
        self.min_rank = self._rank(min_severity)
        self.throttle_window_s = throttle_window_s
        self.throttle_max = throttle_max
        self.dedup_ttl_s = dedup_ttl_s

        self.channels: list[Channel] = [LogChannel(log_path)]
        if broadcast is not None:
            self.channels.insert(0, ConsoleChannel(broadcast))
        self.webhook = WebhookChannel(webhook_url)
        if self.webhook.configured:
            self.channels.append(self.webhook)

        # delivery runs off the detection thread
        self._queue: queue.Queue = queue.Queue(maxsize=200)
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None

        # dedup + throttle state
        self._seen: dict[str, float] = {}                 # fingerprint -> last sent
        self._recent: deque[float] = deque()              # send timestamps
        self._suppressed_since_throttle = 0
        self._lock = threading.Lock()

        self.raised = 0
        self.suppressed_dedup = 0
        self.suppressed_severity = 0
        self.history: deque[Alert] = deque(maxlen=100)

    @staticmethod
    def _rank(sev: str) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 3)

    # -- composition: incident -> harm message ------------------------------

    def _fingerprint(self, incident) -> str:
        """Two incidents are 'the same threat' if they share entity, severity
        and the set of rules that fired. This is what stops one ongoing attack
        from paging every few seconds while its score ticks up."""
        rules = sorted({d.rule_id for d in incident.detections})
        return f"{incident.entity}|{incident.severity}|{','.join(rules)}"

    def _compose(self, incident) -> Alert:
        sev = incident.severity
        families = sorted({d.source for d in incident.detections})
        corrob = ("Multiple independent detectors agree."
                  if len(families) > 1 else
                  f"Detected by the {families[0] if families else 'rule'} layer.")
        # Prefer the model's narrative if triage has written one; it is the most
        # human sentence available. Otherwise assemble from the detections.
        if incident.narrative:
            what = incident.narrative
        else:
            top = max(incident.detections, key=lambda d: d.score, default=None)
            what = top.title if top else incident.title
        body = (f"{_HEADLINE.get(sev, sev.upper())}. {what} on {incident.entity}, "
                f"scoring {incident.score:.0f} out of 100. {corrob}")
        return Alert(
            incident_id=incident.id, severity=sev, score=incident.score,
            entity=incident.entity, title=incident.title,
            headline=_HEADLINE.get(sev, sev.upper()), body=body,
            first_move=_FIRST_MOVE.get(sev, "Review the incident."),
            mitre=list(incident.mitre), fingerprint=self._fingerprint(incident))

    # -- gating -------------------------------------------------------------

    def consider(self, incident) -> str:
        """Decide whether this incident becomes an alert, and enqueue if so.

        Returns the reason: 'raised', 'below_severity', 'duplicate', 'throttled',
        or 'disabled'. Called from the detection path, so it does no I/O - it
        only composes and enqueues; the worker delivers.
        """
        if not self.enabled:
            return "disabled"
        if self._rank(incident.severity) < self.min_rank:
            self.suppressed_severity += 1
            return "below_severity"

        alert = self._compose(incident)
        now = time.time()
        with self._lock:
            # dedup: same threat inside the TTL is not re-sent
            last = self._seen.get(alert.fingerprint)
            if last is not None and now - last < self.dedup_ttl_s:
                self.suppressed_dedup += 1
                return "duplicate"

            # throttle: cap alerts per window; excess collapses into a count
            while self._recent and now - self._recent[0] > self.throttle_window_s:
                self._recent.popleft()
            if len(self._recent) >= self.throttle_max:
                self._suppressed_since_throttle += 1
                return "throttled"

            self._seen[alert.fingerprint] = now
            self._recent.append(now)
            if len(self._seen) > 2000:
                self._seen = {k: v for k, v in self._seen.items()
                              if now - v < self.dedup_ttl_s}
            # fold any throttled-away incidents into this alert's count
            if self._suppressed_since_throttle:
                alert.count += self._suppressed_since_throttle
                self._suppressed_since_throttle = 0

        self.raised += 1
        self.history.appendleft(alert)
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            pass
        return "raised"

    # -- delivery worker ----------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            for ch in self.channels:
                try:
                    ch.deliver(alert)
                except Exception:
                    # a channel must never take down delivery for the others
                    continue

    def start(self) -> None:
        if self._worker:
            return
        self._worker = threading.Thread(target=self._run, name="alerts", daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._stop.set()

    # -- introspection / test hooks -----------------------------------------

    def set_webhook(self, url: str) -> None:
        self.webhook.url = url
        if url and self.webhook not in self.channels:
            self.channels.append(self.webhook)

    def send_test(self) -> Alert:
        """Fire a synthetic alert through every channel, so an operator can
        confirm delivery works before trusting it with a real one."""
        alert = Alert(
            incident_id="inc-test", severity="high", score=88.0, entity="pid 4242",
            title="Test alert — delivery check", headline=_HEADLINE["high"],
            body="This is a test alert from OSentinel confirming the channel works.",
            first_move=_FIRST_MOVE["high"], mitre=["T1059"], fingerprint="test")
        for ch in self.channels:
            try:
                ch.deliver(alert)
            except Exception:
                continue
        return alert

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "min_severity": {0: "info", 1: "low", 2: "medium", 3: "high",
                             4: "critical"}[self.min_rank],
            "channels": [ch.status() for ch in self.channels],
            "raised": self.raised,
            "suppressed_below_severity": self.suppressed_severity,
            "suppressed_duplicate": self.suppressed_dedup,
            "throttle": {"window_s": self.throttle_window_s, "max": self.throttle_max},
            "recent": [a.to_dict() for a in list(self.history)[:10]],
        }
