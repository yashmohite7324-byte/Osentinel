"""Durable storage for telemetry.

Uses SQLite in WAL mode so the collector threads can write while the API layer
reads without blocking each other. Every write goes through one lock because a
single connection is shared across threads (check_same_thread=False).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .models import Detection, Event, Incident

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, ts REAL, category TEXT, action TEXT,
    entity TEXT, attrs TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category);

CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY, ts REAL, rule_id TEXT, title TEXT, score REAL,
    confidence REAL, source TEXT, entity TEXT, category TEXT,
    mitre TEXT, evidence TEXT, remediation TEXT
);
CREATE INDEX IF NOT EXISTS idx_det_ts ON detections(ts);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY, opened_ts REAL, updated_ts REAL, title TEXT,
    entity TEXT, score REAL, state TEXT, mitre TEXT, narrative TEXT, payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_inc_ts ON incidents(updated_ts);

CREATE TABLE IF NOT EXISTS metrics (
    ts REAL, name TEXT, value REAL
);
CREATE INDEX IF NOT EXISTS idx_metrics ON metrics(name, ts);

CREATE TABLE IF NOT EXISTS baseline_files (
    path TEXT PRIMARY KEY, sha256 TEXT, size INTEGER, mtime REAL, mode INTEGER
);
"""


class Store:
    def __init__(self, path: str = "data/osentinel.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    # ---------------------------------------------------------------- writes

    def add_events(self, events: list[Event]) -> None:
        if not events:
            return
        rows = [
            (e.id, e.ts, e.category, e.action, e.entity, json.dumps(e.attrs, default=str))
            for e in events
        ]
        with self._lock:
            self._db.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?)", rows)
            self._db.commit()

    def add_detections(self, dets: list[Detection]) -> None:
        if not dets:
            return
        rows = [
            (d.id, d.ts, d.rule_id, d.title, d.score, d.confidence, d.source, d.entity,
             d.category, json.dumps(d.mitre), json.dumps(d.evidence, default=str), d.remediation)
            for d in dets
        ]
        with self._lock:
            self._db.executemany(
                "INSERT OR REPLACE INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            self._db.commit()

    def upsert_incident(self, inc: Incident) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?)",
                (inc.id, inc.opened_ts, inc.updated_ts, inc.title, inc.entity, inc.score,
                 inc.state, json.dumps(inc.mitre), inc.narrative,
                 json.dumps(inc.to_dict(), default=str)))
            self._db.commit()

    def add_metrics(self, samples: dict[str, float], ts: float | None = None) -> None:
        ts = ts or time.time()
        with self._lock:
            self._db.executemany(
                "INSERT INTO metrics VALUES (?,?,?)",
                [(ts, k, float(v)) for k, v in samples.items()])
            self._db.commit()

    def save_file_baseline(self, rows: list[tuple]) -> None:
        if not rows:
            return
        with self._lock:
            self._db.executemany(
                "INSERT OR REPLACE INTO baseline_files VALUES (?,?,?,?,?)", rows)
            self._db.commit()

    # ----------------------------------------------------------------- reads

    def _q(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    def recent_events(self, limit: int = 200, category: str | None = None):
        if category:
            rows = self._q("SELECT * FROM events WHERE category=? ORDER BY ts DESC LIMIT ?",
                           (category, limit))
        else:
            rows = self._q("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
        for r in rows:
            r["attrs"] = json.loads(r["attrs"])
        return rows

    def recent_detections(self, limit: int = 200):
        rows = self._q("SELECT * FROM detections ORDER BY ts DESC LIMIT ?", (limit,))
        for r in rows:
            r["mitre"] = json.loads(r["mitre"])
            r["evidence"] = json.loads(r["evidence"])
        return rows

    def incidents(self, limit: int = 100):
        rows = self._q("SELECT payload FROM incidents ORDER BY updated_ts DESC LIMIT ?", (limit,))
        return [json.loads(r["payload"]) for r in rows]

    def metric_series(self, name: str, since: float):
        return self._q(
            "SELECT ts, value FROM metrics WHERE name=? AND ts>=? ORDER BY ts ASC",
            (name, since))

    def file_baseline(self) -> dict[str, dict]:
        return {r["path"]: r for r in self._q("SELECT * FROM baseline_files")}

    def counts(self) -> dict[str, int]:
        out = {}
        for table in ("events", "detections", "incidents"):
            out[table] = self._q(f"SELECT COUNT(*) c FROM {table}")[0]["c"]
        return out

    def prune(self, older_than_seconds: float) -> None:
        cutoff = time.time() - older_than_seconds
        with self._lock:
            self._db.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self._db.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()
