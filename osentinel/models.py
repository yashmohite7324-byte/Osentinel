"""Core data structures shared by collectors, detectors and the API layer."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


SEVERITY_BANDS = [
    (85, "critical"),
    (65, "high"),
    (40, "medium"),
    (15, "low"),
    (0, "info"),
]


def severity_band(score: float) -> str:
    for threshold, name in SEVERITY_BANDS:
        if score >= threshold:
            return name
    return "info"


@dataclass
class Event:
    """A single normalised observation taken from the operating system."""

    category: str          # process | network | filesystem | resource | identity
    action: str            # process_started, connection_opened, file_modified ...
    entity: str            # pid, path, socket tuple - whatever identifies the subject
    attrs: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: _uid("evt"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Detection:
    """Output of a detector: something that looks wrong, with evidence attached."""

    rule_id: str
    title: str
    score: float                       # 0-100 raw severity contribution
    confidence: float                  # 0-1
    source: str                        # rule | baseline | ml | correlation
    entity: str
    category: str = "process"
    mitre: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: _uid("det"))

    @property
    def severity(self) -> str:
        return severity_band(self.score)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity
        return d


@dataclass
class ResponseAction:
    action: str            # suspend | terminate | quarantine | isolate | notify
    target: str
    executed: bool
    dry_run: bool
    detail: str = ""
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Incident:
    """Several detections about the same subject, folded into one story."""

    title: str
    entity: str
    score: float
    detections: list[Detection] = field(default_factory=list)
    actions: list[ResponseAction] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    narrative: str = ""
    state: str = "open"                # open | contained | closed
    opened_ts: float = field(default_factory=time.time)
    updated_ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: _uid("inc"))

    @property
    def severity(self) -> str:
        return severity_band(self.score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "entity": self.entity,
            "score": round(self.score, 1),
            "severity": self.severity,
            "state": self.state,
            "mitre": self.mitre,
            "narrative": self.narrative,
            "opened_ts": self.opened_ts,
            "updated_ts": self.updated_ts,
            "detections": [d.to_dict() for d in self.detections],
            "actions": [a.to_dict() for a in self.actions],
        }
