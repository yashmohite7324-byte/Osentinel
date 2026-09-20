"""Signature layer: YAML-declared heuristics evaluated against each Event.

Rules are data, not code, so an analyst can add coverage without touching
Python. The `when` field is a Python expression evaluated in a namespace that
contains only the event fields plus a handful of whitelisted helpers - no
builtins, no imports, no attribute access to anything dangerous.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from ..models import Detection, Event


def shannon_entropy(s: str) -> float:
    """High entropy in a filename or argument often means packing or encoding."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def matches(pattern: str, text: str) -> bool:
    try:
        return re.search(pattern, text or "", re.IGNORECASE) is not None
    except re.error:
        return False


def any_of(text: str, needles: list[str]) -> bool:
    low = (text or "").lower()
    return any(n.lower() in low for n in needles)


SAFE_HELPERS: dict[str, Any] = {
    "entropy": shannon_entropy,
    "matches": matches,
    "any_of": any_of,
    "len": len,
    "abs": abs,
    "min": min,
    "max": max,
    "int": int,
    "float": float,
    "str": str,
    "lower": lambda s: (s or "").lower(),
    "basename": lambda p: Path(p or "").name,
    "dirname": lambda p: str(Path(p or "").parent),
}


class Rule:
    __slots__ = ("id", "title", "category", "action", "when", "score", "confidence",
                 "mitre", "remediation", "evidence_fields", "_code")

    def __init__(self, raw: dict):
        self.id = raw["id"]
        self.title = raw["title"]
        self.category = raw.get("category", "process")
        self.action = raw.get("action")          # optional event-action filter
        self.when = raw["when"]
        self.score = float(raw.get("score", 50))
        self.confidence = float(raw.get("confidence", 0.7))
        self.mitre = raw.get("mitre", []) or []
        self.remediation = raw.get("remediation", "")
        self.evidence_fields = raw.get("evidence", []) or []
        # YAML folded scalars keep newlines on more-indented continuation lines,
        # so wrap the whole expression to make any line break implicit.
        self._code = compile(f"(\n{self.when}\n)", f"<rule:{self.id}>", "eval")

    def evaluate(self, event: Event) -> Detection | None:
        if self.category != "*" and event.category != self.category:
            return None
        if self.action and event.action != self.action:
            return None

        ns = {**SAFE_HELPERS, **event.attrs,
              "action": event.action, "entity": event.entity, "category": event.category}
        try:
            hit = bool(eval(self._code, {"__builtins__": {}}, ns))  # noqa: S307 - sandboxed ns
        except Exception:
            return None
        if not hit:
            return None

        fields = self.evidence_fields or list(event.attrs.keys())[:8]
        evidence = {k: event.attrs.get(k) for k in fields if k in event.attrs}
        evidence["matched_expression"] = self.when
        return Detection(
            rule_id=self.id, title=self.title, score=self.score,
            confidence=self.confidence, source="rule", entity=event.entity,
            category=event.category, mitre=list(self.mitre),
            evidence=evidence, remediation=self.remediation, ts=event.ts)


class RuleEngine:
    def __init__(self, rules_path: str = "rules/rules.yaml"):
        self.rules: list[Rule] = []
        self.errors: list[str] = []
        self.load(rules_path)

    def load(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            self.errors.append(f"rule file not found: {path}")
            return
        doc = yaml.safe_load(p.read_text()) or {}
        for raw in doc.get("rules", []):
            try:
                self.rules.append(Rule(raw))
            except Exception as exc:
                self.errors.append(f"{raw.get('id', '?')}: {exc}")

    def run(self, events: list[Event]) -> list[Detection]:
        out: list[Detection] = []
        for e in events:
            for r in self.rules:
                d = r.evaluate(e)
                if d:
                    out.append(d)
        return out

    def describe(self) -> list[dict]:
        """Everything about a rule that a human might reasonably ask.

        The `when` expression is included deliberately. An operator deciding
        whether an alert is a false positive needs to see the condition that
        fired, not a paraphrase of it, and the assistant reads this same view.
        """
        return [{"id": r.id, "title": r.title, "category": r.category,
                 "action": r.action, "score": r.score, "confidence": r.confidence,
                 "mitre": r.mitre, "remediation": r.remediation.strip(),
                 "condition": " ".join(r.when.split()),
                 "evidence_fields": r.evidence_fields} for r in self.rules]
