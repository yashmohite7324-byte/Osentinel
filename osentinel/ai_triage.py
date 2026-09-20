"""AI triage: turn an incident's raw evidence into an analyst-readable brief.

If an Anthropic API key is present the incident goes to a model for a written
assessment. If it isn't - offline lab, no key, no network - the module falls
back to a deterministic template built from the same evidence, so the product
never has a dead feature. The fallback is not a stub: it reports the real
kill-chain stage, the corroborating detectors, and the recommended action.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request

from .detect.correlator import stage_for
from .models import Incident

API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"

SYSTEM = (
    "You are a host-intrusion analyst. You receive structured detection evidence "
    "from an endpoint agent. Write a triage note of at most 120 words with three "
    "parts, unlabelled and in plain prose: what the evidence shows, how confident "
    "you are and why, and the single next action an operator should take. Never "
    "invent evidence that is not in the input. If the evidence is weak, say so "
    "plainly and recommend closing the alert."
)


def _fallback(inc: Incident) -> str:
    stage, _ = stage_for(inc.mitre)
    families = sorted({d.source for d in inc.detections})
    rules = sorted({d.rule_id for d in inc.detections})
    top = max(inc.detections, key=lambda d: d.score) if inc.detections else None

    family_text = {
        "rule": "signature rules", "baseline": "statistical baselining",
        "ml": "the anomaly model", "correlation": "correlation",
    }
    named = [family_text.get(f, f) for f in families]
    agree = named[0] if len(named) == 1 else ", ".join(named[:-1]) + f" and {named[-1]}"

    conf = ("Corroborated across independent detection methods, so a false positive "
            "is unlikely."
            if len(families) > 1 else
            f"All of this came from {agree} alone, so it is one line of evidence "
            f"observed several ways rather than independent corroboration; treat it "
            f"as a lead.")

    if inc.score >= 95:
        act = f"Contain {inc.entity} now and preserve its memory before it exits."
    elif inc.score >= 80:
        act = f"Freeze {inc.entity} with SIGSTOP and inspect its open files and sockets."
    elif inc.score >= 60:
        act = f"Check the parent process and binary path for {inc.entity} against a known-good host."
    else:
        act = "Watch for a repeat within the hour; close the alert if nothing recurs."

    detail = ""
    if top and top.evidence:
        keys = [k for k in ("cmdline", "name", "path", "raddr", "metric", "z_score")
                if k in top.evidence]
        if keys:
            detail = " Key evidence: " + ", ".join(f"{k}={top.evidence[k]}" for k in keys[:3]) + "."

    return (f"{stage} activity on {inc.entity}, scored {inc.score:.0f}/100 from "
            f"{len(rules)} rule{'s' if len(rules) != 1 else ''} "
            f"({', '.join(rules[:4])}).{detail} {conf} {act}")


def _payload(inc: Incident) -> dict:
    return {
        "incident_id": inc.id,
        "entity": inc.entity,
        "score": round(inc.score, 1),
        "kill_chain_stage": stage_for(inc.mitre)[0],
        "mitre_techniques": inc.mitre,
        "detections": [
            {"rule": d.rule_id, "title": d.title, "source": d.source,
             "score": d.score, "confidence": d.confidence, "evidence": d.evidence}
            for d in inc.detections[-8:]
        ],
    }


class Triage:
    def __init__(self, enabled: bool = True, min_score: float = 65.0,
                 api_key: str | None = None, timeout: float = 20.0):
        self.enabled = enabled
        self.min_score = min_score
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.timeout = timeout
        self.calls = 0
        self.failures = 0
        self._lock = threading.Lock()

    @property
    def live(self) -> bool:
        return bool(self.enabled and self.api_key)

    def _ask_model(self, inc: Incident) -> str | None:
        body = json.dumps({
            "model": MODEL, "max_tokens": 400, "system": SYSTEM,
            "messages": [{"role": "user",
                          "content": "Triage this incident:\n"
                                     + json.dumps(_payload(inc), indent=2, default=str)}],
        }).encode()
        req = urllib.request.Request(API_URL, data=body, method="POST", headers={
            "content-type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
            parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
            text = "\n".join(p for p in parts if p).strip()
            return text or None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError):
            return None

    def summarise(self, inc: Incident) -> str:
        """Blocking. Callers should run this off the hot detection path."""
        if inc.score < self.min_score:
            return inc.narrative
        if self.live:
            with self._lock:
                self.calls += 1
            text = self._ask_model(inc)
            if text:
                return text
            with self._lock:
                self.failures += 1
        return _fallback(inc)

    def status(self) -> dict:
        return {"enabled": self.enabled, "model_backed": self.live, "model": MODEL if self.live else None,
                "mode": "model" if self.live else "deterministic fallback",
                "min_score": self.min_score, "calls": self.calls, "failures": self.failures}
