"""Correlation layer: turn a stream of detections into a small number of incidents.

A single alert is noise. The same entity tripping three different detectors
inside a short window is a story. This module groups detections by entity and
time, then scores the group superlinearly when independent detector families
(rule / baseline / ml) agree - independent corroboration is what separates a
real intrusion from a flaky heuristic.
"""

from __future__ import annotations

import time

from ..models import Detection, Incident

# Where each technique sits in an intrusion. Used to order the narrative and to
# reward incidents that span multiple stages, which is what a real attack does.
KILL_CHAIN = {
    "T1059": ("Execution", 2), "T1204": ("Execution", 2),
    "T1055": ("Defense evasion", 4), "T1027": ("Defense evasion", 4),
    "T1070": ("Defense evasion", 4), "T1562": ("Defense evasion", 4),
    "T1548": ("Privilege escalation", 3), "T1068": ("Privilege escalation", 3),
    "T1543": ("Persistence", 5), "T1053": ("Persistence", 5),
    "T1547": ("Persistence", 5), "T1136": ("Persistence", 5),
    "T1071": ("Command and control", 6), "T1571": ("Command and control", 6),
    "T1105": ("Command and control", 6),
    "T1041": ("Exfiltration", 7), "T1048": ("Exfiltration", 7),
    "T1486": ("Impact", 8), "T1496": ("Impact", 8), "T1499": ("Impact", 8),
    "T1057": ("Discovery", 1), "T1082": ("Discovery", 1), "T1083": ("Discovery", 1),
    "T1046": ("Discovery", 1), "T1518": ("Discovery", 1),
}


def stage_for(mitre: list[str]) -> tuple[str, int]:
    best = ("Reconnaissance", 0)
    for t in mitre:
        s = KILL_CHAIN.get(t)
        if s and s[1] > best[1]:
            best = s
    return best


class Correlator:
    def __init__(self, window_s: float = 180.0, max_open: int = 60):
        self.window_s = window_s
        self.max_open = max_open
        self.incidents: dict[str, Incident] = {}     # keyed by correlation key

    @staticmethod
    def _key(det: Detection) -> str:
        # Host-wide signals share one key; per-entity signals get their own.
        if det.entity in ("host", "", None):
            return "host"
        return f"{det.category}:{det.entity}"

    def ingest(self, detections: list[Detection]) -> list[Incident]:
        touched: dict[str, Incident] = {}
        now = time.time()

        for det in detections:
            key = self._key(det)
            inc = self.incidents.get(key)
            if inc is None or (now - inc.updated_ts) > self.window_s:
                inc = Incident(title=det.title, entity=det.entity, score=0.0)
                self.incidents[key] = inc
            inc.detections.append(det)
            inc.updated_ts = now
            for m in det.mitre:
                if m not in inc.mitre:
                    inc.mitre.append(m)
            touched[key] = inc

        for inc in touched.values():
            self._rescore(inc)

        self._evict()
        return list(touched.values())

    def _rescore(self, inc: Incident) -> None:
        dets = inc.detections[-40:]
        inc.detections = dets
        if not dets:
            return

        # Base: strongest single signal, weighted by its own confidence.
        base = max(d.score * (0.6 + 0.4 * d.confidence) for d in dets)

        # Corroboration: separate detector families agreeing is strong evidence.
        # With six families now (rule, baseline, ml, semantic, sequence,
        # correlation) the multiplier is capped rather than extended - past
        # three independent witnesses the marginal evidence is small, and
        # letting it grow would push every multi-family incident to 100 and
        # flatten the distinction between serious and very serious.
        families = {d.source for d in dets}
        corroboration = min(1.45, {1: 1.0, 2: 1.18, 3: 1.34}.get(len(families), 1.45))

        # Breadth: distinct rules firing, with diminishing returns. Six metrics
        # from the same baseline tracker spiking together is one event observed
        # six ways, not six confirmations, so single-family breadth is discounted.
        distinct = len({d.rule_id for d in dets})
        breadth = 1.0 + min(0.30, 0.06 * (distinct - 1)) * (0.4 if len(families) == 1 else 1.0)

        # Kill-chain progression: signals from multiple stages beat repetition.
        stages = {stage_for(d.mitre)[0] for d in dets if d.mitre}
        progression = 1.0 + min(0.25, 0.09 * max(0, len(stages) - 1))

        inc.score = min(100.0, base * corroboration * breadth * progression)
        top = max(dets, key=lambda d: d.score)
        stage, _ = stage_for(inc.mitre)
        if distinct == 1:
            inc.title = top.title
        elif len(families) > 1:
            inc.title = (f"{stage}: {len(families)} independent detector families "
                         f"agree on {inc.entity}")
        else:
            inc.title = f"{stage}: {distinct} correlated signals on {inc.entity}"

    def _evict(self) -> None:
        if len(self.incidents) <= self.max_open:
            return
        ordered = sorted(self.incidents.items(), key=lambda kv: kv[1].updated_ts)
        for key, _ in ordered[: len(self.incidents) - self.max_open]:
            self.incidents.pop(key, None)

    def open_incidents(self) -> list[Incident]:
        return sorted(self.incidents.values(), key=lambda i: i.score, reverse=True)
