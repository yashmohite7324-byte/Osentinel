"""Behavioural layer: learn what this machine normally does, flag what it doesn't.

Two independent detectors:

  BaselineTracker  - per-metric exponentially weighted mean and variance.
                     Cheap, online, no training phase, catches host-wide shifts.
  ProcessAnomalyModel - IsolationForest over per-process feature vectors.
                     Catches processes whose *shape* is unlike anything else
                     running, which signature rules cannot express.
"""

from __future__ import annotations

import math
import time

import numpy as np

from ..models import Detection

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN = True
except ImportError:                                    # graceful degradation
    SKLEARN = False


class EWMA:
    """Exponentially weighted mean/variance - O(1) memory per metric."""

    def __init__(self, alpha: float = 0.05):
        self.alpha = alpha
        self.mean: float | None = None
        self.var = 0.0
        self.n = 0

    def update(self, x: float) -> float:
        self.n += 1
        if self.mean is None:
            self.mean = x
            return 0.0
        delta = x - self.mean
        self.mean += self.alpha * delta
        self.var = (1 - self.alpha) * (self.var + self.alpha * delta * delta)
        return self.z(x)

    def z(self, x: float) -> float:
        sd = math.sqrt(self.var)
        if self.mean is None or sd < 1e-9:
            return 0.0
        return (x - self.mean) / sd


class BaselineTracker:
    """Host-level metric drift detection."""

    WATCHED = {
        "cpu_percent": ("CPU saturation outside the learned envelope", 45, "T1496"),
        "mem_percent": ("Memory pressure outside the learned envelope", 45, "T1496"),
        "ctx_switches_per_s": ("Context-switch storm", 55, "T1499"),
        "process_count": ("Unusual growth in the process table", 60, "T1055"),
        "tx_bps": ("Outbound throughput far above normal", 70, "T1041"),
        "rx_bps": ("Inbound throughput far above normal", 50, "T1105"),
        "load1": ("Run-queue depth outside the learned envelope", 40, "T1496"),
    }

    def __init__(self, warmup: int = 25, z_threshold: float = 3.5):
        self.trackers: dict[str, EWMA] = {}
        self.warmup = warmup
        self.z_threshold = z_threshold

    def update(self, sample: dict[str, float]) -> list[Detection]:
        dets: list[Detection] = []
        for name, value in sample.items():
            t = self.trackers.setdefault(name, EWMA())
            z = t.update(float(value))
            if name not in self.WATCHED or t.n < self.warmup:
                continue
            if z > self.z_threshold:
                title, base, mitre = self.WATCHED[name]
                # score grows with how far past the threshold we are, capped
                score = min(95.0, base + (z - self.z_threshold) * 6)
                dets.append(Detection(
                    rule_id=f"BASE-{name.upper()}", title=title, score=score,
                    confidence=min(0.95, 0.45 + z / 20), source="baseline",
                    entity="host", category="resource", mitre=[mitre],
                    evidence={"metric": name, "value": round(float(value), 2),
                              "learned_mean": round(t.mean or 0, 2),
                              "std_dev": round(math.sqrt(t.var), 2),
                              "z_score": round(z, 2), "samples_learned": t.n},
                    remediation="Identify the top consumer for this metric and confirm "
                                "the workload is expected."))
        return dets

    def envelope(self) -> dict[str, dict]:
        return {k: {"mean": round(v.mean or 0, 2), "sd": round(math.sqrt(v.var), 2), "n": v.n}
                for k, v in self.trackers.items() if k in self.WATCHED}


FEATURES = ["cpu", "rss_mb", "threads", "fds", "conns", "cmd_len", "cmd_entropy",
            "age_min", "is_root", "depth_hint"]


def process_features(p: dict, now: float | None = None) -> list[float]:
    now = now or time.time()
    cmd = p.get("cmdline") or p.get("name") or ""
    from .rules import shannon_entropy
    return [
        float(p.get("cpu", 0.0)),
        float(p.get("rss", 0)) / 1_048_576.0,
        float(p.get("threads", 0)),
        float(p.get("fds", 0)),
        float(p.get("conns", 0)),
        float(len(cmd)),
        shannon_entropy(cmd),
        max(0.0, (now - float(p.get("started", now))) / 60.0),
        1.0 if p.get("euid", -1) == 0 else 0.0,
        float(min(p.get("ppid", 0), 5000)) / 5000.0,
    ]


class ProcessAnomalyModel:
    """Unsupervised outlier detection over the live process table.

    The model retrains periodically on a rolling window of observations, so it
    tracks what "normal" means on *this* host rather than a generic baseline.
    """

    def __init__(self, window: int = 4000, retrain_every: int = 300,
                 min_samples: int = 400, contamination: float = 0.02):
        self.window = window
        self.retrain_every = retrain_every
        self.min_samples = min_samples
        self.contamination = contamination
        self.buffer: list[list[float]] = []
        self.model = None
        self.since_train = 0
        self.trained_at: float | None = None
        self.train_count = 0
        self.threshold = -0.15

    @property
    def ready(self) -> bool:
        return SKLEARN and self.model is not None

    def observe(self, processes: list[dict]) -> None:
        now = time.time()
        for p in processes:
            self.buffer.append(process_features(p, now))
        if len(self.buffer) > self.window:
            self.buffer = self.buffer[-self.window:]
        self.since_train += len(processes)
        if SKLEARN and len(self.buffer) >= self.min_samples and \
                (self.model is None or self.since_train >= self.retrain_every):
            self._fit()

    def _fit(self) -> None:
        X = np.asarray(self.buffer, dtype=float)
        self.model = IsolationForest(
            n_estimators=150, contamination=self.contamination,
            random_state=42, n_jobs=1).fit(X)
        self.since_train = 0
        self.trained_at = time.time()
        self.train_count += 1

    def score(self, processes: list[dict]) -> list[Detection]:
        if not self.ready or not processes:
            return []
        now = time.time()
        X = np.asarray([process_features(p, now) for p in processes], dtype=float)
        scores = self.model.decision_function(X)      # lower = more anomalous
        dets: list[Detection] = []
        for p, s in zip(processes, scores):
            if s >= self.threshold:
                continue
            severity = min(90.0, 35.0 + (self.threshold - float(s)) * 220)
            feats = dict(zip(FEATURES, [round(v, 3) for v in process_features(p, now)]))
            dets.append(Detection(
                rule_id="ML-ISOFOREST",
                title=f"Process '{p.get('name')}' does not fit the learned host profile",
                score=severity, confidence=min(0.9, 0.4 + (self.threshold - float(s))),
                source="ml", entity=str(p.get("pid")), category="process",
                mitre=["T1057"],
                evidence={"pid": p.get("pid"), "name": p.get("name"),
                          "cmdline": (p.get("cmdline") or "")[:200],
                          "user": p.get("user"),
                          "anomaly_score": round(float(s), 4),
                          "decision_threshold": self.threshold,
                          "features": feats,
                          "trained_on_samples": len(self.buffer)},
                remediation="Compare this process against a known-good host. Verify the "
                            "binary path and its parent before allowing it to continue."))
        return dets

    def status(self) -> dict:
        return {"available": SKLEARN, "trained": self.ready,
                "samples": len(self.buffer), "retrains": self.train_count,
                "trained_at": self.trained_at, "features": FEATURES}
