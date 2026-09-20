"""Layer 2b: the trained classifier at runtime.

This is the student, in production. It loads the JSON artefact the trainer
produced and scores live command lines with a dot product and a softmax - no
sklearn at inference, no API calls, microseconds per command. It is what the
whole distillation pipeline exists to produce: the teacher's judgement, made
cheap and local and repeatable.

It runs alongside the similarity detector rather than replacing it, and the two
answer different questions. Similarity asks "how close is this to a specific
known attack and how unlike this host's normal". The classifier asks "which of
benign / suspicious / malicious does this command's whole feature profile look
like". They agree often and disagree usefully - a command the classifier calls
malicious that resembles nothing in the exemplar set is exactly the novel-but-
learnable case distillation was supposed to catch.

Reloadable. The console can retrain and this picks up the new model on its next
check without a restart, so the learning loop closes at runtime.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time

from ..models import Detection
from .features import FEATURE_NAMES, extract_features


def _softmax(xs: list[float]) -> list[float]:
    m = max(xs)
    exps = [math.exp(x - m) for x in xs]
    total = sum(exps) or 1.0
    return [e / total for e in exps]


class TrainedClassifier:
    def __init__(self, enabled: bool = True, model_path: str = "data/models/classifier.json",
                 fire_threshold: float = 0.6, suspicious_threshold: float = 0.55):
        self.enabled = enabled
        self.model_path = model_path
        self.fire_threshold = fire_threshold
        self.suspicious_threshold = suspicious_threshold
        self._lock = threading.Lock()
        self._model: dict | None = None
        self._mtime = 0.0
        self.families: list[str] = []
        self.scored = 0
        self.fired = 0
        self.last_load_error = ""
        if enabled:
            self.reload()

    # -- model loading ------------------------------------------------------

    def reload(self) -> bool:
        """Load or hot-reload the artefact. Returns True if a model is live."""
        try:
            mtime = os.path.getmtime(self.model_path)
        except OSError:
            self.last_load_error = "no model file yet - run training"
            return False
        if self._model is not None and mtime <= self._mtime:
            return True
        try:
            with open(self.model_path) as fh:
                artefact = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            self.last_load_error = f"{type(exc).__name__}"
            return False
        # Feature-order guard: a model trained against a different feature
        # schema must not be used, or every score is quietly wrong.
        if artefact.get("feature_order") != FEATURE_NAMES:
            self.last_load_error = "feature schema mismatch - retrain required"
            return False
        with self._lock:
            self._model = artefact
            self._mtime = mtime
            self.families = artefact["family_order"]
            self.last_load_error = ""
        return True

    @property
    def ready(self) -> bool:
        return self._model is not None

    @property
    def trained_at(self) -> float:
        return self._model.get("trained_at", 0.0) if self._model else 0.0

    # -- inference ----------------------------------------------------------

    def predict(self, command: str) -> dict | None:
        if not self.ready:
            return None
        with self._lock:
            model = self._model
        raw = extract_features(command)
        mean, scale = model["scaler_mean"], model["scaler_scale"]
        x = [(raw[i] - mean[i]) / (scale[i] or 1.0) for i in range(len(raw))]

        logits = []
        for c, coef_row in enumerate(model["coef"]):
            z = model["intercept"][c] + sum(x[i] * coef_row[i] for i in range(len(x)))
            logits.append(z)
        probs = _softmax(logits)
        fam_probs = {self.families[i]: round(probs[i], 4) for i in range(len(self.families))}
        top_idx = max(range(len(probs)), key=lambda i: probs[i])

        # Explanation from the SCALED contribution: coefficient times the
        # standardised feature value, which is what actually entered the logit.
        # Using the raw feature here would make `length` explain everything.
        mal_idx = self.families.index("malicious") if "malicious" in self.families else 0
        coef_row = model["coef"][mal_idx]
        contrib = sorted(
            ((FEATURE_NAMES[i], x[i] * coef_row[i]) for i in range(len(x))),
            key=lambda kv: kv[1], reverse=True)
        drivers = [(n, round(v, 3)) for n, v in contrib[:4] if v > 0.05]

        return {"family": self.families[top_idx],
                "probabilities": fam_probs,
                "confidence": round(probs[top_idx], 4),
                "p_malicious": fam_probs.get("malicious", 0.0),
                "p_suspicious": fam_probs.get("suspicious", 0.0),
                "drivers": drivers}

    def evaluate(self, entity: str, command: str, extra: dict | None = None) -> Detection | None:
        if not self.ready or not command or len(command) < 6:
            return None
        # cheap staleness check, at most once a second
        if time.time() - self._mtime > 2:
            self.reload()
        pred = self.predict(command)
        if pred is None:
            return None
        self.scored += 1

        p_mal, p_susp = pred["p_malicious"], pred["p_suspicious"]
        combined = p_mal + 0.4 * p_susp
        if pred["family"] == "benign" or combined < self.suspicious_threshold:
            return None

        malicious = p_mal >= self.fire_threshold
        self.fired += 1
        score = min(90.0, 30.0 + 65.0 * p_mal + 25.0 * p_susp)
        conf = min(0.85, 0.4 + 0.5 * pred["confidence"])

        drivers = ", ".join(f"{name}" for name, _ in pred["drivers"]) or "profile"
        return Detection(
            rule_id="CLF-MALICIOUS" if malicious else "CLF-SUSPICIOUS",
            title=("Command classified as attacker tradecraft"
                   if malicious else "Command classified as suspicious"),
            score=round(score, 1), confidence=round(conf, 2), source="classifier",
            entity=entity, category="process", mitre=[],
            evidence={
                **(extra or {}),
                "command": command[:400],
                "classification": pred["family"],
                "probabilities": pred["probabilities"],
                "decided_by": drivers,
                "model_trained_at": self.trained_at,
            },
            remediation=(
                "This was not matched by a written rule or a stored exemplar; a model "
                "trained on labelled attack and benign command lines classified it by its "
                "overall feature profile. The features that drove the decision are listed as "
                "'decided_by'. Read the command against those - if it is legitimate work that "
                "happens to share that profile, it is a candidate for the next training round."),
        )

    def status(self) -> dict:
        m = self._model
        return {
            "enabled": self.enabled,
            "ready": self.ready,
            "model_path": self.model_path,
            "trained_at": self.trained_at or None,
            "corpus_size": m.get("corpus_size") if m else None,
            "families": self.families,
            "accuracy": m["metrics"]["accuracy"] if m else None,
            "macro_f1": m["metrics"]["macro_f1"] if m else None,
            "hard_case_accuracy": m["metrics"].get("hard_case_accuracy") if m else None,
            "scored": self.scored,
            "fired": self.fired,
            "fire_threshold": self.fire_threshold,
            "load_error": self.last_load_error or None,
        }
