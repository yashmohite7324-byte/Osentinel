"""Training the student model.

Reads the corpus, extracts features through the shared extractor, fits a
calibrated linear classifier, and reports honest held-out metrics. The model is
deliberately simple - logistic regression over interpretable features - for
three reasons that all matter more than squeezing out another point of accuracy:

  explainable   a linear model's decision is a weighted sum of named features,
                so the runtime detector can tell an analyst *why* it fired.

  fast          inference is a dot product; thousands per second on one core,
                which is what running in the event path at line rate requires.

  auditable     the entire model is a coefficient per feature. You can read it,
                diff two versions, and see exactly what the teacher taught.

The output is a small JSON file - coefficients, intercepts, feature order,
calibration and metrics - not a pickle. JSON because it loads without importing
the trainer, survives library upgrades, and can be inspected by a human or
checked into version control as the artefact it is.
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .corpus import FAMILIES
from .features import FEATURE_NAMES, N_FEATURES, extract_features


@dataclass
class TrainReport:
    trained_at: float = 0.0
    samples: int = 0
    train_n: int = 0
    test_n: int = 0
    accuracy: float = 0.0
    macro_f1: float = 0.0
    per_class: dict = field(default_factory=dict)
    confusion: list = field(default_factory=list)
    hard_case_accuracy: float = 0.0
    top_features: dict = field(default_factory=dict)
    model_path: str = ""

    def summary(self) -> str:
        return (f"{self.samples} samples -> accuracy {self.accuracy:.3f}, "
                f"macro-F1 {self.macro_f1:.3f}, hard-case accuracy "
                f"{self.hard_case_accuracy:.3f}")


def load_corpus(path: str) -> list[dict]:
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows


def _metrics(y_true: list[int], y_pred: list[int], labels: list[int]) -> dict:
    """Per-class precision/recall/F1 and a confusion matrix, without sklearn's
    reporting - so the numbers are computed here and cannot be misread."""
    n = len(labels)
    conf = [[0] * n for _ in range(n)]
    for t, p in zip(y_true, y_pred):
        conf[t][p] += 1
    per_class = {}
    f1s = []
    for i, lab in enumerate(labels):
        tp = conf[i][i]
        fp = sum(conf[j][i] for j in range(n)) - tp
        fn = sum(conf[i]) - tp
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per_class[FAMILIES[lab]] = {"precision": round(prec, 3), "recall": round(rec, 3),
                                    "f1": round(f1, 3), "support": sum(conf[i])}
        f1s.append(f1)
    acc = sum(conf[i][i] for i in range(n)) / max(sum(sum(r) for r in conf), 1)
    return {"accuracy": round(acc, 4), "macro_f1": round(sum(f1s) / len(f1s), 4),
            "per_class": per_class, "confusion": conf}


def train(corpus_path: str, model_path: str, test_frac: float = 0.2,
          seed: int = 7, progress=None) -> TrainReport:
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    rows = load_corpus(corpus_path)
    if len(rows) < 30:
        raise ValueError(f"corpus too small to train: {len(rows)} samples")

    fam_to_idx = {f: i for i, f in enumerate(FAMILIES)}
    X = np.array([extract_features(r["command"]) for r in rows], dtype=float)
    y = np.array([fam_to_idx[r["family"]] for r in rows], dtype=int)
    difficulties = [r.get("difficulty", "medium") for r in rows]

    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(rows))
    cut = int(len(rows) * (1 - test_frac))
    tr, te = idx[:cut], idx[cut:]
    if progress:
        progress(f"loaded {len(rows)} samples, {N_FEATURES} features, "
                 f"{len(tr)} train / {len(te)} test")

    scaler = StandardScaler().fit(X[tr])
    Xtr, Xte = scaler.transform(X[tr]), scaler.transform(X[te])

    # Balanced class weight because even a balanced corpus skews once dedupe
    # removes the easy repeated malicious shapes faster than the varied benign.
    # multinomial is the default and only mode in sklearn >=1.7; the old
    # multi_class kwarg was removed, so it is not passed.
    clf = LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced")
    clf.fit(Xtr, y[tr])

    y_pred = clf.predict(Xte).tolist()
    labels = list(range(len(FAMILIES)))
    m = _metrics(y[te].tolist(), y_pred, labels)

    # Accuracy specifically on the hard cases - the look-alikes. This is the
    # number that says whether distillation actually bought anything over the
    # exemplar list, which handled only the easy cases.
    hard_mask = [difficulties[i] == "hard" for i in te]
    hard_true = [int(y[te][k]) for k in range(len(te)) if hard_mask[k]]
    hard_pred = [y_pred[k] for k in range(len(te)) if hard_mask[k]]
    hard_acc = (sum(t == p for t, p in zip(hard_true, hard_pred)) / len(hard_true)
                if hard_true else 0.0)

    # Which features push toward "malicious", read straight off the coefficients.
    mal = fam_to_idx["malicious"]
    coefs = clf.coef_[mal]
    order = sorted(range(N_FEATURES), key=lambda i: coefs[i], reverse=True)
    top_features = {FEATURE_NAMES[i]: round(float(coefs[i]), 3) for i in order[:8]}

    artefact = {
        "version": 2,
        "trained_at": time.time(),
        "family_order": FAMILIES,
        "feature_order": FEATURE_NAMES,
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": scaler.scale_.tolist(),
        "coef": clf.coef_.tolist(),
        "intercept": clf.intercept_.tolist(),
        "metrics": {**m, "hard_case_accuracy": round(hard_acc, 4)},
        "corpus_size": len(rows),
    }
    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    # Write-then-rename so a detector reloading concurrently never reads a
    # partially written file: rename is atomic on POSIX, open-for-write is not.
    tmp = str(model_path) + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(artefact, fh, indent=1)
    os.replace(tmp, model_path)

    rep = TrainReport(
        trained_at=artefact["trained_at"], samples=len(rows), train_n=len(tr),
        test_n=len(te), accuracy=m["accuracy"], macro_f1=m["macro_f1"],
        per_class=m["per_class"], confusion=m["confusion"],
        hard_case_accuracy=round(hard_acc, 4), top_features=top_features,
        model_path=model_path)
    if progress:
        progress(rep.summary())
    return rep


if __name__ == "__main__":      # python -m osentinel.learn.trainer [corpus] [model]
    import sys
    corpus = sys.argv[1] if len(sys.argv) > 1 else "data/models/corpus.jsonl"
    model = sys.argv[2] if len(sys.argv) > 2 else "data/models/classifier.json"
    r = train(corpus, model, progress=lambda m: print("  ", m))
    print("\n" + r.summary())
    print("per-class:", json.dumps(r.per_class, indent=1))
    print("top malicious features:", json.dumps(r.top_features, indent=1))
