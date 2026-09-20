"""Configuration. YAML file on disk, overridable per-field by environment."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml


@dataclass
class Config:
    # collection cadence (seconds)
    process_interval: float = 1.0
    network_interval: float = 3.0
    fim_interval: float = 30.0
    resource_interval: float = 2.0

    # collection scope
    deep_scan_top_n: int = 25
    fim_max_files: int = 400
    watch_paths: list[str] = field(default_factory=lambda: [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
        "/etc/crontab", "~/.ssh", "~/.bashrc", "~/.profile", "data/sandbox",
    ])

    # detection tuning
    rules_file: str = "rules/rules.yaml"
    baseline_warmup: int = 25
    z_threshold: float = 3.5
    contamination: float = 0.02
    correlation_window_s: float = 180.0
    suppress_window_s: float = 60.0

    # similarity layer (layer 2)
    semantic: bool = True
    semantic_encoder: str = "auto"        # auto | transformer | hashed
    semantic_threshold: float = 0.62
    semantic_margin: float = 0.10

    # trained classifier (distilled model, layer 2b)
    classifier: bool = True
    classifier_model_path: str = "data/models/classifier.json"
    classifier_corpus_path: str = "data/models/corpus.jsonl"
    classifier_fire_threshold: float = 0.6
    classifier_train_on_start: bool = True   # build corpus + train if no model exists

    # sequence layer (layer 3)
    sequence: bool = True
    sequence_window_s: float = 600.0
    sequence_surprise_bits: float = 4.5
    sequence_markov_warmup: int = 40

    # llm adjudication (layer 4)
    llm_judge: bool = True
    llm_backend: str = "anthropic"        # anthropic | local
    llm_model: str = "claude-sonnet-4-6"
    llm_local_url: str = "http://127.0.0.1:11434/v1"
    llm_band_low: float = 45.0
    llm_band_high: float = 88.0
    llm_max_shift: float = 20.0
    llm_calls_per_hour: int = 60

    # response policy
    dry_run: bool = True
    suspend_at: float = 80.0
    terminate_at: float = 95.0
    quarantine_dir: str = "data/quarantine"
    protected_processes: list[str] = field(default_factory=list)

    # ai triage
    ai_triage: bool = True
    triage_min_score: float = 65.0

    # conversational assistant
    assistant: bool = True
    assistant_model: str = "claude-sonnet-4-6"
    assistant_max_tool_hops: int = 5
    assistant_history_turns: int = 12

    # runtime
    database: str = "data/osentinel.db"
    queue_size: int = 5000
    retention_s: float = 86400.0
    host: str = "127.0.0.1"
    port: int = 8787

    @classmethod
    def load(cls, path: str = "config.yaml") -> "Config":
        raw: dict = {}
        p = Path(path)
        if p.exists():
            raw = yaml.safe_load(p.read_text()) or {}

        known = {f.name: f for f in fields(cls)}
        kwargs = {k: v for k, v in raw.items() if k in known}

        # environment wins, so a container can be tuned without a config file
        for name, f in known.items():
            env = os.environ.get(f"OSENTINEL_{name.upper()}")
            if env is None:
                continue
            if f.type in ("float", float):
                kwargs[name] = float(env)
            elif f.type in ("int", int):
                kwargs[name] = int(env)
            elif f.type in ("bool", bool):
                kwargs[name] = env.strip().lower() in ("1", "true", "yes", "on")
            else:
                kwargs[name] = env
        return cls(**kwargs)
