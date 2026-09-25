"""The engine: a bounded producer/consumer pipeline.

    collector threads ──push──▶ bounded Queue ──pop──▶ analysis thread
                                    │                        │
                              drops on overflow        detections ─▶ correlator
                                                                       │
                                                          responder ◀──┤
                                                          triage    ◀──┘

Collectors are producers on independent timers. One analysis thread is the sole
consumer, which means the rule engine, the baseline tracker and the correlator
all run single-threaded and need no locking of their own - the queue is the
synchronisation boundary. The queue is bounded on purpose: under a telemetry
flood we shed load and count the drops rather than growing memory without limit
until the OOM killer settles the argument for us.

Triage runs on a separate worker so a slow network call can never stall
detection.
"""

from __future__ import annotations

import queue
import threading
import time
from collections import deque
from typing import Callable

from .ai_triage import Triage
from .assistant import SecurityAssistant
from .collectors import (FileIntegrityCollector, NetworkCollector, ProcessCollector,
                         ResourceCollector, SystemMonitorCollector, host_identity)
from .config import Config
from .detect.anomaly import BaselineTracker, ProcessAnomalyModel
from .detect.correlator import Correlator
from .detect.responder import Responder
from .detect.llm_judge import LLMAdjudicator
from .detect.rules import RuleEngine
from .detect.semantic import SimilarityDetector
from .learn.classifier import TrainedClassifier
from .detect.sequence import SequenceDetector
from .models import Detection, Event, Incident
from .store import Store


class PeriodicTask(threading.Thread):
    """A daemon thread that runs fn() every `interval` seconds without drift."""

    def __init__(self, name: str, fn: Callable[[], None], interval: float,
                 stop_event: threading.Event):
        super().__init__(name=name, daemon=True)
        self.fn = fn
        self.interval = interval
        self.stop_event = stop_event
        self.runs = 0
        self.errors = 0
        self.last_duration = 0.0
        self.last_error = ""

    def run(self) -> None:
        next_at = time.monotonic()
        while not self.stop_event.is_set():
            start = time.monotonic()
            try:
                self.fn()
                self.runs += 1
            except Exception as exc:                     # a bad collector must not kill the agent
                self.errors += 1
                self.last_error = f"{type(exc).__name__}: {exc}"
            self.last_duration = time.monotonic() - start
            next_at += self.interval
            sleep_for = max(0.0, next_at - time.monotonic())
            if sleep_for == 0.0:                          # we fell behind; resync
                next_at = time.monotonic()
            self.stop_event.wait(sleep_for)

    def status(self) -> dict:
        return {"name": self.name, "interval_s": self.interval, "runs": self.runs,
                "errors": self.errors, "last_ms": round(self.last_duration * 1000, 1),
                "last_error": self.last_error}


class Engine:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.store = Store(cfg.database)
        self.started_at = time.time()

        self.procs = ProcessCollector(cfg.deep_scan_top_n)
        self.net = NetworkCollector()
        self.files = FileIntegrityCollector(cfg.watch_paths, self.store, cfg.fim_max_files)
        self.res = ResourceCollector()

        self.rules = RuleEngine(cfg.rules_file)
        self.baseline = BaselineTracker(cfg.baseline_warmup, cfg.z_threshold)
        self.ml = ProcessAnomalyModel(contamination=cfg.contamination)
        self.semantic = SimilarityDetector(
            cfg.semantic, cfg.semantic_encoder,
            cfg.semantic_threshold, cfg.semantic_margin)
        self.classifier = TrainedClassifier(
            cfg.classifier, cfg.classifier_model_path,
            cfg.classifier_fire_threshold)
        self.sequence = SequenceDetector(
            cfg.sequence, cfg.sequence_window_s,
            cfg.sequence_surprise_bits, markov_warmup=cfg.sequence_markov_warmup)
        self.correlator = Correlator(cfg.correlation_window_s)
        self.responder = Responder(cfg.dry_run, cfg.suspend_at, cfg.terminate_at,
                                   cfg.quarantine_dir, set(cfg.protected_processes))
        self.triage = Triage(cfg.ai_triage, cfg.triage_min_score)
        self.judge = LLMAdjudicator(
            self, cfg.llm_judge, cfg.llm_backend, cfg.llm_model, cfg.llm_local_url,
            band=(cfg.llm_band_low, cfg.llm_band_high), max_shift=cfg.llm_max_shift,
            calls_per_hour=cfg.llm_calls_per_hour)
        # The assistant reads the engine, so it is built last and holds a
        # back-reference. Nothing in the detection path calls into it.
        self.assistant = SecurityAssistant(
            self, enabled=cfg.assistant, backend=cfg.llm_backend,
            model=cfg.assistant_model, local_url=cfg.llm_local_url,
            max_tool_hops=cfg.assistant_max_tool_hops,
            history_turns=cfg.assistant_history_turns)

        self.queue: queue.Queue[Event] = queue.Queue(maxsize=cfg.queue_size)
        self.triage_queue: queue.Queue[Incident] = queue.Queue(maxsize=64)
        self.dropped = 0
        self.processed = 0
        self._alert_seen: dict[tuple[str, str], tuple[float, int]] = {}

        self._lock = threading.RLock()
        self.recent_events: deque[dict] = deque(maxlen=400)
        self.recent_detections: deque[dict] = deque(maxlen=300)
        self.metrics_history: deque[dict] = deque(maxlen=360)
        self.latest_metrics: dict[str, float] = {}
        self.beacons: list[dict] = []
        self.subscribers: list[queue.Queue] = []

        self.stop_event = threading.Event()
        self.tasks: list[PeriodicTask] = []
        self.identity = host_identity()

    # ------------------------------------------------------------ plumbing

    def _emit(self, events: list[Event]) -> None:
        for e in events:
            try:
                self.queue.put_nowait(e)
            except queue.Full:
                self.dropped += 1

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def _broadcast(self, message: dict) -> None:
        with self._lock:
            subs = list(self.subscribers)
        for q in subs:
            try:
                q.put_nowait(message)
            except queue.Full:
                pass                                      # slow client, drop the frame

    # ---------------------------------------------------------- collectors

    def _tick_process(self) -> None:
        self._emit(self.procs.poll())
        table = list(self.procs.snapshot.values())
        self.ml.observe(table)
        dets = self.ml.score(table)
        if dets:
            self._handle_detections(dets)

    def _tick_network(self) -> None:
        self._emit(self.net.poll())
        beacons = self.net.beacon_candidates()
        self.beacons = beacons
        for b in beacons:
            self._emit([Event(category="network", action="periodic_contact",
                              entity=b["raddr"], attrs=b)])

    def _tick_files(self) -> None:
        self._emit(self.files.poll())

    def _tick_resources(self) -> None:
        sample = self.res.sample()
        sample.update(self.net.rates)
        self.latest_metrics = sample
        row = {"ts": time.time(), **{k: round(v, 2) for k, v in sample.items()}}
        with self._lock:
            self.metrics_history.append(row)
        self.store.add_metrics(sample)
        dets = self.baseline.update(sample)
        if dets:
            self._handle_detections(dets)
        self._broadcast({"type": "metrics", "data": row})

    def _tick_maintenance(self) -> None:
        self.store.prune(self.cfg.retention_s)

    # ------------------------------------------------------------ analysis

    def _analysis_loop(self) -> None:
        batch: list[Event] = []
        while not self.stop_event.is_set():
            try:
                batch.append(self.queue.get(timeout=0.5))
            except queue.Empty:
                pass
            # drain whatever else is waiting so we analyse in batches
            while len(batch) < 200:
                try:
                    batch.append(self.queue.get_nowait())
                except queue.Empty:
                    break
            if not batch:
                continue

            self.processed += len(batch)
            self.store.add_events(batch)
            payload = [e.to_dict() for e in batch]
            with self._lock:
                self.recent_events.extend(payload)
            self._broadcast({"type": "events", "data": payload[-40:]})

            # Layer 1 signatures, then layer 2 similarity on anything that
            # carries a command line, then layer 3 over the ordering. All three
            # are cheap and synchronous; only layer 4 leaves this thread.
            dets = self.rules.run(batch)
            dets.extend(self._run_similarity(batch))
            dets.extend(self._run_classifier(batch))
            dets.extend(self.sequence.observe(batch))
            if dets:
                self._handle_detections(dets)
            batch = []

    def _run_classifier(self, batch: list[Event]) -> list[Detection]:
        if not self.classifier.ready:
            return []
        out: list[Detection] = []
        for e in batch:
            if e.category != "process" or e.action != "process_started":
                continue
            cmd = e.attrs.get("cmdline") or e.attrs.get("name")
            if not cmd:
                continue
            d = self.classifier.evaluate(
                e.entity, str(cmd),
                {k: e.attrs.get(k) for k in ("pid", "name", "user", "parent_name")
                 if k in e.attrs})
            if d:
                out.append(d)
        return out

    def train_classifier(self, use_llm: bool = True, progress=None) -> dict:
        """Build the corpus and train the student, then hot-reload it.

        This is the whole distillation pipeline behind one call: teacher writes
        and labels the corpus, trainer fits the student, the running detector
        picks up the new model without a restart.
        """
        from .learn.corpus import build_corpus
        from .learn.trainer import train
        rep = build_corpus(self.cfg.classifier_corpus_path, use_llm=use_llm,
                           progress=progress)
        tr = train(self.cfg.classifier_corpus_path, self.cfg.classifier_model_path,
                   progress=progress)
        self.classifier.reload()
        return {"corpus": {"total": rep.total, "by_family": rep.by_family,
                           "by_source": rep.by_source, "llm_batches": rep.llm_batches},
                "training": {"samples": tr.samples, "accuracy": tr.accuracy,
                             "macro_f1": tr.macro_f1,
                             "hard_case_accuracy": tr.hard_case_accuracy,
                             "per_class": tr.per_class, "top_features": tr.top_features}}

    def _run_similarity(self, batch: list[Event]) -> list[Detection]:
        if not self.semantic.ready:
            return []
        out: list[Detection] = []
        for e in batch:
            if e.category != "process" or e.action != "process_started":
                continue
            cmd = e.attrs.get("cmdline") or e.attrs.get("name")
            if not cmd:
                continue
            d = self.semantic.evaluate(
                e.entity, str(cmd),
                {k: e.attrs.get(k) for k in ("pid", "name", "user", "parent_name")
                 if k in e.attrs})
            if d:
                out.append(d)
        return out

    def _suppress(self, dets: list[Detection]) -> list[Detection]:
        """Collapse repeat firings of the same rule on the same entity.

        A rule that matches a long-lived condition will match on every cycle.
        Forwarding all of them buries the operator and starves the UI of the
        signals that matter, so we forward the first, then one every
        `suppress_window` seconds, and carry the suppressed count as evidence.
        """
        now = time.time()
        kept: list[Detection] = []
        for d in dets:
            key = (d.rule_id, d.entity)
            last, count = self._alert_seen.get(key, (0.0, 0))
            if now - last < self.cfg.suppress_window_s:
                self._alert_seen[key] = (last, count + 1)
                continue
            if count:
                d.evidence["suppressed_repeats"] = count
            self._alert_seen[key] = (now, 0)
            kept.append(d)
        if len(self._alert_seen) > 4000:                  # bound the bookkeeping
            cutoff = now - self.cfg.suppress_window_s * 10
            self._alert_seen = {k: v for k, v in self._alert_seen.items() if v[0] > cutoff}
        return kept

    def _handle_detections(self, dets: list[Detection]) -> None:
        dets = self._suppress(dets)
        if not dets:
            return
        self.store.add_detections(dets)
        payload = [d.to_dict() for d in dets]
        with self._lock:
            self.recent_detections.extend(payload)
        self._broadcast({"type": "detections", "data": payload})

        # Layer 4 runs after correlation so the model sees corroboration, and
        # off-thread so a slow or unreachable model cannot stall detection.
        for d in dets:
            self.judge.submit(d)

        for inc in self.correlator.ingest(dets):
            actions = self.responder.evaluate(inc)
            for act in actions:
                self._broadcast({"type": "action", "data": act.to_dict()})
            self.store.upsert_incident(inc)
            self._broadcast({"type": "incident", "data": inc.to_dict()})
            if inc.score >= self.cfg.triage_min_score and not inc.narrative:
                try:
                    self.triage_queue.put_nowait(inc)
                except queue.Full:
                    pass

    def _triage_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                inc = self.triage_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                inc.narrative = self.triage.summarise(inc)
                self.store.upsert_incident(inc)
                self._broadcast({"type": "incident", "data": inc.to_dict()})
            except Exception:
                continue

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        specs = [
            ("collector:process", self._tick_process, self.cfg.process_interval),
            ("collector:network", self._tick_network, self.cfg.network_interval),
            ("collector:filesystem", self._tick_files, self.cfg.fim_interval),
            ("collector:resource", self._tick_resources, self.cfg.resource_interval),
            ("maintenance", self._tick_maintenance, 300.0),
        ]
        for name, fn, interval in specs:
            t = PeriodicTask(name, fn, interval, self.stop_event)
            t.start()
            self.tasks.append(t)

        self.analysis_thread = threading.Thread(
            target=self._analysis_loop, name="analysis", daemon=True)
        self.analysis_thread.start()
        self.triage_thread = threading.Thread(
            target=self._triage_loop, name="triage", daemon=True)
        self.triage_thread.start()
        self.judge.start()
        if self.cfg.classifier_train_on_start and not self.classifier.ready:
            threading.Thread(target=self._bootstrap_classifier,
                            name="classifier-bootstrap", daemon=True).start()

    def _bootstrap_classifier(self) -> None:
        # No model on disk: build one from the synthetic corpus (no key needed)
        # so the layer is live on first run rather than dark until someone
        # trains manually. LLM enrichment is left for an explicit retrain.
        try:
            self.train_classifier(use_llm=False)
        except Exception:
            pass

    def stop(self) -> None:
        self.stop_event.set()
        self.judge.stop()
        for t in self.tasks:
            t.join(timeout=2)
        self.store.close()

    # --------------------------------------------------------------- views

    def posture(self) -> dict:
        """One number an operator can act on, plus what drives it."""
        incidents = self.correlator.open_incidents()
        top = incidents[0].score if incidents else 0.0
        active = [i for i in incidents if i.score >= 40]
        # risk climbs with the worst incident and, more slowly, with breadth
        risk = min(100.0, top + min(20.0, 3.0 * max(0, len(active) - 1)))
        return {
            "risk": round(risk, 1),
            "state": ("critical" if risk >= 85 else "elevated" if risk >= 60
                      else "watch" if risk >= 30 else "nominal"),
            "open_incidents": len(incidents),
            "actionable": len(active),
            "top_incident": incidents[0].to_dict() if incidents else None,
        }

    def status(self) -> dict:
        return {
            "host": self.identity,
            "uptime_s": round(time.time() - self.started_at, 1),
            "pipeline": {
                "queue_depth": self.queue.qsize(),
                "queue_capacity": self.cfg.queue_size,
                "events_processed": self.processed,
                "events_dropped": self.dropped,
                "alerts_suppressed": sum(c for _, c in self._alert_seen.values()),
                "throughput_eps": round(
                    self.processed / max(1.0, time.time() - self.started_at), 2),
            },
            "collectors": [t.status() for t in self.tasks],
            "detectors": {
                "rules_loaded": len(self.rules.rules),
                "rule_errors": self.rules.errors,
                "ml": self.ml.status(),
                "baseline": self.baseline.envelope(),
                "semantic": self.semantic.status(),
                "classifier": self.classifier.status(),
                "sequence": self.sequence.status(),
                "llm_judge": self.judge.status(),
            },
            "response": self.responder.status(),
            "triage": self.triage.status(),
            "assistant": self.assistant.status(),
            "storage": self.store.counts(),
        }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "posture": self.posture(),
                "metrics": self.latest_metrics,
                "history": list(self.metrics_history)[-120:],
                "events": list(self.recent_events)[-120:][::-1],
                "detections": list(self.recent_detections)[-80:][::-1],
                "incidents": [i.to_dict() for i in self.correlator.open_incidents()[:20]],
                "processes": self.procs.tree(),
                "network": self.net.summary(),
                "beacons": self.beacons,
                "actions": [a.to_dict() for a in self.responder.log[-30:]][::-1],
                "status": self.status(),
            }
