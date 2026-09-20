"""Layer 3: sequence detection over the event stream.

Every layer above this one scores things in isolation - one command line, one
metric, one connection. Real intrusions are not isolated events, they are
ordered ones, and the ordering carries information that no individual event
contains. Discovery, then a download, then a cron entry is an intrusion.
Any one of those three, on its own, is a Tuesday.

Two independent mechanisms, because they fail differently:

  Chain matching      Known attack progressions expressed as ordered stages.
                      Precise, explainable, and blind to anything not listed -
                      it is the signature layer applied to time instead of text.

  Transition surprise A first-order Markov model over action transitions,
                      learned from this host. Scores how unlikely an observed
                      transition is given everything seen before. Catches novel
                      orderings that no chain describes, at the cost of needing
                      a warmup and of flagging genuinely rare-but-fine events.

The two disagree often. That is the point - a chain hit on a transition the
host does all the time is weaker evidence than a chain hit on one it has never
made, and the detector reports both numbers rather than collapsing them.
"""

from __future__ import annotations

import math
import re
import time
from collections import defaultdict, deque

from ..models import Detection, Event

# ── stage mapping ────────────────────────────────────────────────────────
# Events are noisy and numerous; stages are few and meaningful. Collapsing to a
# stage alphabet before matching is what makes chains writable by a human and
# keeps the Markov model's state space small enough to learn from one host.

STAGE_RULES: list[tuple[str, str, tuple[str, ...]]] = [
    # (stage, event category, substrings that appear in action or attrs)
    ("discovery",   "process",    ("whoami", "uname", "id", "hostname", "ps ",
                                   "netstat", "ss ", "ifconfig", "ip a", "lsb_release",
                                   "/etc/passwd", "sudo -l", "getcap", "-perm -4000")),
    ("ingress",     "process",    ("curl", "wget", "ftp ", "scp ", "tftp", "urlretrieve",
                                   "urlopen", "Invoke-WebRequest")),
    ("execution",   "process",    ("sh -c", "bash -c", "python -c", "perl -e", "php -r",
                                   "eval", "exec", "base64 -d")),
    ("persistence", "filesystem", ("crontab", "cron.d", "systemd", "init.d",
                                   "authorized_keys", "rc.local", "bashrc", "profile",
                                   "ld.so.preload")),
    ("persistence", "process",    ("crontab", "systemctl enable", "useradd", "usermod",
                                   "adduser", "chkconfig")),
    ("escalation",  "process",    ("sudo", "su -", "pkexec", "setcap", "chmod +s",
                                   "setuid")),
    ("evasion",     "process",    ("history -c", "shred", "unset HISTFILE", "touch -r",
                                   "setenforce", "iptables -F", "systemctl stop aud",
                                   "chattr")),
    ("c2",          "network",    ("periodic_contact",)),
    ("lateral",     "network",    ("connection_opened",)),
    ("impact",      "resource",   ("cpu_sustained", "disk_write_burst")),
    ("collection",  "filesystem", ("file_read_burst",)),
]

# Ordered progressions worth alerting on. Gaps are allowed - the matcher looks
# for these as subsequences, not as contiguous runs - because a real intrusion
# generates a great deal of unrelated activity in between.
CHAINS: list[dict] = [
    {"id": "CHAIN-FOOTHOLD", "stages": ["discovery", "ingress", "execution"],
     "score": 76, "mitre": ["T1082", "T1105", "T1059"],
     "title": "Reconnaissance followed by tool download and execution"},
    {"id": "CHAIN-ESTABLISH", "stages": ["ingress", "execution", "persistence"],
     "score": 88, "mitre": ["T1105", "T1059", "T1543"],
     "title": "Downloaded code executed and then made persistent"},
    {"id": "CHAIN-ESCALATE", "stages": ["discovery", "escalation", "persistence"],
     "score": 86, "mitre": ["T1082", "T1548", "T1136"],
     "title": "Privilege enumeration, escalation, then persistence"},
    {"id": "CHAIN-COVER", "stages": ["execution", "evasion"],
     "score": 82, "mitre": ["T1059", "T1070"],
     "title": "Execution followed by log or history tampering"},
    {"id": "CHAIN-BEACON", "stages": ["execution", "c2"],
     "score": 78, "mitre": ["T1059", "T1071"],
     "title": "Execution followed by regular outbound contact"},
    {"id": "CHAIN-EXFIL", "stages": ["collection", "c2"],
     "score": 84, "mitre": ["T1005", "T1041"],
     "title": "Bulk file access followed by outbound transfer"},
    {"id": "CHAIN-SCAN", "stages": ["discovery", "lateral"],
     "score": 62, "mitre": ["T1046"],
     "title": "Host enumeration followed by connections to new peers"},
    {"id": "CHAIN-MINE", "stages": ["ingress", "impact"],
     "score": 74, "mitre": ["T1105", "T1496"],
     "title": "Download followed by sustained resource consumption"},
]


_WORDISH = re.compile(r"[a-z0-9_]+")


def _hit(needle: str, blob: str, words: set[str]) -> bool:
    """Substring match, except for short tokens, which must be whole words.

    Without this, the needle "id" matches "provider", "ssh-ed25519" and half of
    /usr/lib, and every event on the host is classified as discovery - which
    makes the Markov model learn nothing and every chain match meaningless.
    """
    n = needle.lower().strip()
    if len(n) <= 3 and _WORDISH.fullmatch(n):
        return n in words
    return n in blob


def stage_of(event: Event) -> str | None:
    """Map one event onto the stage alphabet, or None if it carries no stage."""
    blob = " ".join([
        str(event.action),
        str(event.attrs.get("cmdline", "")),
        str(event.attrs.get("name", "")),
        str(event.attrs.get("path", "")),
    ]).lower()
    words = set(_WORDISH.findall(blob))
    for stage, category, needles in STAGE_RULES:
        if event.category != category:
            continue
        if any(_hit(n, blob, words) for n in needles):
            return stage
    return None


class MarkovSurprise:
    """First-order transition model over the stage alphabet.

    Laplace-smoothed so an unseen transition has a defined, finite surprisal
    rather than an infinite one; an infinite score would make the first
    occurrence of anything a critical alert, which is how a detector earns
    itself a permanent mute.
    """

    def __init__(self, warmup: int = 40, alpha: float = 1.0):
        self.warmup = warmup
        self.alpha = alpha
        self.counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.totals: dict[str, int] = defaultdict(int)
        self.observations = 0
        self.alphabet: set[str] = {s for s, _, _ in STAGE_RULES}

    @property
    def trained(self) -> bool:
        return self.observations >= self.warmup

    def surprisal(self, prev: str, nxt: str) -> float:
        """Bits of surprise. Zero means routine, higher means unusual here."""
        k = len(self.alphabet)
        p = ((self.counts[prev][nxt] + self.alpha)
             / (self.totals[prev] + self.alpha * k))
        return -math.log2(max(p, 1e-9))

    def observe(self, prev: str, nxt: str) -> None:
        self.counts[prev][nxt] += 1
        self.totals[prev] += 1
        self.observations += 1

    def status(self) -> dict:
        return {"trained": self.trained, "observations": self.observations,
                "warmup": self.warmup, "states": len(self.totals)}


class SequenceDetector:
    def __init__(self, enabled: bool = True, window_s: float = 600.0,
                 surprise_bits: float = 4.5, max_tracked: int = 300,
                 markov_warmup: int = 40):
        self.enabled = enabled
        self.window_s = window_s
        self.surprise_bits = surprise_bits
        self.max_tracked = max_tracked
        self.markov = MarkovSurprise(markov_warmup)
        # entity -> deque[(ts, stage, detail)]
        self.trails: dict[str, deque] = {}
        self.parent: dict[int, int] = {}        # pid -> ppid, for lineage
        self.last_stage: dict[str, str] = {}
        self.fired: dict[str, float] = {}
        self.staged = 0
        self.chain_hits = 0
        self.surprise_hits = 0

    # -- trail maintenance --------------------------------------------------

    def _actor(self, event: Event) -> str:
        """Who this event is attributed to.

        This has to be the process *lineage*, not the pid. An intrusion runs
        `curl` and then `sh` as two short-lived children of one shell, so
        keying trails on pid gives every step its own trail of length one and
        no chain ever matches - the detector looks like it works and detects
        nothing. Walking up ppid to a stable ancestor puts all the steps of one
        session on one trail, which is the whole premise of the layer.

        Network and resource events are host-wide and join the host trail, so a
        beacon can line up with the execution that started it.
        """
        if event.category in ("network", "resource"):
            return "host"
        pid, ppid = event.attrs.get("pid"), event.attrs.get("ppid")
        if pid is None:
            return event.entity or "host"
        pid = int(pid)
        if ppid is not None:
            self.parent[pid] = int(ppid)
            if len(self.parent) > 8000:
                self.parent = dict(list(self.parent.items())[-4000:])
        return str(self.lineage_root(pid))

    def lineage_root(self, pid: int) -> int:
        """Highest known ancestor, stopping short of init and the kernel."""
        seen = {pid}
        cur = pid
        for _ in range(12):
            parent = self.parent.get(cur)
            # Stop at init, kthreadd, or anything we have not observed: the
            # session leader is the useful grouping, not pid 1, which would put
            # every process on the host into a single trail.
            if parent is None or parent <= 2 or parent in seen:
                return cur
            seen.add(parent)
            cur = parent
        return cur

    def _trim(self, trail: deque, now: float) -> None:
        while trail and now - trail[0][0] > self.window_s:
            trail.popleft()

    def _evict(self) -> None:
        if len(self.trails) <= self.max_tracked:
            return
        newest = {k: (t[-1][0] if t else 0.0) for k, t in self.trails.items()}
        for k, _ in sorted(newest.items(), key=lambda kv: kv[1])[
                : len(self.trails) - self.max_tracked]:
            self.trails.pop(k, None)
            self.last_stage.pop(k, None)

    # -- matching -----------------------------------------------------------

    @staticmethod
    def _subsequence_span(stages: list[str], pattern: list[str]) -> tuple[int, int] | None:
        """Index of the first and last element of an in-order match, or None."""
        i, first = 0, None
        for idx, s in enumerate(stages):
            if s == pattern[i]:
                if i == 0:
                    first = idx
                i += 1
                if i == len(pattern):
                    return (first, idx)
        return None

    def observe(self, events: list[Event]) -> list[Detection]:
        if not self.enabled:
            return []
        now = time.time()
        dets: list[Detection] = []
        touched: set[str] = set()

        for ev in events:
            stage = stage_of(ev)
            if stage is None:
                continue
            self.staged += 1
            actor = self._actor(ev)
            trail = self.trails.setdefault(actor, deque(maxlen=60))
            detail = (str(ev.attrs.get("cmdline") or ev.attrs.get("path")
                          or ev.attrs.get("raddr") or ev.action))[:140]
            trail.append((ev.ts, stage, detail))
            touched.add(actor)

            prev = self.last_stage.get(actor)
            if prev:
                bits = self.markov.surprisal(prev, stage)
                self.markov.observe(prev, stage)
                if self.markov.trained and bits >= self.surprise_bits and prev != stage:
                    d = self._surprise_detection(actor, prev, stage, bits, detail)
                    if d:
                        dets.append(d)
            else:
                self.markov.observe("<start>", stage)
            self.last_stage[actor] = stage

        for actor in touched:
            trail = self.trails[actor]
            self._trim(trail, now)
            dets.extend(self._chain_detections(actor, trail, now))

        self._evict()
        return dets

    def _chain_detections(self, actor: str, trail: deque, now: float) -> list[Detection]:
        stages = [s for _, s, _ in trail]
        details = [d for _, _, d in trail]
        times = [t for t, _, _ in trail]
        out: list[Detection] = []

        # Chains overlap by design - FOOTHOLD and ESTABLISH share two stages -
        # so emitting every match would report one intrusion three times and
        # inflate the incident through breadth scoring. Take the strongest.
        candidates = []
        for chain in CHAINS:
            span = self._subsequence_span(stages, chain["stages"])
            if span is not None:
                candidates.append((chain["score"], len(chain["stages"]), chain, span))
        candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)

        for _, _, chain, span in candidates[:1]:
            key = f"{actor}:{chain['id']}"
            # A chain stays true for as long as its events are in the window, so
            # without this it would re-fire on every subsequent event.
            if now - self.fired.get(key, 0.0) < self.window_s / 2:
                continue
            self.fired[key] = now
            self.chain_hits += 1

            first, last = span
            elapsed = times[last] - times[first]
            # Fast progressions are more suspicious: a human administrator does
            # not move from enumeration to persistence in eleven seconds.
            speed = 1.0 if elapsed > 300 else 1.18 if elapsed > 60 else 1.3
            # And a chain built from transitions this host makes constantly is
            # weaker than one built from transitions it has never made.
            bits = sum(self.markov.surprisal(a, b)
                       for a, b in zip(chain["stages"], chain["stages"][1:]))
            rarity = min(1.25, 0.85 + 0.05 * bits) if self.markov.trained else 1.0

            score = min(94.0, chain["score"] * speed * rarity)
            out.append(Detection(
                rule_id=chain["id"],
                title=chain["title"],
                score=round(score, 1),
                confidence=round(min(0.86, 0.55 + 0.05 * len(chain["stages"])
                                     + (0.08 if elapsed < 60 else 0.0)), 2),
                source="sequence",
                entity=actor,
                category="process",
                mitre=list(chain["mitre"]),
                evidence={
                    "stages_matched": chain["stages"],
                    "observed_order": stages[first:last + 1],
                    "elapsed_s": round(elapsed, 1),
                    "steps": [f"{time.strftime('%H:%M:%S', time.localtime(times[i]))} "
                              f"{stages[i]}: {details[i]}"
                              for i in range(first, last + 1)][:10],
                    "transition_rarity_bits": round(bits, 2),
                    "model_trained": self.markov.trained,
                },
                remediation=(
                    "No single event here is necessarily alarming; the ordering is. Read the "
                    "steps in sequence and establish whether one actor is responsible for all "
                    "of them. If this was a deployment or an administrator, the trail will "
                    "have a change record behind it - if it does not, treat the earliest step "
                    "as your initial access time."),
            ))
        return out

    def _surprise_detection(self, actor: str, prev: str, stage: str,
                            bits: float, detail: str) -> Detection | None:
        key = f"{actor}:surprise:{prev}->{stage}"
        now = time.time()
        if now - self.fired.get(key, 0.0) < 300:
            return None
        self.fired[key] = now
        self.surprise_hits += 1
        score = min(72.0, 34.0 + 5.0 * (bits - self.surprise_bits) + 3.0 * self.surprise_bits)
        return Detection(
            rule_id="SEQ-RARE-TRANSITION",
            title=f"Unusual progression on this host: {prev} to {stage}",
            score=round(score, 1),
            confidence=round(min(0.6, 0.32 + 0.03 * bits), 2),
            source="sequence",
            entity=actor,
            category="process",
            mitre=[],
            evidence={"from_stage": prev, "to_stage": stage,
                      "surprisal_bits": round(bits, 2),
                      "threshold_bits": self.surprise_bits,
                      "trigger": detail,
                      "transitions_learned": self.markov.observations},
            remediation=(
                "This is a statement about rarity on this host, not about maliciousness. "
                "It is worth attention when something else corroborates it and worth very "
                "little on its own - expect it on a host whose workload has just changed."),
        )

    def status(self) -> dict:
        return {"enabled": self.enabled, "window_s": self.window_s,
                "chains": len(CHAINS), "tracked_actors": len(self.trails),
                "events_staged": self.staged, "chain_hits": self.chain_hits,
                "rare_transition_hits": self.surprise_hits,
                "markov": self.markov.status()}
