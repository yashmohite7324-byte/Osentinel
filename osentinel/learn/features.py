"""Feature extraction for command-line classification.

This is the contract between the teacher and the student. The LLM labels raw
command lines offline; the trained classifier scores them live. Both must see
the *same* numeric description of a command or the model learns one thing and
is asked another at inference. So the single source of that description lives
here, imported by both sides, and nothing computes features any other way.

The design choice worth stating: these are interpretable, hand-designed
features, not a learned embedding. A host-security model that fires has to be
explainable to the analyst it interrupts - "flagged because: writes then
executes the same path, contacts a raw IP, decodes base64 into a shell" is
actionable; a cosine distance in a 384-dimensional space is not. Every feature
below has a name and a reason, and the trained model can report which ones drove
a given verdict.

Two feature groups:

  structural   counts and ratios that survive obfuscation - length, entropy,
               token count, how many pipes and redirects, whether a network
               primitive and an interpreter co-occur. These catch the *shape*
               of tradecraft, which changes far more slowly than its spelling.

  lexical      presence of specific high-signal tokens and idioms - /dev/tcp,
               base64 -d, chmod +x, curl|sh. Fast, precise, and brittle alone,
               which is exactly why they sit alongside the structural features
               rather than replacing them.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# Ordered feature names. THE ORDER IS THE SCHEMA - a model is trained against
# these positions, so appending is safe and reordering silently corrupts every
# saved model. New features go on the end, never in the middle.
FEATURE_NAMES: list[str] = [
    # structural
    "length", "token_count", "entropy", "digit_ratio", "special_ratio",
    "max_token_length", "pipe_count", "redirect_count", "semicolon_count",
    "subshell_count", "quote_count", "backtick_count", "url_count", "ip_count",
    "path_count", "uppercase_ratio", "encoded_blob_len",
    # co-occurrence (the interactions that matter more than any single token)
    "net_and_interp", "download_and_exec", "decode_and_exec", "write_and_exec",
    # lexical idioms
    "has_dev_tcp", "has_reverse_shell_fd", "has_base64_decode", "has_hex_escape",
    "has_chmod_exec", "has_pipe_to_shell", "has_nc_exec", "has_curl_wget",
    "has_interpreter", "has_scheduler", "has_cred_path", "has_suid_hunt",
    "has_history_wipe", "has_disable_security", "has_tmp_exec_path",
    "has_raw_ip_conn", "has_python_oneliner", "has_add_account",
]

N_FEATURES = len(FEATURE_NAMES)

# ── patterns ─────────────────────────────────────────────────────────────
_URL = re.compile(r"https?://[^\s'\"]+")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PATH = re.compile(r"(?:^|\s)(/[^\s'\"|;&]+)")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"\\x[0-9a-f]{2}", re.I)
_TOKEN = re.compile(r"\S+")
_INTERP = re.compile(r"\b(sh|bash|zsh|dash|python[23]?|perl|php|ruby|node|powershell|pwsh)\b")
_NET = re.compile(r"(/dev/tcp|/dev/udp|\bnc\b|\bncat\b|\bsocat\b|fsockopen|socket\.socket|"
                  r"create_connection|curl|wget)")
_DOWNLOAD = re.compile(r"\b(curl|wget|fetch|Invoke-WebRequest|urlretrieve|urlopen)\b")
_EXEC = re.compile(r"(\|\s*(sh|bash|python|perl)\b|\bexec\b|-e\s|sh\s+-c|bash\s+-c|"
                   r"eval\b|\$\(|\bsystem\()")
_DECODE = re.compile(r"(base64\s+(-d|--decode)|b64decode|xxd\s+-r|\|\s*base64)")
_WRITE = re.compile(r"(-o\s+/|>\s*/|>>\s*/|tee\s+/|\bcp\b|\bmv\b|write\()")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_features(command: str) -> list[float]:
    """Turn one command line into the fixed feature vector. Pure and total.

    Never raises: a detector that crashes on a weird command line is a detector
    an attacker turns off by sending a weird command line.
    """
    cmd = (command or "")[:2000]
    low = cmd.lower()
    tokens = _TOKEN.findall(cmd)
    n = max(len(cmd), 1)

    letters = sum(c.isalpha() for c in cmd)
    digits = sum(c.isdigit() for c in cmd)
    special = sum(not c.isalnum() and not c.isspace() for c in cmd)
    upper = sum(c.isupper() for c in cmd)
    blobs = _B64.findall(cmd)

    net = bool(_NET.search(low))
    interp = bool(_INTERP.search(low))
    download = bool(_DOWNLOAD.search(low))
    execish = bool(_EXEC.search(low))
    decode = bool(_DECODE.search(low))
    write = bool(_WRITE.search(cmd))

    f = [
        # structural
        float(len(cmd)),
        float(len(tokens)),
        round(shannon_entropy(cmd), 4),
        round(digits / n, 4),
        round(special / n, 4),
        float(max((len(t) for t in tokens), default=0)),
        float(cmd.count("|")),
        float(cmd.count(">") + cmd.count("<")),
        float(cmd.count(";")),
        float(cmd.count("$(") + cmd.count("`")),
        float(cmd.count("'") + cmd.count('"')),
        float(cmd.count("`")),
        float(len(_URL.findall(cmd))),
        float(len(_IP.findall(cmd))),
        float(len(_PATH.findall(cmd))),
        round(upper / max(letters, 1), 4),
        float(max((len(b) for b in blobs), default=0)),
        # co-occurrence
        float(net and interp),
        float(download and (execish or "| sh" in low or "|sh" in low)),
        float(decode and execish),
        float(write and execish),
        # lexical idioms
        float("/dev/tcp" in low or "/dev/udp" in low),
        float(bool(re.search(r"<&\d|>&\d|>&\s*/dev/tcp", low))),
        float(bool(_DECODE.search(low))),
        float(bool(_HEX.search(cmd))),
        float("chmod +x" in low or "chmod 7" in low or "chmod u+x" in low),
        float(bool(re.search(r"\|\s*(sh|bash|/bin/sh|/bin/bash)\b", low))),
        float(bool(re.search(r"\bnc\b.*-e|\bncat\b.*-e|-e\s+/bin/(sh|bash)", low))),
        float(bool(re.search(r"\b(curl|wget)\b", low))),
        float(interp),
        float(bool(re.search(r"crontab|cron\.d|systemctl enable|/etc/init|at\s+now", low))),
        float(bool(re.search(r"/etc/passwd|/etc/shadow|authorized_keys|/etc/sudoers", low))),
        float(bool(re.search(r"-perm\s+-?[0-7]*4000|find\s+/.*-perm|getcap\s+-r", low))),
        float(bool(re.search(r"history\s+-c|rm\s+.*bash_history|>\s*/var/log|shred\b|"
                             r"unset\s+histfile", low))),
        float(bool(re.search(r"setenforce\s+0|iptables\s+-f|systemctl\s+stop\s+aud|"
                             r"pkill\s+-f\s+(falcon|osquery|auditd)", low))),
        float(bool(re.search(r"/tmp/|/dev/shm/|/var/tmp/", low))),
        float(bool(_IP.search(cmd) and net)),
        float(bool(re.search(r"python[23]?\s+-c", low))),
        float(bool(re.search(r"useradd|adduser|usermod\s+-ag|>>\s*/etc/passwd", low))),
    ]
    assert len(f) == N_FEATURES, f"feature drift: {len(f)} != {N_FEATURES}"
    return f


def top_contributing_features(command: str, weights: list[float], k: int = 5
                              ) -> list[tuple[str, float]]:
    """Which features, times the model's weights, drove this score.

    This is what makes a linear model worth using here: the explanation is
    exact, not a post-hoc guess. weights is the trained coefficient vector.
    """
    feats = extract_features(command)
    contrib = [(FEATURE_NAMES[i], feats[i] * weights[i])
               for i in range(min(len(weights), N_FEATURES))]
    contrib.sort(key=lambda kv: abs(kv[1]), reverse=True)
    return [(name, round(val, 3)) for name, val in contrib[:k] if abs(val) > 1e-6]
