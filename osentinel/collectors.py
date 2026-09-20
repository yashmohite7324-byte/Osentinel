"""Collectors read live state out of the operating system and emit Events.

Each collector is a stateful object with a poll() method. The engine calls
poll() on a schedule from a worker thread; collectors diff the current state
against the previous snapshot so we emit *changes*, not the whole world.
"""

from __future__ import annotations

import hashlib
import os
import platform
import socket
import stat
import time
from collections import defaultdict, deque
from pathlib import Path

import psutil

from .models import Event

IS_LINUX = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"


def _connections(proc: psutil.Process | None = None, kind: str = "inet"):
    """psutil renamed Process.connections -> net_connections in v6. Support both."""
    try:
        if proc is not None:
            fn = getattr(proc, "net_connections", None) or proc.connections
            return fn(kind=kind)
        fn = getattr(psutil, "net_connections", None)
        return fn(kind=kind) if fn else []
    except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
        return []


def _addr(a) -> str:
    if not a:
        return ""
    try:
        return f"{a.ip}:{a.port}"
    except AttributeError:
        return str(a)


# ---------------------------------------------------------------- processes

class ProcessCollector:
    """Tracks the process table: births, deaths, privilege changes, lineage."""

    FIELDS = ["pid", "ppid", "name", "username", "cmdline", "create_time",
              "cpu_percent", "memory_info", "num_threads", "status", "exe"]

    def __init__(self, deep_scan_top_n: int = 25):
        self.known: dict[int, dict] = {}
        self.deep_scan_top_n = deep_scan_top_n
        self.snapshot: dict[int, dict] = {}
        self._first_pass = True

    def _describe(self, p: psutil.Process) -> dict | None:
        try:
            with p.oneshot():
                info = p.as_dict(attrs=self.FIELDS)
            uids = None
            try:
                uids = p.uids()
            except Exception:
                pass
            mem = info.get("memory_info")
            cmd = info.get("cmdline") or []
            return {
                "pid": info["pid"],
                "ppid": info.get("ppid") or 0,
                "name": info.get("name") or "?",
                "user": info.get("username") or "?",
                "cmdline": " ".join(cmd)[:512],
                "exe": info.get("exe") or "",
                "started": info.get("create_time") or 0.0,
                "cpu": float(info.get("cpu_percent") or 0.0),
                "rss": int(getattr(mem, "rss", 0) or 0),
                "threads": int(info.get("num_threads") or 0),
                "status": info.get("status") or "?",
                "uid": uids.real if uids else -1,
                "euid": uids.effective if uids else -1,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def poll(self) -> list[Event]:
        events: list[Event] = []
        current: dict[int, dict] = {}

        for p in psutil.process_iter():
            d = self._describe(p)
            if d:
                current[d["pid"]] = d

        # attach descriptor / connection counts for the busiest processes only,
        # because /proc/<pid>/fd walks are expensive on a loaded machine.
        hot = sorted(current.values(), key=lambda x: x["cpu"], reverse=True)[:self.deep_scan_top_n]
        for d in hot:
            try:
                p = psutil.Process(d["pid"])
                d["fds"] = p.num_fds() if hasattr(p, "num_fds") else 0
                d["conns"] = len(_connections(p))
            except Exception:
                d["fds"], d["conns"] = 0, 0

        new_pids = set(current) - set(self.known)
        gone_pids = set(self.known) - set(current)

        if not self._first_pass:
            for pid in new_pids:
                d = current[pid]
                parent = current.get(d["ppid"]) or self.known.get(d["ppid"]) or {}
                events.append(Event(
                    category="process", action="process_started", entity=str(pid),
                    attrs={**d, "parent_name": parent.get("name", "?"),
                           "parent_cmdline": parent.get("cmdline", "")}))
            for pid in gone_pids:
                d = self.known[pid]
                events.append(Event(
                    category="process", action="process_exited", entity=str(pid),
                    attrs={"pid": pid, "name": d["name"],
                           "lifetime": max(0.0, time.time() - d["started"])}))

            for pid in set(current) & set(self.known):
                now, before = current[pid], self.known[pid]
                if now["euid"] != before["euid"] and now["euid"] >= 0:
                    events.append(Event(
                        category="identity", action="privilege_changed", entity=str(pid),
                        attrs={"pid": pid, "name": now["name"],
                               "from_euid": before["euid"], "to_euid": now["euid"],
                               "cmdline": now["cmdline"]}))

        self._first_pass = False
        self.known = current
        self.snapshot = current
        return events

    def tree(self) -> list[dict]:
        """Process lineage for the UI, capped so the payload stays small."""
        procs = sorted(self.snapshot.values(), key=lambda d: d["cpu"], reverse=True)[:120]
        return [{"pid": d["pid"], "ppid": d["ppid"], "name": d["name"], "user": d["user"],
                 "cpu": round(d["cpu"], 1), "rss": d["rss"], "threads": d["threads"],
                 "cmdline": d["cmdline"][:160]} for d in procs]


# ------------------------------------------------------------------ network

class NetworkCollector:
    """Tracks sockets, listeners and per-destination timing for beacon detection."""

    def __init__(self, beacon_window: int = 12):
        self.known: set[tuple] = set()
        self.listeners: set[tuple] = set()
        self.contact_times: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=beacon_window))
        self._first_pass = True
        self.last_io = psutil.net_io_counters()
        self.last_io_ts = time.time()
        self.rates = {"tx_bps": 0.0, "rx_bps": 0.0}

    def poll(self) -> list[Event]:
        events: list[Event] = []
        conns = _connections()
        now = time.time()

        active, listening = set(), set()
        meta: dict[tuple, dict] = {}
        for c in conns:
            pid = c.pid or 0
            if c.status == psutil.CONN_LISTEN:
                key = (pid, _addr(c.laddr))
                listening.add(key)
                meta[key] = {"pid": pid, "laddr": _addr(c.laddr), "family": str(c.family)}
            elif c.raddr:
                key = (pid, _addr(c.raddr))
                active.add(key)
                meta[key] = {"pid": pid, "laddr": _addr(c.laddr), "raddr": _addr(c.raddr),
                             "status": c.status}

        # Only stamp a contact when the connection is newly observed. Stamping
        # every poll would measure our own polling cadence and report perfect
        # periodicity for any long-lived socket - a guaranteed false positive.
        for key in active - self.known:
            if not self._is_local(key[1]):
                self.contact_times[key].append(now)
        self._expire_contacts(now)

        if not self._first_pass:
            for key in active - self.known:
                info = meta.get(key, {})
                info["process"] = self._pname(info.get("pid", 0))
                info["remote_port"] = self._port(info.get("raddr", ""))
                events.append(Event(category="network", action="connection_opened",
                                    entity=info.get("raddr", "?"), attrs=info))
            for key in listening - self.listeners:
                info = meta.get(key, {})
                info["process"] = self._pname(info.get("pid", 0))
                info["port"] = self._port(info.get("laddr", ""))
                events.append(Event(category="network", action="listener_opened",
                                    entity=info.get("laddr", "?"), attrs=info))

        # throughput deltas
        io = psutil.net_io_counters()
        dt = max(1e-6, now - self.last_io_ts)
        self.rates = {
            "tx_bps": max(0.0, (io.bytes_sent - self.last_io.bytes_sent) / dt),
            "rx_bps": max(0.0, (io.bytes_recv - self.last_io.bytes_recv) / dt),
        }
        self.last_io, self.last_io_ts = io, now

        self._first_pass = False
        self.known, self.listeners = active, listening
        return events

    @staticmethod
    def _is_local(addr: str) -> bool:
        """Loopback and link-local peers are not command and control."""
        ip = addr.rsplit(":", 1)[0].strip("[]")
        return (ip.startswith("127.") or ip in ("::1", "0.0.0.0", "")
                or ip.startswith("169.254.") or ip.startswith("fe80:"))

    def _expire_contacts(self, now: float, ttl: float = 1800.0) -> None:
        """Drop destinations we have not seen recently so memory stays bounded."""
        stale = [k for k, stamps in self.contact_times.items()
                 if not stamps or (now - stamps[-1]) > ttl]
        for k in stale:
            del self.contact_times[k]

    @staticmethod
    def _pname(pid: int) -> str:
        try:
            return psutil.Process(pid).name() if pid else "?"
        except Exception:
            return "?"

    @staticmethod
    def _port(addr: str) -> int:
        try:
            return int(addr.rsplit(":", 1)[1])
        except Exception:
            return 0

    def beacon_candidates(self, min_samples: int = 6) -> list[dict]:
        """A C2 beacon calls home on a metronome. Human traffic does not.

        We measure the coefficient of variation of inter-arrival gaps; a value
        close to zero means near-perfect periodicity.
        """
        out = []
        for (pid, raddr), stamps in self.contact_times.items():
            if len(stamps) < min_samples:
                continue
            gaps = [b - a for a, b in zip(stamps, list(stamps)[1:])]
            gaps = [g for g in gaps if g > 0.5]
            if len(gaps) < min_samples - 1:
                continue
            mean = sum(gaps) / len(gaps)
            var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
            cv = (var ** 0.5) / mean if mean else 1.0
            # Reject anything that lines up with our own polling cadence: that
            # is an artefact of observation, not evidence about the host.
            if abs(mean % 3.0) < 0.15 and cv < 0.02:
                continue
            if cv < 0.25:
                out.append({"pid": pid, "raddr": raddr, "interval_s": round(mean, 2),
                            "jitter_cv": round(cv, 3), "samples": len(gaps) + 1,
                            "process": self._pname(pid)})
        return out

    def summary(self) -> dict:
        return {"established": len(self.known), "listeners": len(self.listeners), **self.rates}


# --------------------------------------------------------------- filesystem

class FileIntegrityCollector:
    """Hash-based integrity monitoring of paths that attackers like to touch."""

    def __init__(self, watch_paths: list[str], store, max_files: int = 400,
                 max_bytes: int = 4_000_000):
        self.watch_paths = watch_paths
        self.store = store
        self.max_files = max_files
        self.max_bytes = max_bytes
        self.baseline: dict[str, dict] = store.file_baseline()
        self._primed = bool(self.baseline)

    @staticmethod
    def _sha256(path: Path, limit: int) -> str | None:
        h = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                read = 0
                while chunk := fh.read(65536):
                    h.update(chunk)
                    read += len(chunk)
                    if read >= limit:
                        break
            return h.hexdigest()
        except (OSError, PermissionError):
            return None

    def _walk(self) -> dict[str, dict]:
        seen: dict[str, dict] = {}
        for root in self.watch_paths:
            rp = Path(os.path.expanduser(root))
            if not rp.exists():
                continue
            candidates = [rp] if rp.is_file() else list(rp.rglob("*"))
            for f in candidates:
                if len(seen) >= self.max_files:
                    return seen
                try:
                    if not f.is_file() or f.is_symlink():
                        continue
                    st = f.stat()
                    if st.st_size > self.max_bytes:
                        continue
                    digest = self._sha256(f, self.max_bytes)
                    if digest:
                        seen[str(f)] = {"sha256": digest, "size": st.st_size,
                                        "mtime": st.st_mtime, "mode": st.st_mode}
                except (OSError, PermissionError):
                    continue
        return seen

    def poll(self) -> list[Event]:
        events: list[Event] = []
        current = self._walk()

        if self._primed:
            for path, info in current.items():
                old = self.baseline.get(path)
                if old is None:
                    events.append(Event(category="filesystem", action="file_created",
                                        entity=path, attrs={"path": path, **info}))
                elif old["sha256"] != info["sha256"]:
                    events.append(Event(category="filesystem", action="file_modified",
                                        entity=path,
                                        attrs={"path": path, "old_sha256": old["sha256"][:16],
                                               "new_sha256": info["sha256"][:16],
                                               "size": info["size"]}))
                elif old["mode"] != info["mode"]:
                    events.append(Event(category="filesystem", action="permissions_changed",
                                        entity=path,
                                        attrs={"path": path,
                                               "old_mode": stat.filemode(old["mode"]),
                                               "new_mode": stat.filemode(info["mode"])}))
            for path in set(self.baseline) - set(current):
                events.append(Event(category="filesystem", action="file_deleted",
                                    entity=path, attrs={"path": path}))
        else:
            self._primed = True

        self.baseline = current
        self.store.save_file_baseline(
            [(p, i["sha256"], i["size"], i["mtime"], i["mode"]) for p, i in current.items()])
        return events

    def suid_binaries(self) -> list[dict]:
        out = []
        for path, info in self.baseline.items():
            if info["mode"] & (stat.S_ISUID | stat.S_ISGID):
                out.append({"path": path, "mode": stat.filemode(info["mode"])})
        return out


# ---------------------------------------------------------------- resources

class ResourceCollector:
    """Kernel-level resource pressure: CPU, memory, swap, disk, load, context switches."""

    def __init__(self):
        psutil.cpu_percent(interval=None)
        self._last_ctx = psutil.cpu_stats()
        self._last_ts = time.time()

    def sample(self) -> dict[str, float]:
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        cs = psutil.cpu_stats()
        now = time.time()
        dt = max(1e-6, now - self._last_ts)
        ctx_rate = (cs.ctx_switches - self._last_ctx.ctx_switches) / dt
        intr_rate = (cs.interrupts - self._last_ctx.interrupts) / dt
        self._last_ctx, self._last_ts = cs, now

        try:
            load1 = os.getloadavg()[0]
        except (OSError, AttributeError):
            load1 = 0.0
        try:
            disk = psutil.disk_usage("/").percent
        except Exception:
            disk = 0.0

        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "mem_percent": vm.percent,
            "swap_percent": sw.percent,
            "disk_percent": disk,
            "load1": load1,
            "ctx_switches_per_s": ctx_rate,
            "interrupts_per_s": intr_rate,
            "process_count": len(psutil.pids()),
        }


def host_identity() -> dict:
    boot = psutil.boot_time()
    return {
        "hostname": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "kernel": platform.version()[:80],
        "cpus": psutil.cpu_count(logical=True),
        "memory_gb": round(psutil.virtual_memory().total / 1024**3, 1),
        "boot_time": boot,
        "uptime_s": time.time() - boot,
        "user": psutil.Process().username(),
        "elevated": (os.geteuid() == 0) if hasattr(os, "geteuid") else False,
    }

class SystemMonitorCollector:
    """Gathers overall system health for the monitoring panel."""
    
    def __init__(self):
        self.last_net = psutil.net_io_counters() if hasattr(psutil, 'net_io_counters') else None
        self.last_time = time.time()

    def poll(self):
        now = time.time()
        dt = now - self.last_time
        if dt == 0:
            dt = 1
            
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        
        disk = None
        try:
            # On windows use C:\
            disk = psutil.disk_usage('C:\\' if platform.system() == 'Windows' else '/')
        except Exception:
            pass
            
        net_tx = 0
        net_rx = 0
        try:
            current_net = psutil.net_io_counters()
            if self.last_net and current_net:
                net_tx = (current_net.bytes_sent - self.last_net.bytes_sent) / dt
                net_rx = (current_net.bytes_recv - self.last_net.bytes_recv) / dt
            self.last_net = current_net
        except Exception:
            pass
            
        self.last_time = now
        
        return [Event(
            type="system_monitor",
            category="metrics",
            subject="host",
            action="monitor",
            summary="System resource metrics",
            data={
                "cpu_percent": cpu_percent,
                "mem_percent": mem.percent,
                "disk_percent": disk.percent if disk else 0,
                "net_tx_bps": net_tx,
                "net_rx_bps": net_rx
            }
        )]
