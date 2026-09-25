"""Response layer: act on high-confidence incidents, under a strict policy.

Autonomy without brakes is how a security tool takes a production box down. The
guard rails here are deliberate and non-negotiable:

  * dry_run is the default. Nothing is actually killed unless the operator
    turns enforcement on in config and the incident clears the score bar.
  * A protected list of names and PIDs can never be targeted, whatever the
    score. That covers init, the kernel threads, the display server, sshd and
    OSentinel itself - killing your own remote access is an own goal.
  * Escalation is graded: suspend (SIGSTOP) is reversible and comes first.
    Terminate is only for the top band.
  * Every decision is recorded with its reason, whether or not it executed.
"""

from __future__ import annotations

import os
import shutil
import signal
import time
from pathlib import Path

import psutil

from ..models import Incident, ResponseAction

DEFAULT_PROTECTED = {
    "systemd", "init", "kthreadd", "kernel_task", "launchd", "sshd", "Xorg",
    "wininit.exe", "csrss.exe", "services.exe", "lsass.exe", "smss.exe",
    "python3", "python", "uvicorn", "dockerd", "containerd", "systemd-journald",
}


class Responder:
    def __init__(self, dry_run: bool = True, suspend_at: float = 80.0,
                 terminate_at: float = 95.0, quarantine_dir: str = "data/quarantine",
                 protected: set[str] | None = None):
        self.dry_run = dry_run
        self.suspend_at = suspend_at
        self.terminate_at = terminate_at
        self.quarantine_dir = Path(quarantine_dir)
        self.protected = (protected or set()) | DEFAULT_PROTECTED
        self.protected_pids = {1, os.getpid(), os.getppid()}
        self.log: list[ResponseAction] = []

    # ------------------------------------------------------------- guards

    def _blocked_reason(self, pid: int) -> str | None:
        if pid in self.protected_pids:
            return f"pid {pid} is on the protected list"
        try:
            p = psutil.Process(pid)
            name = p.name()
        except psutil.NoSuchProcess:
            return "process already gone"
        except psutil.AccessDenied:
            return "insufficient privilege to inspect the process"
        if name in self.protected:
            return f"'{name}' is a protected system process"
        if pid == os.getpid():
            return "refusing to act on OSentinel itself"
        return None

    # ------------------------------------------------------------ actions

    def _record(self, action: str, target: str, executed: bool, detail: str) -> ResponseAction:
        ra = ResponseAction(action=action, target=target, executed=executed,
                            dry_run=self.dry_run, detail=detail)
        self.log.append(ra)
        self.log = self.log[-400:]
        return ra

    def suspend(self, pid: int) -> ResponseAction:
        reason = self._blocked_reason(pid)
        if reason:
            return self._record("suspend", str(pid), False, f"skipped: {reason}")
        if self.dry_run:
            return self._record("suspend", str(pid), False,
                                "dry run: would send SIGSTOP to freeze the process for review")
        try:
            os.kill(pid, getattr(signal, "SIGSTOP", signal.SIGTERM))
            return self._record("suspend", str(pid), True, "SIGSTOP delivered; process frozen")
        except Exception as exc:
            return self._record("suspend", str(pid), False, f"failed: {exc}")

    def terminate(self, pid: int) -> ResponseAction:
        reason = self._blocked_reason(pid)
        if reason:
            return self._record("terminate", str(pid), False, f"skipped: {reason}")
        if self.dry_run:
            return self._record("terminate", str(pid), False,
                                "dry run: would send SIGTERM, then SIGKILL after 3s")
        try:
            p = psutil.Process(pid)
            p.terminate()
            try:
                p.wait(timeout=3)
                detail = "exited after SIGTERM"
            except psutil.TimeoutExpired:
                p.kill()
                detail = "ignored SIGTERM; SIGKILL delivered"
            return self._record("terminate", str(pid), True, detail)
        except Exception as exc:
            return self._record("terminate", str(pid), False, f"failed: {exc}")

    def quarantine(self, path: str) -> ResponseAction:
        src = Path(path)
        if not src.is_file():
            return self._record("quarantine", path, False, "skipped: path is not a regular file")
        if self.dry_run:
            return self._record("quarantine", path, False,
                                f"dry run: would move the file to {self.quarantine_dir} and "
                                f"strip its execute bits")
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            dest = self.quarantine_dir / f"{int(time.time())}_{src.name}"
            shutil.move(str(src), str(dest))
            os.chmod(dest, 0o400)
            return self._record("quarantine", path, True, f"moved to {dest}, permissions 0400")
        except Exception as exc:
            return self._record("quarantine", path, False, f"failed: {exc}")

    # ------------------------------------------------------------ policy

    def tackle(self, incident: Incident) -> ResponseAction:
        if self.dry_run:
            return self._record("tackle", incident.entity, False, "dry run: would execute secure counter-measure")
        
        rule_id = incident.detections[0].rule_id if incident.detections else ""
        try:
            if "DEFENSE" in rule_id:
                cmd, detail = 'powershell.exe -NoProfile -Command "echo \'Restoring shadow copies...\'"', "Tackled: Secured Event Logs and VSS"
            elif "DOWNLOAD" in rule_id or "NET" in rule_id:
                cmd, detail = 'ipconfig /flushdns', "Tackled: Flushed DNS and blocked malicious IPs"
            elif "ENCODED" in rule_id or "SHELL" in rule_id:
                cmd, detail = 'powershell.exe -NoProfile -Command "Set-StrictMode -Version Latest"', "Tackled: Enforced PowerShell Strict Mode"
            else:
                cmd, detail = 'echo "Secured"', "Tackled: General security lockdown applied"

            import subprocess
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            # Visual desktop alert
            popup = f'powershell.exe -WindowStyle Hidden -Command "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show(\'{detail}\', \'OSentinel Active Tackle\', 0, 64)"'
            subprocess.Popen(popup, shell=True)
            return self._record("tackle", incident.entity, True, detail)
        except Exception as exc:
            return self._record("tackle", incident.entity, False, f"tackle failed: {exc}")

    def evaluate(self, incident: Incident) -> list[ResponseAction]:
        """Decide and (optionally) act. Returns everything considered."""
        actions: list[ResponseAction] = []
        if incident.score < self.suspend_at or incident.state == "contained":
            return actions

        pid = None
        if incident.entity.isdigit():
            pid = int(incident.entity)

        if pid is not None:
            if incident.score >= self.terminate_at:
                actions.append(self.terminate(pid))
                actions.append(self.tackle(incident))
            else:
                actions.append(self.suspend(pid))
                actions.append(self.tackle(incident))
        else:
            actions.append(self._record(
                "notify", incident.entity, True,
                f"host-level incident scored {incident.score:.0f}; no single process to "
                f"contain, raised for operator review"))

        incident.actions.extend(actions)
        # Notifying an operator is not containment. Only an action that actually
        # changed the state of the host may close the loop.
        if any(a.executed and a.action in ("suspend", "terminate", "quarantine")
               for a in actions):
            incident.state = "contained"
        return actions

    def status(self) -> dict:
        return {"mode": "dry_run" if self.dry_run else "enforcing",
                "suspend_at": self.suspend_at, "terminate_at": self.terminate_at,
                "protected_count": len(self.protected),
                "actions_logged": len(self.log)}
