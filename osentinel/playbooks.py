"""Prevention knowledge base.

Detection tells an operator what happened. This module answers the question
that follows - "what do I change so it cannot happen again" - and it is the
reason the assistant can give hardening advice without inventing it.

Each entry is keyed by MITRE technique and holds four things: what the
technique actually is, the preconditions an attacker needs, the controls that
remove those preconditions, and the telemetry that would catch it earlier next
time. The assistant retrieves these and cites them; it does not free-associate
security advice, because a model improvising firewall rules is a liability.

Entries are deliberately host-level and vendor-neutral. Anything that depends
on a specific distribution, orchestrator or EDR is left to the operator.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Playbook:
    technique: str
    name: str
    summary: str
    preconditions: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)
    telemetry: list[str] = field(default_factory=list)
    # Cheap, reversible things worth doing during a live incident, as opposed
    # to the structural controls above which are change-managed work.
    immediate: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "technique": self.technique, "name": self.name, "summary": self.summary,
            "preconditions": self.preconditions, "controls": self.controls,
            "telemetry": self.telemetry, "immediate": self.immediate,
        }

    def as_prompt(self) -> str:
        def block(label: str, items: list[str]) -> str:
            return f"{label}: " + "; ".join(items) if items else ""
        parts = [f"{self.technique} {self.name}. {self.summary}",
                 block("Attacker needs", self.preconditions),
                 block("Controls", self.controls),
                 block("Better telemetry", self.telemetry),
                 block("During the incident", self.immediate)]
        return "\n".join(p for p in parts if p)


PLAYBOOKS: dict[str, Playbook] = {

    "T1059": Playbook(
        technique="T1059",
        name="Command and scripting interpreter",
        summary=(
            "An attacker runs commands through a shell or interpreter that is already "
            "on the host. Nothing has to be dropped to disk, which is why this is the "
            "single most common execution technique and why 'no malware found' means "
            "very little on its own."
        ),
        preconditions=[
            "a process that can be made to call exec, usually a service parsing untrusted input",
            "a shell or interpreter reachable on PATH from that service's context",
            "no restriction on what the service account is allowed to execute",
        ],
        controls=[
            "run network-facing services under a dedicated account with a nologin shell",
            "use systemd hardening on the unit: NoNewPrivileges=yes, ProtectSystem=strict, "
            "PrivateTmp=yes, and RestrictSUIDSGID=yes",
            "where the service genuinely never needs to spawn children, add SystemCallFilter "
            "or a seccomp profile that denies execve outright - this is the control that "
            "actually ends the technique rather than making it noisier",
            "remove interpreters that are not needed from container images; a webserver "
            "image with python, perl, curl and nc in it is four extra ways to be exploited",
        ],
        telemetry=[
            "record the full process ancestry, not just the parent - attackers reparent to init",
            "log the service's request stream so a shell can be aligned to the request that caused it",
        ],
        immediate=[
            "capture the process's open sockets and file descriptors before it exits, because "
            "a shell that dies takes its remote peer with it",
            "SIGSTOP rather than SIGKILL if you want the memory image",
        ],
    ),

    "T1071": Playbook(
        technique="T1071",
        name="Application layer command and control",
        summary=(
            "Beaconing to an operator-controlled server over a protocol that looks ordinary, "
            "usually HTTPS or DNS. The give-away is rarely the destination - it is the "
            "regularity, because humans generate irregular traffic and schedulers do not."
        ),
        preconditions=[
            "unrestricted egress from the host to arbitrary destinations",
            "a protocol that survives the perimeter, which today means 443 and 53",
        ],
        controls=[
            "default-deny egress; allow-list the destinations a server actually needs, "
            "which for most backend hosts is a package mirror and a metrics endpoint",
            "force DNS through a resolver you control and log every query",
            "terminate TLS at an egress proxy for server subnets so destination and SNI are visible",
            "block direct outbound from database and application tiers entirely - they should "
            "reach the internet through a proxy or not at all",
        ],
        telemetry=[
            "measure inter-arrival jitter per destination rather than volume; low-and-slow "
            "beacons are invisible to byte-count thresholds but obvious to interval variance",
            "keep a first-seen timestamp per destination so new peers stand out from normal ones",
        ],
        immediate=[
            "null-route or firewall the peer before you touch the process, so the operator "
            "loses the channel before they notice they are being investigated",
            "preserve the peer address and port - it is the pivot into every other affected host",
        ],
    ),

    "T1543": Playbook(
        technique="T1543",
        name="Create or modify system process for persistence",
        summary=(
            "The attacker arranges to be restarted by the operating system - a systemd unit, "
            "an init script, a launch agent. Persistence is the step that turns an intrusion "
            "into an ongoing one, so this is where containment either holds or does not."
        ),
        preconditions=[
            "write access to a unit or init directory, which usually means root already",
            "no integrity monitoring on those directories",
        ],
        controls=[
            "put /etc/systemd, /etc/cron.d, /etc/init.d and the user equivalents under "
            "file integrity monitoring with alerting, not just logging",
            "ship units as read-only immutable image content and rebuild rather than edit",
            "audit for units whose ExecStart points outside package-managed paths",
        ],
        telemetry=[
            "alert on unit file creation, not modification alone - new is more suspicious than changed",
            "reconcile the enabled unit list against a known-good manifest on a schedule",
        ],
        immediate=[
            "enumerate every persistence location before removing any of them; attackers "
            "install several and removing one teaches them you are looking",
            "disable rather than delete first, so you keep the artefact for analysis",
        ],
    ),

    "T1053": Playbook(
        technique="T1053",
        name="Scheduled task or job",
        summary=(
            "Persistence and execution through cron, at, or systemd timers. Cheap for the "
            "attacker, and it survives reboots and process kills without any resident malware."
        ),
        preconditions=[
            "write access to a crontab, /etc/cron.d, or a timer unit",
        ],
        controls=[
            "restrict cron with cron.allow rather than cron.deny, so the default is no access",
            "monitor every crontab location including per-user ones under /var/spool/cron",
            "forbid interpreters and network tools in cron entries by policy and check it",
        ],
        telemetry=[
            "hash every cron file and alert on any change, including whitespace",
            "log the parent of every process whose ancestry includes cron",
        ],
        immediate=[
            "read the entry before deleting it; the command line is often the clearest "
            "single piece of evidence you will get about the operator's intent",
        ],
    ),

    "T1548": Playbook(
        technique="T1548",
        name="Abuse elevation control mechanism",
        summary=(
            "Getting from a service account to root using sudo rules, SUID binaries, or "
            "capabilities that were more generous than anyone realised."
        ),
        preconditions=[
            "a misconfigured sudoers entry, a SUID binary with a shell escape, or an "
            "over-broad file capability",
        ],
        controls=[
            "audit sudoers for NOPASSWD and for wildcards in command paths, which are "
            "almost always exploitable",
            "inventory SUID and SGID binaries and remove the bit from anything not required; "
            "compare against a known-good list on every build",
            "prefer file capabilities over SUID, and grant the narrowest capability that works",
        ],
        telemetry=[
            "alert on new SUID binaries appearing anywhere on the filesystem",
            "log every sudo invocation with the full command and the originating tty",
        ],
        immediate=[
            "assume any account that reached root is fully compromised, and rotate its "
            "credentials and keys rather than trying to clean it",
        ],
    ),

    "T1055": Playbook(
        technique="T1055",
        name="Process injection",
        summary=(
            "Running attacker code inside a legitimate process so that process listings, "
            "network attribution and allow-listing all point at something trusted."
        ),
        preconditions=[
            "ptrace or equivalent access to the target, which usually means same-user or root",
            "a target process with more privilege or more trust than the attacker's own",
        ],
        controls=[
            "set kernel.yama.ptrace_scope=1 at minimum, 2 or 3 on servers that never debug",
            "run services with SELinux or AppArmor confinement so cross-process access is denied "
            "by policy rather than by ownership",
            "drop CAP_SYS_PTRACE from every container that does not need a debugger",
        ],
        telemetry=[
            "watch for writes to /proc/<pid>/mem and for ptrace attach between unrelated services",
            "compare a process's mapped executable regions against its on-disk binary",
        ],
        immediate=[
            "dump the target's memory before stopping it; the injected code may exist nowhere else",
        ],
    ),

    "T1027": Playbook(
        technique="T1027",
        name="Obfuscated files or information",
        summary=(
            "Encoded, packed or otherwise disguised payloads. On its own this is weak evidence "
            "- build tooling encodes things constantly - but combined with anything else it "
            "raises confidence sharply, which is exactly what the correlator is for."
        ),
        preconditions=[
            "the ability to pass a long argument or write a file that something will decode",
        ],
        controls=[
            "block base64-to-interpreter pipelines at the policy layer where a shell is required at all",
            "constrain what your CI and deployment tooling is permitted to execute so the "
            "legitimate encoded traffic on the host is a known, small set",
        ],
        telemetry=[
            "score on argument entropy and length together rather than either alone",
            "keep an allow-list of the encoded command lines your own tooling produces, so "
            "the remainder is genuinely anomalous",
        ],
        immediate=[
            "decode in an isolated environment, never on the affected host",
        ],
    ),

    "T1070": Playbook(
        technique="T1070",
        name="Indicator removal",
        summary=(
            "Log truncation, history clearing, timestamp manipulation. This is the technique "
            "that tells you the operator is deliberate rather than automated, and it is the "
            "one that most damages your ability to investigate later."
        ),
        preconditions=[
            "write access to logs, which is why local-only logging is a design flaw",
        ],
        controls=[
            "ship logs off the host as they are written; a log that only exists locally is "
            "evidence the attacker controls",
            "make the local journal append-only where the platform supports it",
            "keep an authoritative time source so timestamp tampering is detectable",
        ],
        telemetry=[
            "alert on log file truncation and on any gap in a continuous log stream",
            "monitor shell history files for truncation as well as modification",
        ],
        immediate=[
            "stop relying on host-local evidence from this point; pivot to network and "
            "central log sources for the remainder of the investigation",
        ],
    ),

    "T1486": Playbook(
        technique="T1486",
        name="Data encrypted for impact",
        summary=(
            "Ransomware. The window between first encryption and total loss is minutes, which "
            "is the one case where autonomous containment is clearly worth its false positive cost."
        ),
        preconditions=[
            "broad write access across a filesystem or share",
            "enough time to walk directories before anyone reacts",
        ],
        controls=[
            "backups that the host cannot reach or delete, tested by actual restore",
            "least-privilege on shares so no single compromised host can reach everything",
            "canary files in each share that nothing legitimate ever touches",
        ],
        telemetry=[
            "alert on a single process's file-write rate and on entropy of written content",
            "watch for mass rename operations, which usually precede the ransom note",
        ],
        immediate=[
            "kill first and investigate afterwards - this is the exception to preserving state",
            "disconnect the host from storage before anything else",
        ],
    ),

    "T1496": Playbook(
        technique="T1496",
        name="Resource hijacking",
        summary=(
            "Cryptomining. Financially motivated, noisy, and frequently the only visible symptom "
            "of an intrusion whose real purpose was access. Treat it as evidence of a breach, "
            "not as a performance problem to be tuned away."
        ),
        preconditions=[
            "code execution and unrestricted egress to a mining pool",
        ],
        controls=[
            "CPU quotas per service unit so a miner cannot take the whole machine",
            "egress allow-listing, which blocks pool connections as a side effect",
        ],
        telemetry=[
            "sustained high CPU with low I/O is the signature; either alone is normal",
            "correlate CPU with a new outbound destination rather than alerting on CPU",
        ],
        immediate=[
            "find the initial access path before removing the miner, or it returns within hours",
        ],
    ),

    "T1046": Playbook(
        technique="T1046",
        name="Network service discovery",
        summary=(
            "Scanning from a host you already own, to find what else is reachable. Seeing this "
            "from a server means the attacker is past initial access and is choosing a next target."
        ),
        preconditions=[
            "east-west network reachability between hosts that have no business talking",
        ],
        controls=[
            "segment aggressively; application servers should not reach each other at all",
            "default-deny between tiers, enforced at the host firewall as well as the network",
        ],
        telemetry=[
            "count distinct destination ports and hosts per source over a short window",
            "connection failures are the stronger signal - scanning produces many refusals",
        ],
        immediate=[
            "assume every host the scanner could reach is now a target and check them too",
        ],
    ),

    "T1041": Playbook(
        technique="T1041",
        name="Exfiltration over C2 channel",
        summary=(
            "Data leaving over the same channel the attacker uses for control. By the time this "
            "fires the incident has a regulatory dimension as well as a technical one."
        ),
        preconditions=[
            "an established outbound channel and read access to something worth taking",
        ],
        controls=[
            "egress volume caps per host, which is crude but catches bulk transfer",
            "keep sensitive data off application hosts entirely where the architecture allows",
        ],
        telemetry=[
            "alert on outbound-to-inbound byte ratio inverting for a host, not on absolute volume",
        ],
        immediate=[
            "record the byte counts before you cut the connection - the volume transferred is "
            "the number every subsequent conversation will be about",
        ],
    ),
    "T1036": Playbook(
        technique="T1036",
        name="Masquerading",
        summary=(
            "Making malicious activity look routine - a binary named after a kernel thread, "
            "a process running from a path that resembles a system directory, an executable "
            "whose name and actual content disagree. It defeats eyeballing a process list, "
            "which is why the detectors compare name against path and parentage."
        ),
        preconditions=[
            "the ability to choose a filename or argv[0], which costs an attacker nothing",
            "an operator or tool that trusts process names as identity",
        ],
        controls=[
            "execute only from package-managed paths; deny exec on /tmp, /dev/shm and "
            "/var/tmp with noexec mount options, which removes the most common hiding place",
            "application allow-listing keyed on path and hash rather than on name",
            "keep world-writable directories off the execution path entirely",
        ],
        telemetry=[
            "compare the process name against the real path of its executable, and alert "
            "when a system-sounding name resolves somewhere unexpected",
            "hash running executables and reconcile against the package database",
        ],
        immediate=[
            "resolve /proc/<pid>/exe rather than trusting the name in the process list; "
            "a deleted binary shows as '(deleted)' and that alone is worth escalating",
        ],
    ),

    "T1068": Playbook(
        technique="T1068",
        name="Exploitation for privilege escalation",
        summary=(
            "Using a kernel or service vulnerability to gain privilege rather than abusing a "
            "misconfiguration. Less common than sudo and SUID abuse, and much harder to "
            "prevent by configuration, so patch latency is the control that matters."
        ),
        preconditions=[
            "an unpatched local privilege escalation vulnerability",
            "the ability to run code as any local user",
        ],
        controls=[
            "measure and shorten patch latency for the kernel specifically; most public "
            "local privilege escalation exploits target kernels months out of date",
            "enable kernel hardening that removes exploit primitives - kptr_restrict, "
            "unprivileged user namespaces disabled, dmesg_restrict",
            "confine services with SELinux or AppArmor so a successful exploit lands in a "
            "restricted domain rather than at unrestricted root",
        ],
        telemetry=[
            "watch for a process's effective uid changing without a corresponding setuid "
            "binary or sudo invocation in the record",
            "log kernel oops and segfault storms, which usually precede a working exploit",
        ],
        immediate=[
            "capture the kernel version and loaded modules before rebooting, then treat the "
            "whole host as untrusted and rebuild rather than clean",
        ],
    ),

    "T1082": Playbook(
        technique="T1082",
        name="System information discovery",
        summary=(
            "Reading kernel version, distribution, hardware and configuration. Nearly always "
            "the first thing an attacker does after landing, and nearly always indistinguishable "
            "from what a legitimate administrator does, so it is weak alone and useful in sequence."
        ),
        preconditions=["any code execution at all"],
        controls=[
            "there is no meaningful preventive control here, and pretending otherwise wastes "
            "effort; treat this as a sequencing signal rather than something to block",
            "reduce what discovery yields by keeping credentials and topology off the host",
        ],
        telemetry=[
            "value the sequence, not the event: discovery followed within minutes by an "
            "outbound connection or a new persistence entry is the pattern worth alerting on",
            "baseline which accounts normally run these commands, since service accounts do not",
        ],
        immediate=[
            "use the timestamp as the anchor for your timeline; discovery usually sits very "
            "close to initial access",
        ],
    ),

    "T1087": Playbook(
        technique="T1087",
        name="Account discovery",
        summary=(
            "Enumerating local or domain accounts to choose a target for escalation or lateral "
            "movement. Reading /etc/passwd is unremarkable on its own and revealing in context."
        ),
        preconditions=["read access to account stores, which is usually default"],
        controls=[
            "keep local accounts minimal so enumeration returns little of value",
            "no shared administrative accounts - individual accounts make enumeration output "
            "less useful and subsequent misuse attributable",
        ],
        telemetry=[
            "alert when a service account reads account stores, which it has no reason to do",
            "correlate enumeration with a subsequent authentication attempt as the same actor",
        ],
        immediate=[
            "assume every account visible to the attacker is now a target and prioritise "
            "rotating the privileged ones",
        ],
    ),

    "T1098": Playbook(
        technique="T1098",
        name="Account manipulation",
        summary=(
            "Adding an SSH key, changing a password, granting a group membership. This is "
            "persistence that survives every process kill and most rebuilds, and it is quiet, "
            "which makes it more dangerous than the noisier techniques above it."
        ),
        preconditions=[
            "write access to authorized_keys, shadow, or group membership",
        ],
        controls=[
            "centralise authentication so local account changes are anomalous by definition",
            "manage authorized_keys through configuration management and make the files "
            "read-only to the account that owns them",
            "disable password authentication for SSH entirely",
        ],
        telemetry=[
            "file integrity monitoring on every authorized_keys, including under home "
            "directories, with alerting rather than logging",
            "alert on group membership changes for privileged groups",
        ],
        immediate=[
            "enumerate all authorized_keys across every account before removing any, and "
            "compare against your configuration management's expected state",
        ],
    ),

    "T1105": Playbook(
        technique="T1105",
        name="Ingress tool transfer",
        summary=(
            "Pulling additional tooling onto the host after initial access - curl, wget, or a "
            "download inside an interpreter. It marks the transition from a foothold to an "
            "equipped one, and it needs egress, which is where you stop it."
        ),
        preconditions=[
            "outbound network access and a writable, executable directory",
        ],
        controls=[
            "default-deny egress, which stops this and command-and-control with one control",
            "mount /tmp, /var/tmp and /dev/shm noexec so a downloaded binary cannot run "
            "from where it lands",
            "remove curl, wget and package managers from production container images",
        ],
        telemetry=[
            "alert on a service account writing a file and then executing that same path",
            "record the source URL - it is usually attacker infrastructure reused elsewhere",
        ],
        immediate=[
            "hash the downloaded artefact and keep it before quarantining; it is the most "
            "shareable indicator you will produce from this incident",
        ],
    ),

    "T1136": Playbook(
        technique="T1136",
        name="Create account",
        summary=(
            "Adding a new local account for persistence. Blunt, easy to spot if you are "
            "watching, and entirely invisible if you are not, since nothing about a valid "
            "account looks wrong afterwards."
        ),
        preconditions=["root or an equivalent capability"],
        controls=[
            "centralised identity with local account creation disabled or alarmed",
            "reconcile the local account list against an expected manifest on a schedule",
        ],
        telemetry=[
            "file integrity monitoring on /etc/passwd, /etc/shadow and /etc/group",
            "alert on any account creation on a server, since the legitimate rate is zero",
        ],
        immediate=[
            "do not delete it immediately - record its uid, groups, shell and key material "
            "first, because those tie this host to the rest of the intrusion",
        ],
    ),

    "T1546": Playbook(
        technique="T1546",
        name="Event triggered execution",
        summary=(
            "Persistence that fires on an event rather than a schedule - a shell profile, an "
            "LD_PRELOAD entry, a udev rule. Subtler than cron and frequently missed during "
            "cleanup, which is how intrusions come back a week later."
        ),
        preconditions=[
            "write access to a profile, preload configuration, or trigger directory",
        ],
        controls=[
            "file integrity monitoring across shell profiles, /etc/ld.so.preload and udev rules",
            "make shell initialisation files immutable where the workflow allows it",
            "forbid LD_PRELOAD in service units with a clean environment",
        ],
        telemetry=[
            "alert on any change to ld.so.preload, which should never change outside a package update",
            "compare loaded libraries against the on-disk dependency list for long-running services",
        ],
        immediate=[
            "check every persistence location in this playbook and T1543 together; attackers "
            "install redundantly and a partial cleanup is worse than none",
        ],
    ),

    "T1562": Playbook(
        technique="T1562",
        name="Impair defenses",
        summary=(
            "Stopping the agent, flushing firewall rules, unloading audit rules. Treat any "
            "instance of this as confirmed intrusion rather than as an alert to be assessed - "
            "nothing legitimate turns your monitoring off by surprise."
        ),
        preconditions=[
            "privilege to control the security tooling, which usually means root",
        ],
        controls=[
            "run the agent under a service manager that restarts it and alarms on the restart",
            "alert on absence centrally: a host that stops reporting is an incident, and this "
            "is the single control that catches every variant of the technique",
            "make audit rules immutable at boot so they cannot be unloaded without a reboot",
        ],
        telemetry=[
            "heartbeat from every agent, with the alarm fired by the collector rather than "
            "the host, since a compromised host will not report its own silence",
        ],
        immediate=[
            "escalate rather than assess; move to network-derived evidence immediately "
            "because host telemetry from this point is not trustworthy",
        ],
    ),

    "T1571": Playbook(
        technique="T1571",
        name="Non-standard port",
        summary=(
            "Command and control or a listener on a port nobody expects. Weak on its own - "
            "development tooling does this constantly - and meaningful when the process, the "
            "user or the direction is also wrong."
        ),
        preconditions=[
            "the ability to bind or connect on an arbitrary port, meaning no egress or "
            "ingress filtering",
        ],
        controls=[
            "host firewall that allow-lists listening ports per service rather than per host",
            "egress allow-listing by port and destination together",
            "bind development and debug services to loopback rather than all interfaces",
        ],
        telemetry=[
            "keep an expected-listener manifest per host role and diff against it, which "
            "turns a noisy signal into a precise one",
            "note whether the socket is bound to loopback or a routable interface - the "
            "difference is most of the risk",
        ],
        immediate=[
            "identify the owning process and its parent before firewalling, so you contain "
            "the cause rather than the symptom",
        ],
    ),
}


# Advice that is not technique-specific. The assistant falls back to these when
# an incident carries no MITRE mapping at all, which happens with pure baseline
# and anomaly-model detections.
GENERAL: list[str] = [
    "Establish what normal looks like on this host before treating a deviation as an intrusion; "
    "the baseline detector needs its warmup samples for exactly this reason.",
    "Corroboration across independent detector families matters more than any single score. "
    "One rule firing hard is a lead. A rule, a baseline break and the anomaly model agreeing "
    "is an incident.",
    "Preserve volatile state before containment unless the technique is destructive. Sockets, "
    "file descriptors and memory disappear the moment the process does.",
    "Contain at the network before the process where you can - it removes the attacker's "
    "control without telling them you are there.",
]


def for_techniques(mitre: list[str]) -> list[Playbook]:
    seen, out = set(), []
    for t in mitre:
        pb = PLAYBOOKS.get(t)
        if pb and pb.technique not in seen:
            seen.add(pb.technique)
            out.append(pb)
    return out


def search(term: str) -> list[Playbook]:
    """Loose lookup so a question can name a technique, a word, or neither."""
    term = (term or "").strip().lower()
    if not term:
        return []
    hits = []
    for pb in PLAYBOOKS.values():
        haystack = " ".join([pb.technique, pb.name, pb.summary,
                             " ".join(pb.controls), " ".join(pb.preconditions)]).lower()
        if term in haystack:
            hits.append(pb)
    return hits
