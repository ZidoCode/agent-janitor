"""janitor.py — agent-janitor core: find processes the agent left behind.

Design:
- Zero non-stdlib deps. Linux-first (reads /proc), falls back to `ps` elsewhere.
- Detection = signals, never blanket kill. A process is flagged when it has
  accumulating evidence: dead parent, port listener, dev-server traits,
  uptime beyond a TTL, or a match against the ledger of a process-spawning
  tool call (when agent-ledger is installed alongside).
- DRY_RUN everywhere by default. Nothing dies without an explicit
  policy_mode=enforce opt-in (free — same trust model as agent-ledger v0.4+).
"""
import os
import re
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field

# commands that smell like a dev/agent-spawned server or worker
DEV_TRAITS = re.compile(
    r"(vite|next dev|webpack|nodemon|ts-node|tsx |uvicorn|flask run|"
    r"gunicorn|python .*http\.server|python -m http|node .*server|"
    r"ngrok|cloudflared|npm run dev|yarn dev|pnpm dev|jupyter|"
    r"watchexec|air |live-server|php -S|rails s|python .*app\.py)",
    re.I,
)

# processes that are never suspects (system plumbing)
EXEMPT = re.compile(
    r"(systemd|kubelet|sshd|dbus|cron|rsyslog|polkit|snapd|"
    r"containerd|dockerd|nginx|apache|postgres|mysqld|redis-server|"
    r"(^|[\s/])(zsh|bash|sh|fish|ash|dash)$)",
)

# ppid=1 daemons that are standard systemd boot services, not agent orphans.
# Matched only when reparented to init — a user process with a live parent
# running these names is NOT exempt (e.g. dev-installed postgres).
SYSTEM_DAEMON = re.compile(
    r"(multipathd|envd|networkd-dispatcher|udisksd|ModemManager|"
    r"unattended-upgr|systemd-(resolve|logind|udevd|journald|timesyncd)|"
    r"agetty|qemu-ga|acpid|irqbalance|thermald|upower|accounts-daemon|"
    r"wpa_supplicant|cupsd|bluetoothd|chronyd|ntpd|rsync|plymouthd|"
    r"packagekitd|switcheroo-control|polkitd|power-profiles-daemon)"
)


@dataclass
class Proc:
    pid: int
    cmd: str
    ppid: int
    uid: int
    start_ts: float          # boot-relative seconds, from /proc stat field 22
    uptime_s: float          # wall-clock seconds alive
    ports: list = field(default_factory=list)
    parent_alive: bool = True
    signals: list = field(default_factory=list)
    confidence: str = ""     # "confirmed" | "likely" | "possible"


def _boot_time() -> float:
    with open("/proc/stat") as f:
        for line in f:
            if line.startswith("btime "):
                return float(line.split()[1])
    return 0.0


def _ports_of(pid: int) -> list:
    """TCP listen ports held by pid.

    /proc/net/tcp gives (inode, uid, ...) columns — uid is col 7, NOT pid.
    Correct mapping: read /proc/<pid>/fd/* symlinks for socket:[inode],
    then match those inodes against LISTEN entries in /proc/net/tcp.
    """
    inodes = set()
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
                if target.startswith("socket:["):
                    inodes.add(target[8:-1])
            except OSError:
                continue
    except OSError:
        return []
    if not inodes:
        return []
    ports = set()
    try:
        with open("/proc/net/tcp") as f:
            next(f)
            for line in f:
                p = line.split()
                if p[3] != "0A":          # 0A = LISTEN
                    continue
                inode = p[9]
                if inode in inodes:
                    ports.add(int(p[1].split(":")[1], 16))
    except (OSError, IndexError, ValueError):
        pass
    return sorted(ports)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return os.path.exists(f"/proc/{pid}")


def scan_procs(min_uptime_s: int = 60) -> list:
    """Snapshot every user-space process with derived signals."""
    btime = _boot_time()
    now = time.time()
    hermes_uid = os.getuid()
    out = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/stat") as f:
                stat = f.read()
            # comm may contain spaces/parens — split after last ')'
            rest = stat[stat.rindex(")") + 2:].split()
            comm = stat[stat.index("(") + 1:stat.rindex(")")]
            ppid = int(rest[1])
            starttick = int(rest[19])
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
            with open(f"/proc/{pid}/status") as f:
                st = f.read()
            uid = int(re.search(r"\nUid:\s+(\d+)", st).group(1))
        except (OSError, ValueError, AttributeError):
            continue
        if not cmd or pid == os.getpid():
            continue
        hz = os.sysconf("SC_CLK_TCK")
        start_ts = btime + starttick / hz
        out.append(Proc(pid=pid, cmd=cmd, ppid=ppid, uid=uid,
                        start_ts=start_ts, uptime_s=now - start_ts,
                        ports=_ports_of(pid), parent_alive=_alive(ppid)))
    out.sort(key=lambda p: p.pid)
    return [p for p in out if p.uptime_s >= min_uptime_s]


def classify(proc: Proc, ttl_s: int = 6 * 3600, whitelist: list = None) -> Proc:
    """Attach signals + confidence tier. Never mutates anything."""
    whitelist = whitelist or []
    wl = re.compile("|".join(re.escape(w) for w in whitelist)) if whitelist else None
    if wl and wl.search(proc.cmd):
        return proc  # whitelisted → no signals, never swept

    if EXEMPT.search(proc.cmd):
        return proc

    sig = proc.signals
    # Linux reparents orphans to a living ancestor (init/subreaper), so
    # parent_alive is almost always True. The reliable orphan signature is
    # ppid == 1 (init) combined with what the process IS, not who owns it.
    # BUT: system daemons also live at ppid=1 since boot (multipathd,
    # udisksd, ModemManager...). They are not agent orphans — they are
    # standard systemd daemons. Exempt them by name before flagging.
    reparented = proc.ppid == 1
    if reparented and SYSTEM_DAEMON.search(proc.cmd):
        return proc  # standard system daemon — never a suspect
    if reparented:
        sig.append(f"reparented to init (ppid=1)")
    if proc.ports:
        sig.append(f"holds port(s) {proc.ports}")
    if DEV_TRAITS.search(proc.cmd):
        sig.append("dev/server command traits")
    if proc.uptime_s > ttl_s:
        sig.append(f"uptime {int(proc.uptime_s)}s exceeds TTL {ttl_s}s")

    orphan = reparented or not proc.parent_alive
    strong = bool(proc.ports) or bool(DEV_TRAITS.search(proc.cmd))
    long_lived = proc.uptime_s > ttl_s
    # confirmed: reparented + evidence of server-ish purpose, or reparented
    # + long-lived (nobody is coming back for it)
    if orphan and (strong or long_lived):
        proc.confidence = "confirmed"
    elif orphan:
        proc.confidence = "likely"
    elif strong and long_lived:
        proc.confidence = "possible"   # alive long but parent alive → cautious
    return proc


def sweep_candidates(procs: list) -> list:
    """Only confirmed + likely are killable, same policy as portreaper."""
    return [p for p in procs if p.confidence in ("confirmed", "likely")]


def kill_process(pid: int) -> dict:
    """SIGTERM → 2s grace → SIGKILL, with PID-reuse verification."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd_before = f.read().replace(b"\x00", b" ").decode(errors="replace")
    except OSError:
        return {"pid": pid, "result": "already gone"}
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not _alive(pid):
                return {"pid": pid, "result": "terminated (SIGTERM)"}
            time.sleep(0.1)
        # PID-reuse race: confirm /proc/<pid> still the SAME process before -9
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd_now = f.read().replace(b"\x00", b" ").decode(errors="replace")
            if cmd_now != cmd_before:
                return {"pid": pid, "result": "aborted — PID reused by another process"}
        except OSError:
            return {"pid": pid, "result": "terminated (exited during grace)"}
        os.kill(pid, signal.SIGKILL)
        return {"pid": pid, "result": "killed (SIGKILL)"}
    except ProcessLookupError:
        return {"pid": pid, "result": "already gone"}
    except PermissionError:
        return {"pid": pid, "result": "permission denied"}


def scan(ttl_s: int = 6 * 3600, whitelist: list = None, min_uptime_s: int = 60) -> dict:
    procs = [classify(p, ttl_s, whitelist) for p in scan_procs(min_uptime_s)]
    flagged = [p for p in procs if p.confidence in ("confirmed", "likely", "possible")]
    return {
        "scanned": len(procs),
        "flagged": [
            {"pid": p.pid, "cmd": p.cmd, "ppid": p.ppid, "uptime_s": int(p.uptime_s),
             "ports": p.ports, "signals": p.signals, "confidence": p.confidence}
            for p in sorted(flagged, key=lambda x: (x.confidence != "confirmed",
                                                    x.confidence != "likely",
                                                    -x.uptime_s))
        ],
    }
