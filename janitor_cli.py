#!/usr/bin/env python3
"""janitor_cli.py — CLI + daily report for agent-janitor.

    python3 janitor_cli.py scan                 # show flagged processes
    python3 janitor_cli.py scan --json          # machine-readable
    python3 janitor_cli.py report               # human report (Telegram-style)
    python3 janitor_cli.py sweep --dry-run      # what WOULD be killed (default)
    python3 janitor_cli.py sweep                # actually kill (confirmed+likely)
    python3 janitor_cli.py whitelist add ngrok  # never suspect 'ngrok'

Safety model (mirrors agent-ledger):
- sweep without --dry-run requires ~/.hermes/agent-janitor/policy_mode = enforce
- in dry-run mode: print + record, never kill
- whitelist lives in ~/.hermes/agent-janitor/whitelist.json
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from janitor import scan, sweep_candidates, kill_process          # noqa: E402
from ledger_bridge import terminal_calls, attribution             # noqa: E402

def _hermes_home() -> str:
    """Active Hermes home (profile-aware), with a safe fallback."""
    try:
        from hermes_constants import get_hermes_home
        return str(get_hermes_home())
    except Exception:
        return os.path.join(os.path.expanduser("~"), ".hermes")


DATA_DIR = os.path.join(_hermes_home(), "plugin-data", "agent-janitor")
WHITELIST_PATH = os.path.join(DATA_DIR, "whitelist.json")
MODE_PATH = os.path.join(DATA_DIR, "policy_mode")
HISTORY_PATH = os.path.join(DATA_DIR, "sweeps.jsonl")


def load_whitelist() -> list:
    try:
        with open(WHITELIST_PATH) as f:
            # guard: a "" (or whitespace) entry would join into an empty
            # regex alternation and silently exempt EVERY process — drop it
            items = json.load(f)
            if not isinstance(items, list):
                return []
            return [w for w in items if isinstance(w, str) and w.strip()]
    except (OSError, ValueError):
        return []


def save_whitelist(items: list):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(WHITELIST_PATH, "w") as f:
        json.dump(items, f, indent=1)


def mode() -> str:
    try:
        return open(MODE_PATH).read().strip() or "dry_run"
    except OSError:
        return "dry_run"


def enforce_allowed() -> bool:
    """Enforce kill mode requires explicit opt-in — same gate as ledger pro
    will add. For now: file-based, no silent destruction ever."""
    return mode() == "enforce"


def record(entry: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(HISTORY_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def do_scan(ttl_s: int, as_json: bool) -> str:
    wl = load_whitelist()
    r = scan(ttl_s=ttl_s, whitelist=wl)
    calls = terminal_calls()
    for f in r["flagged"]:
        f["attribution"] = attribution(f["cmd"], calls)
    if as_json:
        return json.dumps(r, indent=1)
    lines = [f"scanned {r['scanned']} processes, {len(r['flagged'])} flagged:"]
    for f in r["flagged"]:
        lines.append(
            f"[{f['confidence']:9}] pid={f['pid']} up={f['uptime_s']}s "
            f"ports={f['ports']} :: {f['cmd'][:60]}")
        for s in f["signals"]:
            lines.append(f"             - {s}")
        a = f.get("attribution")
        if a:
            lines.append(f"             ledger: spawned by `{a['spawned_by_command'][:50]}` "
                         f"({a['spawn_age_days']}d ago)")
    return "\n".join(lines)


def do_sweep(ttl_s: int, dry: bool) -> str:
    wl = load_whitelist()
    r = scan(ttl_s=ttl_s, whitelist=wl)
    cands = sweep_candidates(r["flagged"] and
                             [type("P", (), {"pid": f["pid"], "cmd": f["cmd"],
                                             "confidence": f["confidence"]})()
                              for f in r["flagged"]])
    if not cands:
        return "nothing to sweep — box is clean ✨"
    lines = []
    enforced = enforce_allowed() and not dry
    for c in cands:
        if enforced:
            res = kill_process(c.pid)
            lines.append(f"KILLED pid={c.pid} {c.cmd[:50]} → {res['result']}")
            record({"ts": time.time(), "pid": c.pid, "cmd": c.cmd,
                    "mode": "enforce", "result": res["result"]})
        else:
            lines.append(f"WOULD KILL pid={c.pid} {c.cmd[:50]} "
                         f"[{c.confidence}] (dry-run; mode={mode()})")
            record({"ts": time.time(), "pid": c.pid, "cmd": c.cmd,
                    "mode": "dry_run", "result": "would_kill"})
    if not enforced:
        lines.append("dry-run only — set policy_mode=enforce to actually kill")
    return "\n".join(lines)


def main():
    args = sys.argv[1:]
    ttl = 6 * 3600
    if "--ttl-h" in args:
        i = args.index("--ttl-h"); ttl = int(args[i + 1]) * 3600
        del args[i:i + 2]
    cmd = args[0] if args else "report"
    if cmd == "scan":
        print(do_scan(ttl, "--json" in args))
    elif cmd == "report":
        print(do_scan(ttl, as_json=False))
    elif cmd == "sweep":
        print(do_sweep(ttl, dry=not enforce_allowed() or "--dry-run" in args))
    elif cmd == "whitelist" and len(args) >= 2:
        wl = load_whitelist()
        if args[1] == "add" and len(args) >= 3:
            wl.append(args[2]); save_whitelist(wl)
            print(f"whitelisted: {args[2]}")
        elif args[1] == "list":
            print(json.dumps(wl, indent=1))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
