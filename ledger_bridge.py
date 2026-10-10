"""ledger_bridge.py — optional context from agent-ledger's ledger DB.

If agent-ledger is installed and its ledger.db exists, we can answer the
question no orphan-killer can: *which agent session spawned this command,
when, and did anything ever come back to check on it?*

Read-only (mode=ro). Fails silent → janitor still works standalone.
"""
import json
import os
import sqlite3
import time

LEDGER_CANDIDATES = [
    os.path.expanduser("~/.hermes/agent-ledger/ledger.db"),
    os.path.expanduser("~/.hermes/plugins/agent-ledger/ledger.db"),
]

SPAWN_PATTERN = __import__("re").compile(
    r"(nohup|&\s*$|tmux new|setsid|systemd-run|\.serve|dev server|uvicorn|"
    r"vite|next dev|npm run dev|ngrok|cloudflared)", __import__("re").I)


def find_ledger() -> str:
    for p in LEDGER_CANDIDATES:
        if os.path.exists(p):
            return p
    return ""


def terminal_calls(since_s: int = 14 * 86400, limit: int = 500) -> list:
    """Recent terminal tool calls that look like they spawn background work."""
    db = find_ledger()
    if not db:
        return []
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        cur = con.execute(
            "SELECT ts, tool_name, args_json FROM ledger "
            "WHERE tool_name LIKE '%terminal%' AND ts >= ? "
            "ORDER BY id DESC LIMIT ?", (time.time() - since_s, limit))
        rows = cur.fetchall()
        con.close()
    except (sqlite3.Error, OSError):
        return []
    out = []
    for ts, tool, args_json in rows:
        try:
            cmd = (json.loads(args_json).get("command") or "") if args_json else ""
        except (ValueError, TypeError):
            cmd = ""
        if cmd and SPAWN_PATTERN.search(cmd):
            try:
                tsf = float(ts)
            except (TypeError, ValueError):
                try:
                    from datetime import datetime
                    tsf = datetime.fromisoformat(str(ts)).timestamp()
                except ValueError:
                    continue
            out.append({"ts": tsf, "command": cmd})
    return out


def attribution(proc_cmd: str, calls: list) -> dict:
    """Fuzzy-match a live process command against ledger terminal calls."""
    best = None
    parts = proc_cmd.split()
    proc_key = parts[0] if parts else proc_cmd
    basename = os.path.basename(proc_key)
    for c in calls:
        # match on basename (ngrok) OR full path — ledger may store either
        if basename and basename in c["command"]:
            if best is None or c["ts"] > best["ts"]:
                best = c
    if not best:
        return {}
    age = time.time() - best["ts"]
    return {"spawned_by_command": best["command"],
            "spawned_at_ts": best["ts"],
            "spawn_age_days": round(age / 86400, 1),
            "source": "agent-ledger ledger.db"}
