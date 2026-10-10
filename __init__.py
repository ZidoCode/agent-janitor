"""agent-janitor — process hygiene plugin for Hermes Agent.

Finds and (optionally) reaps background processes the agent left behind.
Ledger-aware (uses agent-ledger's ledger.db when present), DRY_RUN by
default, whitelist-first. See README.md for the trust model and limits.
"""
import json
import os
import re
import subprocess
import time

__version__ = "0.1.0"

DATA_DIR = os.path.expanduser("~/.hermes/agent-janitor")
SPAWN_LOG = os.path.join(DATA_DIR, "spawns.jsonl")
# tool calls that look like they leave something running afterwards
_SPAWN_RE = re.compile(
    r"(nohup|&\s*$|tmux new|setsid|systemd-run|disown|"
    r"vite|next dev|npm run dev|yarn dev|uvicorn|gunicorn|"
    r"ngrok|cloudflared|serve|http\.server|watchexec)", re.I)


def _record_spawn(cmd: str):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        entry = {"ts": time.time(), "command": cmd[:300]}
        with open(SPAWN_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # janitor never breaks the agent over its own bookkeeping


def on_post_tool_call(tool_name: str, args: dict, result=None,
                      session_id: str = "", tool_call_id: str = "") -> None:
    """Watch terminal calls; log ones that likely leave a process behind."""
    try:
        if "terminal" not in (tool_name or "").lower():
            return
        cmd = (args or {}).get("command") or ""
        if cmd and _SPAWN_RE.search(cmd):
            _record_spawn(cmd)
    except Exception:
        pass  # observers must never crash the observed


def register(info):
    """Hermes plugin entry point — capability hooks registration."""
    return {
        "hooks": {
            "post_tool_call": on_post_tool_call,
        },
    }
