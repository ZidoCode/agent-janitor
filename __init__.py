"""agent-janitor — process hygiene plugin for Hermes Agent.

Finds and (optionally) reaps background processes the agent left behind.
Ledger-aware (uses agent-ledger's ledger.db when present), DRY_RUN by
default, whitelist-first. See README.md for the trust model and limits.

Storage follows the active Hermes profile via get_hermes_home() —
never a hardcoded hermes home.
"""
import json
import os
import re
import time

__version__ = "0.1.0"

_SPAWN_RE = re.compile(
    r"(nohup|&\s*$|tmux new|setsid|systemd-run|disown|"
    r"vite|next dev|npm run dev|yarn dev|uvicorn|gunicorn|"
    r"ngrok|cloudflared|serve|http\.server|watchexec)", re.I)


def _home():
    """Active Hermes home (profile-aware), with a safe fallback."""
    try:
        from hermes_constants import get_hermes_home
        return str(get_hermes_home())
    except Exception:
        # fallback mirrors hermes_constants default; profile-aware when
        # running inside Hermes, plain home otherwise
        return os.path.join(os.path.expanduser("~"), ".hermes")


def data_dir() -> str:
    """Plugin data dir under the active profile's hermes home."""
    d = os.path.join(_home(), "plugin-data", "agent-janitor")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def _record_spawn(cmd: str):
    try:
        entry = {"ts": time.time(), "command": cmd[:300]}
        with open(os.path.join(data_dir(), "spawns.jsonl"), "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # janitor never breaks the agent over its own bookkeeping


def on_post_tool_call(tool_name: str = "", args: dict = None, result=None,
                      session_id: str = "", tool_call_id: str = "",
                      **kwargs) -> None:
    """Watch terminal calls; log ones that likely leave a process behind."""
    try:
        if "terminal" not in (tool_name or "").lower():
            return
        cmd = (args or {}).get("command") or ""
        if cmd and _SPAWN_RE.search(cmd):
            _record_spawn(cmd)
    except Exception:
        pass  # observers must never crash the observed


def register(ctx):
    """Hermes plugin entry point — hook registration via ctx API."""
    try:
        ctx.register_hook("post_tool_call", on_post_tool_call)
    except Exception:
        pass  # fail open: registration problems must not break the agent
    return {"hooks": ["post_tool_call"]}
