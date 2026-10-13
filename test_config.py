#!/usr/bin/env python3
"""test_config.py — whitelist/policy config loading, edge cases included.

Covers the config surface Muse flagged: whitelist from file, empty file,
duplicates, malformed JSON, missing file, and the enforce-mode gate.
All paths redirected to a temp dir — never touches real config.
"""
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
results = []


def check(name, ok):
    results.append((name, ok))


def load_cli(env):
    """Import janitor_cli fresh, then point its paths at env dir.

    Paths must be patched AFTER exec_module — the module body recomputes
    them from expanduser at import time.
    """
    spec = importlib.util.spec_from_file_location(
        f"janitor_cli_{id(env)}", os.path.join(HERE, "janitor_cli.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.DATA_DIR = env
    mod.WHITELIST_PATH = os.path.join(env, "whitelist.json")
    mod.MODE_PATH = os.path.join(env, "policy_mode")
    mod.HISTORY_PATH = os.path.join(env, "sweeps.jsonl")
    return mod


env = tempfile.mkdtemp()
os.makedirs(env, exist_ok=True)

# 1. missing file → empty whitelist, no crash
cli = load_cli(env)
check("config: missing file → empty list", cli.load_whitelist() == [])

# 2. empty JSON list
with open(cli.WHITELIST_PATH, "w") as f:
    json.dump([], f)
check("config: empty list file → empty list", cli.load_whitelist() == [])

# 3. normal load + roundtrip
cli.save_whitelist(["ngrok", "cloudflared"])
check("config: roundtrip", cli.load_whitelist() == ["ngrok", "cloudflared"])

# 4. duplicates preserved by loader (dedupe is classifier's job — here:
#    loader must not crash); save/load identical
cli.save_whitelist(["a", "a", "b"])
check("config: duplicates load without crash",
      cli.load_whitelist() == ["a", "a", "b"])

# 5. malformed JSON → empty list, never crash
with open(cli.WHITELIST_PATH, "w") as f:
    f.write("{not json")
check("config: malformed JSON → empty list", cli.load_whitelist() == [])

# 6. whitelist applied in scan(): whitelisted cmd gets no signals
from janitor import classify, Proc, scan_procs  # noqa: E402
p = Proc(pid=99999, cmd="ngrok http 8080", ppid=1, uid=os.getuid(),
         start_ts=0.0, uptime_s=99999, ports=[8080])
classify(p, ttl_s=3600, whitelist=["ngrok"])
check("config: whitelisted process gets zero signals",
      p.signals == [] and p.confidence == "")

# 7. non-whitelisted same process IS flagged
p2 = Proc(pid=99998, cmd="notmytool http 8080", ppid=1, uid=os.getuid(),
          start_ts=0.0, uptime_s=99999, ports=[8080])
classify(p2, ttl_s=3600, whitelist=["ngrok"])
check("config: non-whitelisted flagged", p2.confidence == "confirmed")

# 8. enforce gate: default (no file) is dry_run
check("config: default mode is dry_run", cli.mode() == "dry_run")
check("config: enforce not allowed by default", not cli.enforce_allowed())

# 9. enforce mode file flips the gate
with open(cli.MODE_PATH, "w") as f:
    f.write("enforce")
check("config: enforce file → gate open", cli.enforce_allowed())

# 10. garbage mode value → treated as dry_run
with open(cli.MODE_PATH, "w") as f:
    f.write("yolo")
check("config: unknown mode ≠ enforce", not cli.enforce_allowed())

passed = sum(1 for _, ok in results if ok)
for name, ok in results:
    print(("PASS  " if ok else "FAIL  ") + name)
print(f"RESULT: {'PASS ✅' if passed == len(results) else 'FAIL ❌'} "
      f"({passed}/{len(results)})")
sys.exit(0 if passed == len(results) else 1)
