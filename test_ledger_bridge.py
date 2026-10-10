"""test_ledger_bridge.py"""
import json
import os
import sqlite3
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger_bridge as LB
from janitor import Proc, classify

PASS = 0
FAIL = 0
def t(name, cond):
    global PASS, FAIL
    if cond: PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")

# --- tmp ledger with a spawning terminal call
tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "ledger.db")
con = sqlite3.connect(db)
con.execute("CREATE TABLE ledger (id INTEGER PRIMARY KEY, ts REAL, tool_name TEXT, args_json TEXT, status TEXT)")
now = time.time()
con.execute("INSERT INTO ledger (ts, tool_name, args_json, status) VALUES (?,?,?,?)",
            (now - 3 * 86400, "terminal",
             json.dumps({"command": "nohup ngrok http 7680 &"}), "ok"))
con.execute("INSERT INTO ledger (ts, tool_name, args_json, status) VALUES (?,?,?,?)",
            (now - 3600, "terminal", json.dumps({"command": "ls -la"}), "ok"))
con.commit(); con.close()

LB.LEDGER_CANDIDATES = [db]
calls = LB.terminal_calls(since_s=7 * 86400)
t("finds only spawn-like calls", len(calls) == 1 and "ngrok" in calls[0]["command"])

attr = LB.attribution("/usr/local/bin/ngrok http 7680 --url=x", calls)
t("attribution matches ngrok", attr.get("spawned_by_command", "") == "nohup ngrok http 7680 &")
t("attribution age ~3 days", abs(attr.get("spawn_age_days", 0) - 3.0) < 0.1)
t("attribution has ledger source", attr.get("source") == "agent-ledger ledger.db")

# --- no match for unrelated process
t("no attribution for tail", LB.attribution("tail -f /var/log/syslog", calls) == {})

# --- missing ledger → silent empty
LB.LEDGER_CANDIDATES = ["/nonexistent/ledger.db"]
t("missing db → no calls", LB.terminal_calls() == [])

# --- corrupt db → silent empty
bad = os.path.join(tmp, "bad.db")
open(bad, "w").write("not a database at all")
LB.LEDGER_CANDIDATES = [bad]
t("corrupt db → no calls", LB.terminal_calls() == [])

# --- attribution enriches classify output end-to-end
LB.LEDGER_CANDIDATES = [db]
p = Proc(pid=os.getpid(), cmd="/usr/local/bin/ngrok http 7680", ppid=1, uid=1000,
         start_ts=0, uptime_s=9 * 86400, ports=[], parent_alive=False)
p = classify(p, ttl_s=6 * 3600)
a = LB.attribution(p.cmd, calls)
t("e2e: orphaned ngrok confirmed", p.confidence == "confirmed")
t("e2e: attribution attached", "ngrok" in a.get("spawned_by_command", ""))

print("========================================")
print(f"PASS {PASS} / FAIL {FAIL}")
print("RESULT: PASS ✅" if FAIL == 0 else "RESULT: FAIL ❌")
sys.exit(0 if FAIL == 0 else 1)
