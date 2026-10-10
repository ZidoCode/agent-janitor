"""test_janitor.py — unit tests for classification & sweep logic."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from janitor import Proc, classify, sweep_candidates, DEV_TRAITS, EXEMPT

PASS = 0
FAIL = 0
def t(name, cond):
    global PASS, FAIL
    if cond: PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")

def mk(cmd, ppid=100, parent_alive=True, ports=None, uptime=7200):
    return Proc(pid=os.getpid(), cmd=cmd, ppid=ppid, uid=1000,
                start_ts=0, uptime_s=uptime, ports=ports or [],
                parent_alive=parent_alive)

TTL = 6 * 3600

# --- confirmed: orphan + port
p = classify(mk("node /app/server.js", parent_alive=False, ports=[3000]), TTL)
t("orphan+port = confirmed", p.confidence == "confirmed")
t("signals mention port", any("3000" in s for s in p.signals))

# --- confirmed: orphan + dev traits
p = classify(mk("npm run dev", parent_alive=False), TTL)
t("orphan+dev traits = confirmed", p.confidence == "confirmed")

# --- likely: orphan, no dev evidence
p = classify(mk("my-custom-binary --serve", parent_alive=False), TTL)
t("orphan only = likely", p.confidence == "likely")

# --- possible: strong traits + TTL exceeded but parent alive
p = classify(mk("vite", parent_alive=True, ports=[5173], uptime=7 * 3600), TTL)
t("dev traits + TTL, parent alive = possible", p.confidence == "possible")

# --- clean: young dev server with live parent
p = classify(mk("vite", parent_alive=True, uptime=120), TTL)
t("young + parent alive = no flag", p.confidence == "")

# --- clean: system exempt even if orphaned with port
p = classify(mk("sshd -D", parent_alive=False, ports=[22]), TTL)
t("system exempt (sshd)", p.confidence == "")

# --- whitelist beats everything
p = classify(mk("python api.py", parent_alive=False, ports=[8000]), TTL,
             whitelist=["api\\.py"])
t("whitelisted = no flag", p.confidence == "")

# --- dev traits regex sanity
for c in ["vite", "uvicorn main:app", "ngrok http 80", "cloudflared tunnel",
          "python -m http.server 8000", "nodemon index.js"]:
    t(f"dev trait match: {c}", bool(DEV_TRAITS.search(c)))
for c in ["vim notes.txt", "tail -f log", "grep foo bar"]:
    t(f"no dev trait: {c}", not DEV_TRAITS.search(c))

# --- exempt regex sanity
for c in ["nginx: master", "postgres: writer", "systemd --user", "ttys"]:
    t(f"exempt: {c}", bool(EXEMPT.search(c)))
t("exempt does not match vite", not EXEMPT.search("vite"))

# --- sweep list excludes 'possible'
procs = [classify(mk("node a.js", parent_alive=False, ports=[1]), TTL),
         classify(mk("vite", parent_alive=True, uptime=9 * 3600, ports=[2]), TTL),
         classify(mk("tail -f", parent_alive=True, uptime=9 * 3600), TTL)]
cands = sweep_candidates(procs)
t("sweep only confirmed+likely", len(cands) == 1 and cands[0].cmd.startswith("node"))

print(f"========================================")
print(f"PASS {PASS} / FAIL {FAIL}")
print("RESULT: PASS ✅" if FAIL == 0 else "RESULT: FAIL ❌")
sys.exit(0 if FAIL == 0 else 1)
