# agent-janitor 🧹

**Your agent never cleans up after itself. This does the accounting.**

Agent tools (Hermes, Claude Code, OpenCode…) spawn background processes —
dev servers, tunnels, watchers, `nohup` experiments — and then the session
ends and nobody remembers. Weeks later: dead ports, leaked RAM, OOM at 2am,
or worse (the *"I left my self-hosted agent box and it OOM'd three times"*
genre of blog post is now a genre).

Existing orphan-killers (portreaper, clean-orphans, killport) are reactive
one-shots with no memory. **agent-janitor is the accountability layer:**

- **Signals, not vibes** — a process is flagged by evidence (dead parent,
  port listener, dev-server traits, TTL exceeded), never blanket-killed
- **Ledger-aware** *(optional)* — if [agent-ledger](https://github.com/ZidoCode/agent-ledger)
  is installed, janitor reads its ledger and answers what nothing else can:
  *"this ngrok was spawned by this exact command, N days ago"* — no other
  tool has that context
- **DRY_RUN by default** — sweep only kills with explicit `policy_mode=enforce`;
  dry-run records `would_kill` entries so you can review before trusting it
- **Whitelist first-class** — `janitor whitelist add ngrok` and your real
  infrastructure is never flagged again
- 100% local, stdlib-only, Linux (`/proc`), no daemon required

## Quick start

```bash
git clone https://github.com/ZidoCode/agent-janitor ~/.hermes/plugins/agent-janitor

python3 ~/.hermes/plugins/agent-janitor/janitor_cli.py scan
python3 ~/.hermes/plugins/agent-janitor/janitor_cli.py whitelist add cloudflared
python3 ~/.hermes/plugins/agent-janitor/janitor_cli.py sweep --ttl-h 6   # dry-run
```

## Configuration

All state lives under `<hermes-home>/plugin-data/agent-janitor/` and follows
the **active Hermes profile** (via `get_hermes_home()`):

| File | Purpose | Default |
|---|---|---|
| `whitelist.json` | JSON array of command substrings never flagged | `[]` |
| `policy_mode` | File whose content must be exactly `enforce` to allow kills | absent → dry-run |
| `spawns.jsonl` | Append-only log of spawn-y terminal calls (hook) | auto |
| `sweeps.jsonl` | Audit trail of every sweep decision (`would_kill` / killed) | auto |

**Whitelist** — a JSON array you can edit by hand or grow via the CLI:

```json
["ngrok", "cloudflared", "tmux", "my-postgres-dev"]
```

Substrings match anywhere in the process command line (case-sensitive,
regex-escaped — no injection). Empty array / missing file = nothing is
whitelisted. Duplicates are harmless.

**Enforce gate** — `echo enforce > policy_mode` is the *only* way a sweep
ever kills anything. Any other value (or no file) = dry-run: decisions are
printed and logged as `would_kill`, nothing dies.

## Signal → confidence model

| Evidence | Tier |
|---|---|
| reparented to init (ppid=1) + holds port / dev traits / TTL exceeded | **confirmed** |
| reparented to init (ppid=1) only | **likely** |
| dev traits + TTL exceeded, parent alive | **possible** (never auto-swept) |

Linux reparents orphans to a living ancestor, so `ppid == 1` is the reliable
orphan signature — combined with evidence the process has server-like purpose
or nobody has reaped it for a long time. Only **confirmed + likely** are
killable. System daemons that legitimately live at ppid=1 (multipathd,
udisksd, ModemManager, systemd-*…) are exempt by name. Whitelisted commands
are never suspects — add your real infrastructure there:

```bash
janitor whitelist add ngrok        # your intentional long-runners
janitor whitelist add cloudflared
janitor whitelist add tmux
```

## Why these numbers

- **TTL 6 hours** — a dev server the agent is actively using lives for
  minutes; anything running past 6h with ppid=1 was almost certainly
  detached on purpose and forgotten. Shorter TTLs sweep legitimate
  long-running builds; longer ones let real zombies accumulate. Tunable
  per sweep via `--ttl-h`.
- **min uptime 60 s** — filters boot-time noise and short-lived subprocesses
  mid-flight; an orphan older than a minute is one.
- **SIGTERM → 2 s → SIGKILL, with PID-reuse check** — before the `kill -9`,
  the process's cmdline is re-read; if it changed (PID recycled), the kill
  is aborted. No PID-reuse fratricide.

## Threat model

What agent-janitor defends against, and what it deliberately does not:

- **Resource exhaustion by accumulation** — the primary failure mode.
  Detached dev servers, tunnels and watchers leak ports and RAM until the
  box degrades. Janitor finds them with *evidence*, not heuristics alone.
- **The "nobody remembers" problem** — attribution via agent-ledger turns
  an anonymous `python app.py` on port 8080 into *"spawned by this exact
  tool call, 12 days ago, in a session that has since ended."*
- **What it will NOT do**: kill anything by default; kill system daemons
  (exempt by name); kill whitelisted commands; kill without a written audit
  entry; act on processes below `min_uptime`; or run any network I/O.
- **Misfire surface (honest)**: a whitelisted command that *wraps* something
  dangerous (e.g. a whitelisted shell running a rogue child) is invisible —
  matching is on the command line, not the process tree. The fuzzy ledger
  attribution can attach the wrong spawn command (basename match) — treat
  it as a hint. Both limits are recorded in sweeps.jsonl entries so you can
  audit every decision retroactively.

## Known limits (honest coverage)

- Ledger attribution is fuzzy (basename match) — it can attach the wrong
  spawn command when the process name appears in unrelated calls. Treat it
  as a hint, not proof.
- A dev server you *intentionally* detached (`nohup … &`) is behaviorally
  identical to an accidental zombie — that's what the whitelist is for.
- Linux-only today (reads `/proc`). macOS/Windows: not supported yet.

## Tests

```bash
python3 test_janitor.py && python3 test_ledger_bridge.py && \
python3 test_integration.py && python3 test_config.py && \
python3 test_package_import.py
```

MIT. From the author of agent-ledger — *"core ngingetin, pro nyegah, janitor nyapu."*
