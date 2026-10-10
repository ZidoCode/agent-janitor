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

## Signal → confidence model

| Evidence | Tier |
|---|---|
| orphan (parent dead) + holds port / dev traits | **confirmed** |
| orphan only | **likely** |
| dev traits + TTL exceeded, parent alive | **possible** (never auto-swept) |

Only **confirmed + likely** are killable. System processes (sshd, nginx,
postgres, systemd…) are exempt by pattern. Whitelisted commands are never
suspects.

## Known limits (honest coverage)

- Ledger attribution is fuzzy (basename match) — it can attach the wrong
  spawn command when the process name appears in unrelated calls. Treat it
  as a hint, not proof.
- A dev server you *intentionally* detached (`nohup … &`) is behaviorally
  identical to an accidental zombie — that's what the whitelist is for.
- Linux-only today (reads `/proc`). macOS/Windows: not supported yet.

## Tests

```bash
python3 test_janitor.py && python3 test_ledger_bridge.py
```

MIT. From the author of agent-ledger — *"core ngingetin, pro nyegah, janitor nyapu."*
