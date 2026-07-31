# Walkthrough — Test and Understand the Whole System, Yourself

This is a **guided, hands-on path** through the entire identity-aware agent system. You
drive it. Each act is a self-contained session: you run something, watch it work (or watch
it correctly refuse), read the exact code that made that happen, and learn the architecture
decision behind it — so you can explain the system to someone else afterward.

It is **not** a reference manual. When you want the exhaustive detail, the acts link out to
the reference docs instead of repeating them:

| Doc | What it's for |
|-----|---------------|
| [`../../README.md`](../../README.md) | First-time setup of the four human-path services |
| [`../../TESTING.md`](../../TESTING.md) | Entra app registration + environment setup (deep) |
| [`../../MANUAL_TESTING.md`](../../MANUAL_TESTING.md) | Exhaustive per-component UI checklist |
| [`../ENTRA_AGENT_SETUP.md`](../ENTRA_AGENT_SETUP.md) | Agent-tier tenant-admin commands (Act 04 wraps this) |
| [`../../HANDOFF.md`](../../HANDOFF.md) | The complete system state, every seam and limitation |
| [`../../CLAUDE.md`](../../CLAUDE.md) | The load-bearing rules, in brief |

---

## The one idea, before anything else

**Every request carries proof of who is asking, and every layer re-verifies that proof
itself instead of trusting the layer before it.**

That is the whole system in one sentence. Six services, three access-control gates, two
kinds of caller (a human, or a machine acting on its own) — all of it is elaboration on that
one rule. If you remember nothing else, remember that no hop trusts a hop it cannot see.

---

## The acts, in order

Each act builds on the one before. Do them in sequence the first time.

| Act | Title | Needs | You can run it… |
|-----|-------|-------|-----------------|
| [00](00-big-picture.md) | The big picture | nothing | now |
| [01](01-golden-thread.md) | Golden thread — one user through A2A → agent → MCP | 4 services + Entra login | now |
| [02](02-denials-by-gate.md) | Denials — one at every gate | same | now |
| [03](03-mcp-security.md) | MCP security up close | same | now |
| [04](04-agent-tier-setup.md) | Agent-tier Entra setup | **tenant admin**, one-time | when you have admin |
| [05](05-machine-chain.md) | The machine chain — no human anywhere | Act 04 done | after 04 |
| [06](06-delegated-chain.md) | The delegated chain — your token rides the agents | Act 04 done | after 04 |
| [07](07-adversarial.md) | Adversarial — try to break the gates | Act 04 done | after 04 |
| [08](08-orchestration-security.md) | Orchestration security — the full flow, synthesized | Acts 01–07 read | after 07 |
| [09](09-cognito.md) | The second IdP — Cognito | Cognito pool configured | last, optional |

**Companion:** [`CODE-TOUR.md`](CODE-TOUR.md) — read the code in the right order, with a
one-minute explanation script per file. Use it when you want to *teach* the system, not just
run it.

**Helper scripts:** [`scripts/`](scripts/) — two small tools (mint an agent token; OBO-exchange
a user token and dispatch) that Acts 06 and 07 use. They reuse the real `agent_common` code,
so reading them is also a way to see how the library is meant to be called.

---

## How each scenario is laid out

Every scenario in every act uses the same shape, so you always know where to look:

- **Goal** — one line: what you're about to do.
- **What it proves** — the security property you'll have demonstrated.
- **Test it (frontend)** — exact UI steps and what you'll see, with the real labels.
- **Test it (backend)** — exact commands. PowerShell is called out where it differs from bash.
- **Expected output** — near-verbatim: the log lines, JSON, or badges you should get.
- **Read the code** — `file:line` references, in the order to read them.
- **Architecture decision** — what was chosen, why, what the alternatives were, the trade-off.
- **If it fails** — the likely causes.
- **Explain it in one sentence** — the thing to say when you teach it.

Each act ends with a **checkpoint box**: what you've now proven and now understand.

---

## Conventions

- Commands assume you're at the repo root and using `uv`. Windows note: this repo is
  developed on Windows; where a bash idiom (`for` loops, `VAR=$(...)`) won't work in
  PowerShell, the PowerShell form is given alongside.
- `curl` examples use `curl.exe` on Windows PowerShell (plain `curl` there is an alias for
  `Invoke-WebRequest` and takes different flags).
- Ports are the defaults: gateway 10000, ADK agent 10001, MCP 10002, frontend 10003,
  orchestrator 10004, peer 10005.
- Logs live under `logs/` — one file per service. `tail -f` (bash) or
  `Get-Content -Wait -Tail 20` (PowerShell) to follow them live.

> **One accuracy note you'll want.** The top-level `README.md` has two small staleness bugs
> the acts deliberately do **not** copy: it mentions `ANTHROPIC_API_KEY` (the code uses
> `AWS_BEARER_TOKEN_BEDROCK`), and it says "four tiers" while listing three. The denial model
> is genuinely four tiers (AGENT / TOOL / SCOPE / RESOURCE); Act 02 shows all four.
