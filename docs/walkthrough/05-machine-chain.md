# Act 05 — The Machine Chain (No Human Anywhere)

**Needs:** Act 04 complete — the agent app registrations, certs, and the peer + orchestrator
services running.

**Goal of this act:** fire a request that has **no human in it at all** and watch the system
correctly conclude "this is a machine" — not because anyone said so, but because no user token
is present. Then watch a machine get correctly refused a Graph tool, because there's nobody to
act on behalf of. This is the derived-principal rule (Act 00) made real.

---

## 5.1 — Fire the machine chain

`event_trigger.py` is the machine entry point. It authenticates with the event-trigger agent's
own certificate, calls the orchestrator with an agent token and **no** user token, and the
orchestrator fans out to the peer and the gateway. No browser, no login, no human.

```bash
uv run python event_trigger.py --task status
```

**Expected output** — exit code `0`, and a JSON body shaped like this:

```json
{
  "principal_type": "machine",
  "acting_agent": "<AGENT_ORCHESTRATOR_CLIENT_ID>",
  "on_behalf_of": "",
  "subagents": {
    "peer":    { "ok": true, "status": 200, "response": { "...": "..." }, "error": null },
    "gateway": { "ok": true, "status": 200, "response": { "...": "..." }, "error": null }
  }
}
```

Read every field, because each one is a claim the system is making:

- **`principal_type: "machine"`** — derived. No `X-Delegated-User-Token` rode along, so the
  orchestrator concluded machine. Nothing in the request declared this.
- **`acting_agent`** — the calling agent's app id (the event-trigger, as seen by the
  orchestrator). Even with no human, *who is acting* is always recorded, so the chain is
  auditable.
- **`on_behalf_of: ""`** — empty, correctly. There is no human to be on behalf of.
- **`subagents.*.ok`** — the explicit success flag. Both legs are present in the object
  *always*, so membership proves nothing — you check `ok`. A refused leg would be
  `ok: false` with a `status` and `error`, shape-distinguishable from success on purpose.

**The exit codes** (this simulates a cron source, which can only see the status):

| Code | Means |
|------|-------|
| `0` | dispatched, and the chain resolved a **machine** principal (the happy path) |
| `1` | couldn't run — not configured, or the orchestrator is unreachable |
| `2` | the orchestrator refused or failed the dispatch |
| `3` | it worked, but the principal was **not** a machine — a human leaked into a chain that should have none |

Exit `3` is the interesting one: it's a *correctness alarm*. If someone wired a user token
into this supposedly-human-free path, the machine-chain guarantee would be silently broken —
so `event_trigger.py` checks the returned `principal_type` and fails loudly if it isn't
`machine`.

**Trace it in the logs** — the orchestrator (`logs/orchestrator.log`) logs the derivation:

```
Dispatching 'status' for agent <event-trigger id> (principal=machine)
```

and the peer (`logs/peer_agent.log`):

```
Action 'status' by agent <orchestrator id> (principal=machine)
```

Notice the peer sees the **orchestrator** as its caller, not the event-trigger — each hop's
`acting_agent` is whoever called *that* hop. Identity is per-edge.

**Read the code:** `event_trigger.py` — `fire()` mints the agent token and sends it with **no**
user token (the comment at the header spells out that the *absence* is the whole point); `main()`
maps the response to the exit codes. The orchestrator's `dispatch` and `_dispatch_to` are in
`orchestrator_agent/server.py`.

---

## 5.2 — A machine asks for a Graph tool, and is refused

**Goal:** prove the machine principal can't reach a "on behalf of a user" Graph tool. **What it
proves:** the principal type isn't cosmetic — it changes what the request is *allowed to do*.

Drive a Graph tool through the machine chain (a task that would route to `get_user_profile` or
`list_files`). The tool returns a structured refusal rather than data:

```json
{
  "error": "no_delegated_user",
  "agent_id": "<the calling agent's app id>",
  "note": "This tool acts on behalf of a signed-in user. The caller is an agent with no user context (event-triggered). Invoke it through a user session instead."
}
```

This isn't an error in the "something broke" sense — it's the system refusing to invent a
human. A Graph "/me" call as an app-only token would read the *application's* own mailbox and
drive, which is emphatically not what "get the user's profile" means. So the tool refuses
before it builds the request.

**Read the code:** `_require_delegated_user` (`mcp_server/server.py:484-501`) returns exactly
that dict when `current_principal_type` is `"machine"`; it's called at the top of
`get_user_profile`, `list_files`, and `send_email`. And `_get_graph_token`
(`mcp_server/server.py:436+`) refuses to run the OBO exchange for a machine principal, so even
the token acquisition can't accidentally proceed.

---

## 5.3 — How the machine verdict is reached, in code

Three functions, in order:

1. **`is_app_token(claims)`** — `agent_common/principal.py:45-65`. Reads `idtyp == "app"`,
   fails closed if absent. This is how the orchestrator knew the *caller* was an agent.
2. **`derive_principal(agent_claims, user_claims, user_token)`** —
   `agent_common/principal.py:223-262`. If a valid user token rode along → `delegated`; else →
   `machine`. Here, no user token → machine. Crucially, if a `user_token` is present but its
   claims failed validation, it's treated as *dangling* and discarded — the principal does
   **not** become delegated on a token nobody could verify.
3. **`TomlPolicyEvaluator.get_agent_roles(agent_id, provider)`** — `mcp_server/policy.py`. A
   machine's role comes from its **app id** via `[agent_rules]` in `permissions.toml`, and
   from nothing else. It deliberately ignores group claims.

That last point is a real security decision, not an omission — see below.

---

## Architecture decision — principal type is derived, and a machine's role ignores group claims

**What was chosen:** the principal type is computed from which tokens are present (§5.3 #2),
and a machine's role is resolved from its app id alone (§5.3 #3), never from any `groups`
claim in its token.

**The alternative for principal type:** let the caller send a field — `"principal_type":
"machine"` — or infer it from some heuristic like "no username claim present."

**Why derived:** a field the caller sets is a field the caller can lie about. If a machine
could *declare* itself delegated, it could claim a human's authority; if it could declare
itself machine, it could dodge a human-only restriction. By deriving type from the tokens —
which are signed and audience-bound — the caller has nothing to lie *with*. And the heuristic
alternative ("no username → machine") is exactly the fail-open guess that `is_app_token` was
written to avoid: it misclassifies a real human whose tenant omits optional claims.

**The alternative for machine role:** resolve an agent's role from a `groups` claim, reusing
the same path humans use.

**Why app-id-only:** an app registration controls its own optional claims. If an agent could be
promoted to a role by presenting a `groups` claim, it could put *any* group in that claim and
grant itself *any* role in the tenant — self-service privilege escalation. Its role must come
from something only an operator controls: an entry in `permissions.toml` keyed by app id. That's
why `get_agent_roles` is a separate method from `get_available_roles`, and why it consults
`[agent_rules]` and never group rules.

**The trade-off:** two role-resolution paths to maintain (human via groups, machine via app id)
instead of one, and an operator must explicitly list each agent's role in `permissions.toml` —
there's no "unknown agents get a default" fallback (that too would hand a role to any app in the
directory). More configuration, in exchange for making privilege un-self-grantable.

---

> ### Checkpoint — Act 05
> **You have now proven:** a request with no user token resolves to a machine principal
> end-to-end (exit 0, `principal_type: machine`, `on_behalf_of: ""`), and a machine is
> correctly refused the Graph "on behalf of a user" tools with `no_delegated_user`.
>
> **You now understand:** how the machine verdict is derived (`is_app_token` → `derive_principal`),
> why a machine's role comes from its app id and never a group claim, and what exit code 3 is
> guarding against.
>
> **Explain it in one sentence:** *"With no human token in the request, the system derives a
> machine principal on its own and won't let it use human-only tools or grant itself a role — a
> machine can't lie its way into a human's authority because it was never asked to declare
> anything."*

Next: [Act 06 — the delegated chain](06-delegated-chain.md). Now put a human back in, and watch
their identity ride through the agents.
