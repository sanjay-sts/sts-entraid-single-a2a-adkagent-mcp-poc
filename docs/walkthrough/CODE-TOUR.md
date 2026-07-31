# Code Tour — Read the Code in the Order That Makes It Click

The acts teach the system by *running* it. This teaches it by *reading* it — in the order that
builds understanding fastest, so you can explain any part to someone else. Eleven files, bottom
up: pure logic first, then the services that use it.

For each file: **what it is → what to notice → which of the six load-bearing rules it embodies
→ a one-minute "how I'd explain this file" script.** The six rules are in
[`08-orchestration-security.md`](08-orchestration-security.md) §8.4 and in `CLAUDE.md`.

Read them in this order:

```
agent_common/principal.py      →  the pure contract, no I/O — START HERE
agent_common/jwt_validator.py  →  why signature comes first
agent_common/registry.py       →  who the agents are, who may call whom
agent_common/tokens.py         →  mint (who I am) vs exchange (who I act for)
agent_common/outbound.py       →  the two-header wire contract, in one place
peer_agent/server.py           →  the smallest COMPLETE agent — read top to bottom
orchestrator_agent/server.py   →  fan-out, and partial-failure honesty
a2a_server/server.py           →  the gateway's human/machine fork (the big one)
mcp_server/server.py + policy.py → role resolution for both principal types
mcp_server/graph_obo.py        →  the resource-tier exchange
event_trigger.py               →  the machine entry point, and why absence is the point
```

---

## 1. `agent_common/principal.py` — the pure contract

**What it is:** every security decision as a *pure function of claims* — no network, no I/O. This
is why the contract is unit-testable without a tenant, and why it's the right place to start:
read this and you know the rules before you meet a single HTTP handler.

**What to notice:**
- The module docstring's SECURITY WARNING: every function trusts its claims completely.
  Signature verification is the caller's job. These functions on an *unverified* token are
  "attacker-supplied strings dressed up as JSON."
- `is_app_token` (`:45`) — the whole machine-vs-human decision, one claim, fail-closed.
- `verify_agent_claims` (`:91`) — the four checks a callee runs on an agent token (is-app,
  audience, known caller, has the role), and the up-front validation of its *own* arguments
  (empty `expected_audience` would "match" a token with no `aud`).
- `verify_delegated_user` (`:152`) — the two rider-token checks (is a user, not blocked).
- `Principal` (`:184`) — frozen *and* deep-immutable via `__post_init__`, so a downstream tier
  can't escalate by mutating `agent_roles` or `user_claims` in place.
- `derive_principal` (`:223`) — delegated iff a valid user token rode along; a dangling
  (present-but-unvalidated) user token is discarded, not trusted.

**Rules it embodies:** #1 (its warning is the reason signature comes first), #2 (`is_app_token`
fails closed), #3 (nothing here reads groups for a machine).

**One-minute explanation:** *"This file is the rulebook with the crypto deliberately left out.
Every function decides something — is this a machine, is this caller allowed, is this rider a
real user — purely from claims, and it says loudly that claims mean nothing until someone else
has checked the signature. It's pure so it can be tested exhaustively without a tenant, and
everything else in the system is these rules wired to HTTP."*

---

## 2. `agent_common/jwt_validator.py` — why signature comes first

**What it is:** the piece that makes `principal.py` safe to trust — signature, issuer, audience,
expiry against Entra's JWKS.

**What to notice:**
- The docstring: "Without this, `verify_agent_claims()` is decoration."
- `validate` (`:89`) pins `algorithms=["RS256"]`, passes both audience forms
  (`api://<id>` and bare), and both issuer forms (v2.0 and v1.0). `alg=none` and HS256-confusion
  die here.
- `_get_jwks` with a TTL, plus a force-refetch on key-not-found (`:76-107`) — key rotation
  without either trusting stale keys forever or refetching every call.

**Rules it embodies:** #1, literally.

**One-minute explanation:** *"This is the bouncer that checks the ID is real before anyone reads
what's printed on it. It verifies the signature against Microsoft's published keys first; only
then are the claims worth reading. Pin the algorithm, check audience and issuer and expiry, and
handle key rotation. If this file is wrong, nothing else matters."*

---

## 3. `agent_common/registry.py` — who's who, and who may call whom

**What it is:** the agent identities (each from its own env var + cert paths) and the call graph.

**What to notice:**
- `AgentIdentity.audience` / `.scope` — `api://<client_id>` and `.../.default`, the exact
  strings Entra setup §3 produces.
- `_CALL_GRAPH` (`:25`) — the whole authorization topology in one dict, reviewable at a glance.
- `allowed_callers_for` (`:89`) drops unregistered callers, so a half-configured env fails closed
  rather than authorizing an empty string.
- `reload()` rebuilds from the environment; unset agents simply aren't registered.

**Rules it embodies:** supports #2/#3 by being the out-of-band source of "who is allowed" that a
token can't influence.

**One-minute explanation:** *"This is the org chart: which agents exist and which is allowed to
call which. It's a local mirror of the app-role grants in Entra — Entra enforces, this backs it
up — and it fails closed, so a missing config line means 'refuse,' never 'allow anyone.'"*

---

## 4. `agent_common/tokens.py` — mint vs exchange

**What it is:** the two credential flows, both certificate-backed, no client secrets.

**What to notice:**
- `AgentTokenProvider` — client-credentials, "here is who I am," one credential per agent,
  audience-narrowed per callee via the scope.
- `DelegatedTokenExchanger` — on-behalf-of, "here is who I act for," cached per
  (user-token, callee) because an OBO credential is bound to one user assertion. The LRU
  (`OrderedDict`, `_close_evicted`) closes evicted credentials so their HTTP transports don't
  leak.
- `_combined_pem` — cert + private key in one PEM, as azure-identity wants; the key never leaves
  the process.

**Rules it embodies:** #4 (these are the calls that must *fail*, not fall back, when they can't
mint/exchange).

**One-minute explanation:** *"Two ways to get a token, both signed with the agent's certificate.
One says 'I am this agent' (for machine calls); the other says 'I'm acting for this human'
(exchanging their token, narrowed to the next hop). The private key signs but never leaves
memory; only the public cert is in Entra."*

---

## 5. `agent_common/outbound.py` — the wire contract in one place

**What it is:** `build_agent_headers` — the single function that builds the two outbound headers,
so the "exchange, never forward" rule can't drift across callers.

**What to notice:**
- It's tiny on purpose. `Authorization` = a freshly minted agent token for the callee;
  `X-Delegated-User-Token` = the user token *exchanged* for the callee — and only when a human is
  genuinely upstream.
- The docstring spells out the replay argument: forwarding the inbound token would hand the
  callee a token minted for *us*, replayable anywhere we can be called.
- Delegation is derived from what we *hold* (`principal.user_token`), not from what the principal
  claims — a dangling user token yields a machine-only call, not a header we can't honestly fill.

**Rules it embodies:** #5 (this *is* the rule — "build headers with `build_agent_headers()`").

**One-minute explanation:** *"Every agent-to-agent call goes through this one function so the
header contract is written exactly once. Mint a fresh token for the callee; if a human is
upstream, exchange their token for one scoped to just that callee — never forward what we
received. It's small because the whole point is that nobody re-implements it and gets it subtly
wrong."*

---

## 6. `peer_agent/server.py` — the smallest complete agent

**What it is:** a full agent — callee *and* caller — with no LLM. Read it top to bottom; it's the
template every other agent follows.

**What to notice:**
- `_authenticate` (`:95`) — the canonical inbound sequence: Bearer present → validate signature →
  `verify_agent_claims` → optional rider → `verify_delegated_user` → `derive_principal`. Signature
  first, every time.
- Body is parsed *after* authentication (`:164`) — an unauthenticated request never reaches a
  parser.
- `_call_gateway` (`:134`) uses `build_agent_headers` for its own outbound call — the peer is a
  caller too.
- `BLOCKED_USERS` is read and checked here independently (`:58`) — it doesn't trust the gateway to
  have checked.

**Rules it embodies:** #1, #5, #6 — all visible in one readable file.

**One-minute explanation:** *"This is what an agent looks like with nothing extra. Someone calls
it: check the signature, then the claims, then any rider user token, then work out the principal —
and only then read the body. It also calls the gateway itself, using the shared header builder. If
you understand this file, you understand every agent; the others just add fan-out or an LLM."*

---

## 7. `orchestrator_agent/server.py` — fan-out and partial-failure honesty

**What it is:** the same agent shape as the peer, plus fan-out to two subagents, minting fresh
credentials for each.

**What to notice:**
- Same `_authenticate` as the peer (the shape is deliberately identical).
- `_dispatch_to` (`:158`) mints per-callee headers and, crucially, does **not** catch a
  minting/exchange failure — a hop whose user token couldn't be obtained must *fail*, not proceed
  as a machine (rule #4, in a comment).
- The result wraps each leg as `{ok, status, response, error}` with `ok` explicit, so a refused
  leg is never shape-indistinguishable from a success.
- `dispatch` (`:196`) authenticates before parsing the body, like the peer.

**Rules it embodies:** #4 (no silent downgrade), #6.

**One-minute explanation:** *"The orchestrator is the peer plus fan-out: one inbound principal
becomes N outbound calls, each with its own freshly minted, narrowed credentials. Two things make
it honest — it refuses to downgrade a delegated call to machine if an exchange fails, and it labels
each leg's success explicitly so you can always tell a refusal from a success."*

---

## 8. `a2a_server/server.py` — the gateway's human/machine fork (the big one)

**What it is:** the gateway, and the one place both kinds of caller enter. The most complex file;
read it after the small agents so the shape is familiar.

**What to notice:**
- `auth_middleware` (`:639`) — the fork. `is_app_token(claims)` splits machine callers (authorized
  by app role via `authorize_agent_caller`) from human callers (authorized by group via
  `authorize_human_claims`).
- `authorize_human_claims` (`:591`) is called from *both* the direct-human path and the
  delegated-rider path — so an agent with `Agent.Invoke` can't become a way around the gateway's
  blocklist and group rules.
- The comment at `:682-685`: `call_next` is deliberately *outside* the try/except, so an
  application error downstream isn't mislabeled as a 401 auth failure.
- Every branch sets the full set of ContextVars (including `current_principal`).

**Rules it embodies:** #1, #2 (the `is_app_token` fork), #6.

**One-minute explanation:** *"This is the front door for everyone — humans and agents. It looks at
one claim to decide which you are, then authorizes you the right way: humans by group membership,
agents by app role. The clever bit is that a human riding inside an agent's call gets sent through
the exact same human ACL as a human at the front door, so going through an agent buys you no
shortcut."*

---

## 9. `mcp_server/server.py` + `mcp_server/policy.py` — role resolution for both

**What it is:** the tool gate (Gate 2). The server wires up the verifiers and middleware; the
policy resolves roles.

**What to notice in `server.py`:**
- `_AgentTokenVerifier` (`:135`) + verifier ordering in `_build_auth` (`:160`) — the `idtyp=app`
  verifier ordered last that keeps the human scope check honest (Act 03).
- `_resolve_machine_context` — a machine's role from its app id, X-Assume-Role finally *enforced*
  here (the gateway forwards it unchecked; this is the enforcement point), and all six ContextVars
  set so a stale one can't leak.
- `_require_delegated_user` / `_get_graph_token` — Graph tools refuse a machine (`no_delegated_user`).

**What to notice in `policy.py`:**
- `get_agent_roles` — separate from `get_available_roles` on purpose: an app id must never be
  usable as a group claim. Fails closed, no `unknown_users` fallback for agents, case-insensitive
  GUID match.
- `check_access` — identical RBAC for both principal types; only *where the role came from*
  differs.

**Rules it embodies:** #2, #3 (both, sharply).

**One-minute explanation:** *"This is where 'which role, and can that role use this tool' is
decided — and it's re-decided here from scratch, trusting the token's signature, not the agent that
called. Humans get their role from groups, machines from their app id, and a machine can't smuggle
in a group claim to promote itself. Same tool-permission check for both; only the source of the
role differs."*

---

## 10. `mcp_server/graph_obo.py` — the resource-tier exchange

**What it is:** the OBO exchange for Microsoft Graph (Gate 3's Entra side).

**What to notice:**
- `GraphOBOExchanger` (`:23`) — a singleton; `get_graph_token` (`:54`) exchanges the user's
  custom-audience token for a Graph-scoped one, cached (128).
- It only runs for a *user* token — the MCP server refuses to call it for a machine principal
  before the request is even built.

**Rules it embodies:** supports the delegation model — the human's token, exchanged again for
Graph.

**One-minute explanation:** *"The last exchange in the chain: turn the user's token into one Graph
will accept, so the tool reads *that user's* mailbox and drive — and never runs at all for a
machine, which has no user to be."*

---

## 11. `event_trigger.py` — the machine entry point

**What it is:** the CLI that starts a machine chain. Read it last — by now the absence it's built
around is obvious.

**What to notice:**
- The header docstring: "The absence of `X-Delegated-User-Token` is the entire point of this
  script." Nothing declares "I am a machine"; the missing header *is* the machine-ness.
- `fire` (`:50`) mints an agent token, sends it with no user token, closes the credential even on
  the failure path.
- `main` maps the response to exit codes, including exit 3 — a human leaked into a machine-only
  chain (a correctness alarm).

**Rules it embodies:** #4 in spirit (it verifies the chain stayed machine and fails loudly if not).

**One-minute explanation:** *"This is a cron job's-eye view: authenticate as an agent with a
certificate, call the orchestrator with no user token, and let the derived-principal rule do the
rest. It even checks the answer came back 'machine' and screams via an exit code if a human somehow
appeared — because a machine chain that silently went delegated would be a real bug."*

---

## The five-minute whiteboard version

Draw six boxes: frontend → gateway → agent → MCP → Graph/S3, with the orchestrator and peer hanging
off the gateway. Then say:

1. **One rule.** Every box re-verifies who's asking. No box trusts the box before it.
2. **Three gates.** Gateway (may you enter), MCP (may your role use this tool), resource (may your
   token touch this data) — three owners, three copies of the rules, so breaking one doesn't break
   the others.
3. **Two callers, derived not declared.** A human (delegated) or an agent on its own (machine) —
   worked out from which tokens are present, never from a field the caller sets.
4. **Agents have real identities.** Each authenticates with a certificate, is allowed to call only
   the agents on a fixed graph, and hands the next hop a token minted for *just* that hop — so a
   stolen token is useless one step over.
5. **Fail closed, signature first.** Ambiguity is refusal; claims are meaningless until the
   signature verifies.

Then the honest coda: **what's not done.** No mTLS yet (plain HTTP between agents — audience
narrowing is what holds the line until Phase 2), MCP shares the gateway's app registration (narrowing
stops one hop short), no rate limiting. Being able to say what *isn't* solved is what separates
explaining the system from selling it.

That's the whole thing. Anyone who can draw those six boxes and say those six points understands
this system.
