# Multi-Agent Authentication & Authorization — Design

**Date:** 2026-07-13
**Branch:** `multi-agent-authnz`
**Status:** Approved design, pending implementation plan
**Baseline:** `HANDOFF.md` (system state as of `main` @ `fc041d6`)

---

## 1. Problem

The current system carries a **human user's** identity from browser sign-in to the resource APIs, enforcing access at three tiers (agent / tool / resource). Every premise it rests on assumes one human, one agent, one hop — see `HANDOFF.md` §12. Multi-agent scenarios violate all of them:

- There is no second agent. Nothing in the codebase authenticates *to* another agent or verifies who it is talking to.
- A machine (client-credentials) token dies at three separate points: the gateway rejects it (`no_group_membership` — app tokens carry `roles`, not `groups`), email extraction finds no user claim, and the OBO exchange requires a user assertion by definition.
- The caller's JWT is forwarded **verbatim** to every tier, so any tier can replay it elsewhere.
- Nothing records *which agent* acted on a user's behalf — there is no delegation provenance.

We want a testbed that exercises two agents calling each other, and an orchestrator fanning out to two subagents, where **each side cryptographically verifies who the other is**, in both a delegated (human upstream) and a machine-to-machine (event-triggered) mode.

## 2. Goals / Non-goals

**Goals**
- Agents verify each other's identity — in both directions, not just callee-verifies-caller.
- Support both principal types: **delegated** (acting for a human) and **machine** (event-triggered, no human).
- Make rogue-agent attacks *observable*: demonstrate which layer catches which attack, and what happens when a layer is removed.
- Reuse and extend the existing seams (`PolicyEvaluator`, `IdPConfig`, `permissions.toml`) rather than forking a parallel stack.

**Non-goals**
- LLM-driven orchestration. The new agents route deterministically; auth is under test, not planning.
- Production PKI operations (revocation infrastructure, HSMs). Documented as governance, not built.
- Solving the compromised-agent problem (stolen private key) — see §9.

## 3. Trust model — three verification layers per hop

Each agent-to-agent call is verified at three independent layers, mirroring the project's existing defense-in-depth ethos:

| Layer | Mechanism | Question it answers | Rogue blocked |
|---|---|---|---|
| **Transport** | mTLS, mini-CA-issued certs | "Which workload holds this connection?" | Endpoint impersonators, wire sniffing |
| **Agent identity** | Entra app token (cert-signed client assertion, client-credentials) | "Which registered agent is calling, with what app roles?" | Unregistered agents; registered-but-unauthorized agents |
| **Delegation** | Per-hop OBO-exchanged user token | "On whose behalf, and is that human allowed?" | Privilege escalation past the user's role |

**Binding check** — the weld between layers 1 and 2. The callee requires the agent token's `azp` to match the agent identity in the mTLS peer certificate. A stolen token presented over a connection authenticated by a different agent's cert is rejected. This makes bearer tokens effectively sender-constrained (a poor-man's [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705); Entra's native sender-constrained token support is not generally available, which is why production deployments do this at the mesh layer).

**Why the token layer alone is insufficient.** A bearer token authenticates the *caller to the callee*, and nothing else. It does not authenticate the callee to the caller — so a rogue that squats the callee's port receives a valid token (audience-scoped to the real callee) and can replay it there, along with any delegated user token. Registration in Entra is directory governance; it says nothing about the wire. Layer 1 exists specifically to close this.

## 4. Request contract

```
mTLS connection          client cert CN = agent-orchestrator          (layer 1)

Authorization:           Bearer <agent app token>                     (layer 2 — ALWAYS)
                           aud   = <callee app id>      audience-narrowed per hop
                           azp   = <caller app id>      who is calling
                           idtyp = app                  canonical machine-token marker
                           roles = [Agent.Invoke, ...]  caller's app roles

X-Delegated-User-Token:  <user token>                                 (layer 3 — ONLY when a human is upstream)
                           aud   = <callee app id>      OBO-exchanged per hop
                           sub   = <human>              delegation chain root
                           groups= [...]                drives tool-tier role
```

**Principal type is derived, never declared.** User token present → `delegated`: the human's role drives tool access; the agent identity is audit metadata. Absent → `machine`: the calling agent's app roles drive access. A client cannot self-assert its principal type.

**Both tokens are audience-narrowed at every hop** — the agent token by requesting it for the callee, the user token by OBO exchange. A token captured at hop N is useless at hop N+1. This removes `HANDOFF.md` assumption #4 (verbatim forwarding) as a side effect.

## 5. Topology

```
event_trigger.py (M2M, no user) ──┐                    ┌──▶ existing A2A gateway → ADK → MCP → Graph/S3
                                  ├──▶ orchestrator ───┤         (subagent 1 — full existing stack)
frontend → user token ────────────┘      :10004        └──▶ peer_agent :10005
                                                                 (subagent 2 — no LLM, deterministic tools)

peer scenario:  existing gateway  ◀──── mTLS + tokens ────▶  peer_agent
                                    (each calls the other; each verifies the other)
```

**New components**

| Component | Purpose |
|---|---|
| `agent_common/` | Shared library — the anti-drift piece. Cert-assertion token acquisition (MSAL confidential client), agent-token validation (`aud`/`azp`/`idtyp`/`roles`), per-hop OBO helper, mTLS client/server config, the `azp`↔peer-cert binding check. Every agent imports it, so the contract cannot diverge across services. |
| `orchestrator_agent/` (:10004) | A2A server, deterministic routing (no LLM). Fans out to both subagents. Performs per-hop OBO when a user token arrived; propagates nothing when machine-triggered. |
| `peer_agent/` (:10005) | Minimal A2A subagent, 1–2 deterministic tools. Doubles as the peer in the mutual-verification scenario — it both calls and is called by the existing gateway. |
| `event_trigger.py` | Simulated cron/event source. Client-credentials only, no user token — exercises the pure-M2M path end to end. |
| `rogue_agent.py` | Adversarial harness (§8). |
| `pki/` | Mini-CA scripts (openssl): root CA + one key pair per agent. |

## 6. PKI — the provisioning seam

A local mini-CA issues one key pair per agent, serving both purposes: the TLS cert for mTLS, and the public key uploaded to that agent's Entra app registration for client assertions.

In production an enterprise CA (AWS Private CA, DigiCert, Venafi, Vault PKI, Entra Cloud PKI) fills this same seam **with zero code change**:

- For **Entra client-assertion verification**, the CA is irrelevant — Entra matches the assertion signature against the exact public cert uploaded to the app registration; it does not walk a chain. Self-signed and CA-issued certs are cryptographically equivalent here.
- For **mTLS**, the CA chain *is* the trust root, replacing our local root cert. This is the layer where an enterprise CA becomes load-bearing rather than governance.

What an enterprise CA buys (documented, not built): policy-controlled issuance, central inventory, automated rotation (ACME/SCEP), revocation via CRL/OCSP, and an audit trail. Note the AWS naming trap: public **ACM** serves AWS-managed endpoints and does not release private keys; the workload-identity product is **AWS Private CA** — the same model AWS IoT Core uses for Greengrass device certs.

## 7. Changes to the existing stack

**A2A gateway** (`a2a_server/server.py`)
- Recognize `idtyp=app` tokens: skip the group-membership check, authorize on `roles` + an `azp` allow-list instead.
- Serve mTLS; acquire its own outbound client identity (for the peer scenario).
- New denial reasons: `unknown_agent`, `agent_not_authorized`, `token_binding_mismatch`, `delegation_required`.

**Policy** (`mcp_server/policy.py`, `permissions.toml`)
- New `[agent_rules.entra]` table: app ID → role.
- `AccessRequest` gains `principal_type`.
- The dormant `check_access()` seam (`HANDOFF.md` §13 #15) finally gets called — this is what it was built for.

**MCP server** (`mcp_server/server.py`)
- `UserContextMiddleware` resolves machine principals (no email, no groups).
- New ContextVar: `current_principal_type`.
- Graph tools return a clean `no_delegated_user` error for machine principals — there is no human to act "on behalf of".
- S3 and time tools serve both principal types, gated by role as today.

**Entra setup** (documented as a step-by-step guide on the branch)
- Three new app registrations: orchestrator, peer agent, event-trigger client. The existing gateway app gains a certificate credential for outbound calls.
- Each: public cert uploaded; app role `Agent.Invoke` defined and assigned to the agents permitted to call it; API exposure + pre-authorization wired so per-hop OBO consent works. Admin consent once.
- **Requires tenant admin** in the test tenant.

## 8. Test matrix — the point of the exercise

mTLS is **toggleable** (dev_config-style) so the difference between layers is *observable*, in keeping with this project's habit of making denials visible.

**Adversarial** — `rogue_agent.py` runs each attack; the test asserts which layer catches it:

| Attack | mTLS off | mTLS on |
|---|---|---|
| Unregistered agent calls a subagent | blocked — no valid token | blocked |
| Registered agent lacking `Agent.Invoke` | blocked — `azp`/roles check | blocked |
| Rogue squats callee's port, harvests tokens | **succeeds** | blocked — server cert |
| Harvested token replayed to the real callee | **succeeds** (within lifetime) | blocked — binding check |
| Token from hop N replayed at hop N+1 | blocked — audience | blocked |
| Machine principal calls a Graph (user-only) tool | blocked — `no_delegated_user` | blocked |
| Expired client assertion | blocked | blocked |

**Happy path**
- **Delegated fan-out**: user → orchestrator → both subagents. The human's role is enforced at the MCP tier; the delegation chain (which agent acted) is visible in the audit log.
- **M2M fan-out**: event trigger → orchestrator → both subagents. The agents' app roles are enforced; Graph tools correctly refuse.
- **Peer mutual verification**: existing gateway ⇄ peer agent, each direction, each side verifying the other.

## 9. Residual risk

**Stolen private key / compromised legitimate agent.** No transport or token technology fixes this — a thief with the key *is* the agent. Mitigation belongs to the governance layer: certificate revocation (CRL/OCSP), short credential lifetimes, and Entra workload-identity Conditional Access. Documented explicitly so the testbed's boundaries stay honest.

## 10. Phasing

The build is large; each phase is independently testable and leaves the system working.

1. **Identity & token layer** — `agent_common/`, PKI scripts, Entra registrations, orchestrator + peer agent, event trigger. Gateway/MCP/policy changes for `idtyp=app` and `principal_type`. Both happy paths pass. mTLS off.
2. **Transport & binding** — mTLS across all agent hops, `azp`↔peer-cert binding check, toggle.
3. **Adversarial harness** — `rogue_agent.py` plus the attack matrix, run in both modes to demonstrate the delta.

## 11. Open items

- Whether the peer agent should surface in the frontend dashboard (audit log already has a role column; a delegation-chain column would show the acting agent).
- Whether to record the delegation chain as nested `act` claims (RFC 8693 style) or as a simple audit field. The former is the standards-aligned answer; the latter is a fraction of the work and sufficient for a POC.

## 12. References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.descope.com/learn/post/oauth-token-exchange) (delegation vs. impersonation; nested `act` claims)
- [RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705)
- [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id) — GA April 2026; agent identities authenticate via federated/cert credentials, supporting app-only and delegated tokens
- [Entra client-credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow) — `idtyp=app`, app `roles`
- [SPIFFE/SPIRE for agent identity](https://www.hashicorp.com/en/blog/spiffe-securing-the-identity-of-agentic-ai-and-non-human-actors) — the production-grade endgame; X.509 SVIDs, ephemeral and rotatable
- [A2A protocol auth gaps](https://dev.to/kanywst/a2a-protocol-auth-taken-apart-why-the-spec-is-thin-and-where-that-leaves-holes-22ii) — the spec advertises auth schemes but does not mandate agent-card verification
- [Dapr: securing A2A with automatic mTLS + SPIFFE IDs](https://www.diagrid.io/blog/making-agent-to-agent-a2a-communication-secure-and-reliable-with-dapr)
- [Multi-hop delegation for AI agents](https://workos.com/blog/oauth-multi-hop-delegation-ai-agents) — the common failure: scope is rarely reduced per hop
