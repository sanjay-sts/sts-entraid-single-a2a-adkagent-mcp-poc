# Act 04 — Agent-Tier Entra Setup (one-time, tenant admin)

**Needs:** tenant-admin rights on your Entra directory, the Azure CLI (`az`), and the four
human-path services already working (Acts 01–03).

**Goal of this act:** give the agents their own cryptographic identities, so that in Acts
05–07 they can prove who they are to each other the same way a human proves who they are. By
the end you'll have three new app registrations, certificates uploaded, the `idtyp` claim
configured, the `Agent.Invoke` role defined and assigned along the call graph, and the peer
and orchestrator services running.

> **This act wraps [`../ENTRA_AGENT_SETUP.md`](../ENTRA_AGENT_SETUP.md); it does not replace
> it.** That guide has the exact `az` commands. This act tells you, for each of its sections,
> *what* you're creating, *why* it exists, and a **verification checkpoint** to run before
> moving on — so you never build three sections on top of a mistake in the first.

Do the sections in order. Run the guide's commands for each `§`, then the checkpoint here.

---

## Before you start — what you're about to build

Four app registrations will be in play:

| Agent | App registration | Identity |
|-------|------------------|----------|
| gateway | **reuses** the existing `ENTRA_CLIENT_ID` app | cert added to the existing app |
| orchestrator | **new** `agent-orchestrator` | `AGENT_ORCHESTRATOR_CLIENT_ID` |
| peer | **new** `agent-peer` | `AGENT_PEER_CLIENT_ID` |
| event-trigger | **new** `agent-event-trigger` | `AGENT_EVENT_TRIGGER_CLIENT_ID` |

And a call graph — who is allowed to call whom — that you'll encode in Entra as role
assignments and that the code mirrors in `agent_common/registry.py` (`_CALL_GRAPH`):

```
event-trigger → orchestrator
orchestrator  → peer, gateway
peer          → gateway
gateway       → peer
```

**Do this first (Task 1 in the guide):** generate the certificates locally, before touching
Entra, because §2 uploads them:

```bash
uv run python pki/generate_certs.py
```

This writes a mini-CA and one key pair per agent into `pki/certs/` (gitignored). It **refuses
to overwrite** existing certs without `--force` — because regenerating would invalidate any
cert already uploaded to Entra, forcing you to re-upload all of them. If you see that refusal,
it's protecting you.

**Checkpoint:** `pki/certs/` contains `ca.crt`, `ca.key`, and `{gateway,orchestrator,peer,event-trigger}.{crt,key}`.

**Read the code:** `pki/generate_certs.py` — `_make_ca` and `_make_agent_cert`. Note the
localhost SAN and client+server EKU: the same certs are reused for mTLS in Phase 2.

---

## §1 — Create the app registrations

**What:** three new app registrations (`AzureADMyOrg`), a service principal for each, and
their appIds recorded into your `.env` as `AGENT_ORCHESTRATOR_CLIENT_ID`,
`AGENT_PEER_CLIENT_ID`, `AGENT_EVENT_TRIGGER_CLIENT_ID`.

**Why:** an app registration *is* an agent's identity in Entra — the thing Entra will mint
tokens for and check the certificate against. Three new agents, three new registrations. The
gateway already has one (it's a real app), so it's reused.

**Checkpoint:**
```bash
az ad app list --display-name agent- --query "[].{name:displayName, appId:appId}" -o table
```
You should see all three `agent-*` apps with appIds matching your `.env`.

---

## §2 — Upload the certificate to each app

**What:** the public cert (`pki/certs/<name>.crt`) goes onto each app registration. The
private key never leaves your machine — it signs the client assertion; Entra checks it against
the uploaded public cert.

**Why:** this is what lets an agent authenticate with a certificate instead of a client
secret. Certificate assertions can't be leaked-and-replayed the way a shared secret can, and
they line up with Phase 2's mTLS.

> ### The one footgun in this whole act — read before touching the gateway app
> For the three **new** agent apps, `az ad app credential reset --cert @... --append` is safe
> (§2a). For the **gateway** app (§2b), **do NOT** use `az ad app credential reset` — even
> with `--append`, it destroys the app's existing `ENTRA_CLIENT_SECRET`, which is the secret
> the Graph OBO tools depend on. On a live tenant that silently breaks Graph for every human
> user. Upload the gateway cert via the **Portal** (Certificates & secrets → Certificates tab
> → Upload `pki/certs/gateway.crt`) or the `az rest` PATCH the guide gives (read-append-write
> of `keyCredentials`).

**Checkpoint:**
```bash
# each agent app has one keyCredential (the cert):
az ad app credential list --id <AGENT_PEER_CLIENT_ID> --cert -o table
# the gateway app STILL has its client secret AND now a cert:
az ad app credential list --id <ENTRA_CLIENT_ID> -o table        # secret present?
az ad app credential list --id <ENTRA_CLIENT_ID> --cert -o table # cert present?
```
If the gateway's secret vanished, reissue `ENTRA_CLIENT_SECRET` before going on — Graph OBO
will be broken until you do.

---

## §3 — Expose each callee as an API, with the `Agent.Invoke` role

**What:** the callees (peer, gateway, orchestrator) get an `api://<appId>` identifier URI and
an `Agent.Invoke` **app role** (`allowedMemberTypes: ["Application"]`, a fresh GUID each).

**Why:** the identifier URI is the audience a caller requests a token *for* — this is what
makes per-hop audience narrowing possible (a token minted for `api://<peer>` names the peer
and nobody else). The `Agent.Invoke` app role is the permission a caller must hold to be
allowed in; it's how a callee distinguishes "an agent that's allowed to call me" from "any
app in the tenant."

**Checkpoint:**
```bash
az ad app show --id <AGENT_PEER_CLIENT_ID> --query "{uris:identifierUris, roles:appRoles[].value}"
```
Expect `identifierUris` = `["api://<peer-appId>"]` and `appRoles` containing `Agent.Invoke`.

**Read the code:** `agent_common/registry.py` — `AgentIdentity.audience` (`api://<client_id>`)
and `.scope` (`.../.default`) are exactly what §3 sets up in Entra.

---

## §4 — Emit the `idtyp` claim on every app

**What:** the `idtyp` optional claim, added to **every** app registration in play (callers and
callees).

**Why:** `idtyp=app` is the *only* signal that distinguishes a machine token from a human one.
The code's `is_app_token` reads this claim and **nothing else**, and it **fails closed**: if
`idtyp` is missing, every token is treated as a human's and agent calls are refused. That's
deliberate — the alternative (guessing "no username claim, therefore a machine") would
misclassify a real human from a tenant that omits optional claims, and misclassifying a human
as a machine is a privilege decision made on a formatting accident. So §4 isn't optional: skip
it and the agent tier simply won't authenticate.

**Checkpoint:**
```bash
az ad app show --id <AGENT_PEER_CLIENT_ID> --query "optionalClaims.accessToken[].name"
```
Expect `idtyp` in the list. Repeat for each app.

**Read the code:** `agent_common/principal.py:45-65` — `is_app_token`, the fail-closed
decision, in ~20 lines with the reasoning in the docstring.

---

## §5 — Assign `Agent.Invoke` to the callers (the call graph)

**What:** five `appRoleAssignedTo` grants, one per caller→callee edge:
orchestrator→peer, orchestrator→gateway, gateway→peer, peer→gateway, event-trigger→orchestrator.

**Why:** this is the call graph, enforced by Entra. Holding `Agent.Invoke` on a callee is what
gets a caller past that callee's role check. The code keeps a local mirror of this graph in
`registry.py` (`_CALL_GRAPH` + `allowed_callers_for`) as a second, independent check — Entra
is the enforcement point, the registry is the backup, and they must agree.

**Checkpoint:**
```bash
# peer's service principal should show TWO assignments (orchestrator, gateway):
az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/<peer-sp-id>/appRoleAssignedTo" \
  --query "value[].principalDisplayName"
```
Confirm the five edges exist. A missing edge surfaces later as a `403 unknown_agent` (Act 07)
— which is why you verify now rather than debugging it three acts from here.

**Read the code:** `agent_common/registry.py` — `_CALL_GRAPH` and `allowed_callers_for`. This
is the exact graph §5 encodes in Entra.

---

## §6 — Enable per-hop user-token OBO (the delegated path)

**What:** expose `access_as_user` on each callee, pre-authorize the orchestrator's appId as a
known client, and admin-consent.

**Why:** Act 06's delegated chain works by *exchanging* a human's token for one narrowed to
the next hop (OBO). That exchange needs the callee to expose a delegated scope and to trust
the calling agent. Without §6, Act 06's OBO exchange fails with a consent error.

**Checkpoint:** deferred to Act 06 — it's exercised by the first real OBO exchange. If you want
to check now: confirm `access_as_user` appears in each callee's `oauth2PermissionScopes` and
the orchestrator is in each callee's `preAuthorizedApplications`.

---

## §7 — Verify the whole setup

**What:** the guide points you at the targeted integration test:

```bash
uv run pytest tests/test_agent_identity.py -v -m integration
```

**Why:** this is the first thing that actually asks Entra to mint a certificate-backed token
for these registrations. It **skips cleanly** if any `AGENT_*_CLIENT_ID` is unset, so a pass
here means the certs, `idtyp`, and audiences are genuinely wired. (The full 14-test
integration suite is Act 07.)

---

## §8 — Generate certs (done), fill env, start the agent services

Certs are already generated (top of this act). With the three `AGENT_*_CLIENT_ID` values in
`.env`, start the two agent-tier services in two more terminals:

```bash
# Terminal 5 — peer agent
uv run python peer_agent/server.py
# Terminal 6 — orchestrator
uv run python orchestrator_agent/server.py
```

**Checkpoint — these two DO have health endpoints:**
```bash
curl.exe http://localhost:10005/health
curl.exe http://localhost:10004/health
```

**Expected output:**
```json
{"status":"healthy","agent":"peer"}
{"status":"healthy","agent":"orchestrator"}
```

**Read the code:** the health handlers are `peer_agent/server.py:207-209` and
`orchestrator_agent/server.py:255-257`. Note both build their token providers *lazily* — the
private key is read on first use, not at import, so `/health` works even before any agent call.

---

## Architecture decision — certificate assertions, not client secrets

**What was chosen:** every agent authenticates to Entra with an x509 **certificate assertion**
(`CertificateCredential` / `OnBehalfOfCredential`), and a local mini-CA issues the certs.

**The alternatives:** (a) a client secret per agent (a shared string); (b) managed identities;
(c) a real enterprise CA from day one.

**Why certificates:** a client secret is a bearer credential — anyone who reads it from an
env var or a log can *be* that agent. A certificate assertion proves possession of a private
key that never leaves the process; the only thing in Entra is the public cert. It's also the
same credential Phase 2 needs for mTLS, so the identities are built once. Managed identities
would be cleaner in Azure-hosted production but don't exist for a laptop-hosted testbed.

**Why a mini-CA:** it makes the testbed self-contained — no external CA dependency to run the
demo. And it's a drop-in seam: an enterprise CA (AWS Private CA, Vault PKI, DigiCert) replaces
`generate_certs.py` with **no downstream code change**, because Entra checks the assertion
against the uploaded public cert and doesn't walk a chain.

**The trade-off:** more setup than a secret (this whole act), and cert rotation is a real
operation (re-generate, re-upload, the `--force` guard exists precisely because getting this
wrong is disruptive). You're buying non-repudiable, non-replayable agent identity for the
price of a one-time provisioning ceremony.

---

> ### Checkpoint — Act 04
> **You have now built:** three agent app registrations with certs, `idtyp` on every app,
> `Agent.Invoke` defined on the callees and assigned along the five call-graph edges, OBO
> enabled, and the peer + orchestrator services healthy.
>
> **You now understand:** why each Entra artifact exists (identity, audience, machine-signal,
> permission, delegation) and how the code mirrors the call graph as an independent check.
>
> **Explain it in one sentence:** *"Each agent gets its own certificate-backed Entra app
> registration and an `Agent.Invoke` grant only along the edges of a fixed call graph, so
> agents prove their identity cryptographically and can only call the agents they're allowed
> to."*

Next: [Act 05 — the machine chain](05-machine-chain.md). Fire a request with no human anywhere
in it.
