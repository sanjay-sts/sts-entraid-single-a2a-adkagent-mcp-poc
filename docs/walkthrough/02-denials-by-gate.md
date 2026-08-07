# Act 02 — Denials, One at Every Gate

**Needs:** the same four services and login as Act 01.

**Goal of this act:** deliberately trigger a refusal at each gate, so you see defense in
depth *working* — not as a diagram, but as red/amber/purple badges in the UI and specific
`denial_reason` strings in the responses. A system you've only seen say "yes" is a system you
haven't really tested.

The frontend classifies every response into one of **four denial tiers**. Keep this table
open while you work — it's the map for the whole act:

| Tier | Badge colour | Fired by | You'll trigger it in |
|------|-------------|----------|----------------------|
| **AGENT** | red `#f85149` | Gate 1, the gateway | 2.1 |
| **TOOL** | amber `#e3b341` | Gate 2, the MCP role check | 2.2 |
| **SCOPE** | yellow `#d29922` | MCP scope check (rarely hit today — see 2.3) | 2.3 |
| **RESOURCE** | purple `#a371f7` | Gate 3, Graph / S3 | 2.3 |

**Read the code (keep it handy):** the four-tier logic is one short file,
`frontend/src/utils/denialClassifier.js` — worth reading top to bottom now. HTTP 401/403 →
`agent`; `[TOOL_DENIAL]` in the text → `tool`; `[SCOPE_DENIAL]` → `scope`; Graph/S3 error
patterns → `resource`. The badge colours are in `frontend/src/components/DenialIndicator.js`.

---

## 2.1 — Gate 1 (AGENT, red): block yourself

**Goal:** get refused at the front door. **What it proves:** the gateway denies a known-bad
principal before the request touches the agent or any tool.

**Backend / config:** find your own object id (the `oid` claim — the `/me` call in Act 1.3
showed it). Add it to `BLOCKED_USERS` in `.env`:

```bash
BLOCKED_USERS=<your-oid>
```

Restart the gateway (Terminal 3). Now send any chat message, or just re-run the `/me` call
from Act 1.3.

**Expected output** — HTTP 403, and in the body:

```json
{"error":"access_denied","message":"Your account has been blocked","denial_reason":"blocked_user"}
```

In the frontend, the message comes back tagged with a **red AGENT badge**; hover it and the
tooltip shows the reason `blocked_user`.

**Now undo it:** remove your oid from `BLOCKED_USERS`, restart the gateway. (Leave it blocked
and every later act fails at the door.)

**The sibling denial — `no_group_membership`:** if you sign in as the *no-group* test user
(a real account in none of the three security groups), you get a different red AGENT denial:
`403 / no_group_membership`. Same gate, different reason — one is "you're on the deny list,"
the other is "you're not on any allow list."

**Read the code:** `authorize_human_claims` (`a2a_server/server.py:591-628`) — the blocklist
check returns `blocked_user`, the group check returns `no_group_membership` (or
`no_group_configuration` if no groups are configured at all). Called from `auth_middleware`
at `:747`.

---

## 2.2 — Gate 2 (TOOL, amber): a viewer reaches for a tool it can't have

**Goal:** pass the front door, then get refused at the tool. **What it proves:** the gates
are independent — getting *in* (Gate 1) is not getting to *do things* (Gate 2).

**Frontend:** in the **Security Context** panel, change the **Role** dropdown to `VIEWER`.
(You can do this as the admin user — admin is allowed to step *down*.) Then send:

> **List my OneDrive files**

**Expected output:** an **amber TOOL badge**. `list_files` is allowed only for `admin` and
`developer`; a viewer's request is refused at the MCP role check. The underlying error text
carries `[TOOL_DENIAL] ... Role 'viewer' cannot use ...`, which the classifier maps to the
`tool` tier.

**Now do it systematically — the RBAC Test Matrix.** This is the single best tool in the app
for seeing the whole role model at once. Open the **RBAC Test Matrix** panel. The sub-line
reads `Testing as: VIEWER`. Hit **Run All** and wait — there are 18 scenarios and a 2-second
gap between each, so a full run takes about **40 seconds**. Each row shows Tool, Scope,
Expected, Result (PASS/FAIL + latency), and a per-row `Run` button.

Run it once per role and confirm the counts:

| Role selected | ALLOW | TOOL denial | What it means |
|---------------|-------|-------------|---------------|
| **ADMIN** | 18 | 0 | admin can use every tool |
| **DEVELOPER** | 8 | 10 | dev loses email, delete, time tools, admin-only tools |
| **VIEWER** | 2 | 16 | viewer keeps only `get_user_profile` and `get_s3_object_info` |

The results reset every time you change the role — that's deliberate, so you're never looking
at stale PASS/FAILs from a different role.

**Read the code:** the scenario definitions and expected outcomes are
`frontend/src/utils/testScenarios.js` (`getScenariosForRole`); the matrix UI is
`frontend/src/components/RBACTestMatrix.js`. The server-side decision is
`require_role(...)` on each `@mcp.tool()` in `mcp_server/server.py`, enforced by
`TomlPolicyEvaluator.check_access` in `mcp_server/policy.py`.

---

## 2.3 — Gate 3 (RESOURCE, purple) and the SCOPE tier

**Goal:** get refused by the *resource itself*, past both earlier gates. **What it proves:**
even a permitted role, calling a permitted tool, is still subject to what the token is
actually scoped for and what the backend permits.

**The honest situation with SCOPE today:** the frontend has a distinct **SCOPE** tier (yellow), and
the MCP server *can* emit `[SCOPE_DENIAL]`, but in the current build the Graph OBO path is
enabled (`GRAPH_OBO_ENABLED = true` in `testScenarios.js`), so the matrix no longer *predicts*
scope/resource denials — that prediction branch is effectively dead. You'll see scope and
resource denials **live**, not in the matrix's Expected column.

**Trigger a RESOURCE denial (purple)** the reliable way — S3 with something the backend can't
serve. As admin, send:

> **List objects in bucket does-not-exist-12345**

The S3 tool runs (role allows it, tool allows it), but boto3 returns an error, which the
classifier's S3 branch tags as a **purple RESOURCE badge** (`aws_error`). A Graph resource
denial (e.g. a token genuinely missing a Graph scope, or Graph returning 403) lands in the
same tier via the `GRAPH_DENIAL_PATTERNS` branch.

**Read the code:** the S3 and Graph resource branches are
`frontend/src/utils/denialClassifier.js:56-64`. The S3 error wrapping is
`_run_s3_operation` in `mcp_server/server.py`; the Graph path is `_get_effective_graph_token`
and `graph_obo.py`.

---

## 2.4 — The time-based denial: let a token expire

**Goal:** watch an *expired* token get refused. **What it proves:** authenticity has a
lifetime; the gateway re-checks `exp` on every request, so a token that was fine a minute ago
isn't automatically fine now.

**Frontend:** watch the **Token Expiry** countdown in the Security Context panel. Under 5
minutes it turns to an `expiry-warning` style; at zero it shows `EXPIRED`. Once it's expired,
send a message *without* refreshing the token.

**Expected output:** HTTP 401 with `denial_reason: token_expired` — a **red AGENT badge**,
because expiry is a Gate 1 concern.

**Read the code:** the gateway catches `jwt.ExpiredSignatureError` explicitly in
`auth_middleware` (`a2a_server/server.py:767-770`) and maps it to `token_expired`.

---

## 2.5 — How the frontend knows which tier a denial belongs to

You've now triggered AGENT, TOOL, and RESOURCE (and seen where SCOPE would live). Read
`denialClassifier.js` once more with the four badges fresh in mind — it's the whole
classification in ~70 lines, and it's a clean example of the system's philosophy showing up
in the UI: the badge isn't decoration, it's *which layer said no*, which is exactly the thing
this testbed exists to make visible.

For the exhaustive per-badge, per-role checklist (every scenario, expected colour, expected
text), use [`../../MANUAL_TESTING.md`](../../MANUAL_TESTING.md) §5 and §6 — this act is the
"understand it" version; that's the "tick every box" version.

---

## Architecture decision — why denials are tiered, and why each tier lives where it does

**What was chosen:** four denial tiers, each emitted by the layer that owns that decision,
and surfaced to the user as a distinct badge with the layer's own reason string.

**The alternative:** a single generic "403 Forbidden / Access Denied." Simpler to produce,
and arguably all a *user* needs.

**Why tiered:** the audience for this system is someone reasoning about *security*, and "why
was I denied" has a different answer and a different fix at each layer. `blocked_user` (fix:
the blocklist), `Role 'viewer' cannot use list_files` (fix: assume a higher role or change
the permission map), `insufficient_scope` (fix: consent to a scope), `s3_access_denied` (fix:
the IAM policy) — collapsing those into one message would throw away exactly the information
that tells you which of four very different things to go change.

**Why each tier lives where it does:** the layer that has the information makes the call. The
gateway is the only place that knows the blocklist and group rules, so AGENT denials are its.
The MCP server is the only place that knows the role→tool map, so TOOL denials are its. The
resource is the only place that truly knows if a scope suffices, so RESOURCE denials come
from Graph/S3. Putting a check where its data lives is what keeps the gates independent — no
layer has to trust another layer's summary of a decision it couldn't make itself.

**The trade-off:** more machinery — four reason vocabularies, a classifier, badge styling —
and a denial can *look* different depending on whether the LLM paraphrased a tool error
(hence the regex fallbacks in the classifier). That fragility is the price of routing a
refusal through an LLM that likes to reword things.

---

> ### Checkpoint — Act 02
> **You have now proven:** each gate refuses independently — AGENT (blocked/no-group), TOOL
> (role can't use tool), RESOURCE (data layer says no), and expiry as a Gate-1 concern — and
> you can name the `denial_reason` for each.
>
> **You now understand:** the four-tier model, why the badge tells you *which layer* said no,
> and where in the code each tier is decided.
>
> **Explain it in one sentence:** *"A refusal is tagged by which of the three services made
> it, because the fix is completely different depending on which gate you hit."*

Next: [Act 03 — MCP security up close](03-mcp-security.md). Stop going through the frontend and
attack the MCP server directly.
