# Spec: ServiceNow Integration with Cedar ABAC Pre-Check (v2 — post-grilling)

**Branch:** `test-integration-servicenow` (base: `mcp-skills-as-resources-abac-rbac`)
**Date:** 2026-05-19
**Target location for this spec after plan exit:** `docs/superpowers/specs/2026-05-19-servicenow-integration-abac-design.md`

---

## Context

Add a ServiceNow integration to the three-tier identity-aware agent system to close two existing test gaps:

- **Gap #2 — claim-based ABAC propagation**: prove the Entra `department` claim flows Frontend → A2A → ADK → MCP → Cedar and influences a policy decision.
- **Gap #3 — multi-attribute Cedar policy**: exercise `User.department` via a composite `role + department` condition.

ServiceNow provides the substrate via its native KB model (multiple Knowledge Bases) and incident table. Cedar gates the agent-side decision; SN's own ACL filters records on the SN side (defense in depth).

Repo context: graphify-out/GRAPH_REPORT.md confirms Cedar is the gravitational center (`CedarPolicyEvaluator` 91 edges, `TomlPolicyEvaluator` 87, `AccessRequest` 74, `AccessDecision` 64). Existing two-phase architecture: Phase 1 RBAC in `require_cedar()`; Phase 2 ABAC via `cedar_check_with_context()`. `_ABAC_PHASE1_PASSTHROUGH` currently `{"delete_s3_object"}`. **Verified during grilling:** `mcp_server/policy.py:156-159` already has `ABAC_CLAIM_KEYS = {"department": str, "archiver": bool}` — dept extraction infrastructure exists.

---

## Decisions Resolved (brainstorming + grilling)

| # | Question | Decision |
|---|---|---|
| 1 | Department source-of-truth | **Token claim only** — Entra `department` claim, Cognito `custom:department` |
| 2 | Tool API for dept-scoped tools | **Optional explicit parameter** (defaults to `principal.department` when omitted) |
| 3 | Token generation for tests | **Mock HS256 for fast suite** + **real Entra with App Registration claim mapping for slow tier** |
| 4 | Architecture | **Cedar pre-check (user-aware) → SN call (service-account auth) → SN native ACL** |
| 5 | SN auth mode in this branch | **Fixed API token (service account)**. OBO documented as future upgrade. |
| 6 | Scope | **Comprehensive**: 7 tools, Cedar unit + mocked + real `@slow`, frontend dept display, SN setup docs |
| 7 | Missing dept-claim UX | **Standard access denial** (no new CONFIG_ERROR tier). User self-discovers via support. |
| 8 | `update_incident` defense-in-depth | **Fetch-then-check** — tool does GET to read incident's dept, runs Phase 2 Cedar with that context, then PUT |
| 9 | X-Abac-Attrs header override of `department` | **Pop `department` from `abac_attrs` before merge in A2A + MCP + auth-bypass path** (header cannot spoof dept claim) |
| 10 | Incident dept modeling in real SN (custom field) | **Deferred** until OBO branch. No `u_department` on incident table in this branch. |
| 11 | Incident dept-ABAC in tests | **Cedar unit + mocked integration cover it**; real-tier skips incident tests |
| 12 | Mock mode trigger | **Empty `instance_url` triggers mock mode**; no extra flag |
| 13 | KB → dept resolution | **Dynamic per call**: tool fetches KB metadata from SN, reads `u_department` |
| 14 | KB dept source field | **Custom `u_department` field on `kb_knowledge_base`** — one-time SN setup (~2 min) |
| 15 | `cedar/entities.json` KB entities | **NOT added** — KB dept comes from SN dynamically, not from static Cedar entities |

---

## Architecture

**Two-stage enforcement:**

1. **Cedar pre-check (agent layer, user-identity-aware)** — runs *before* any SN call. Role + composite `role + department` for parameterized tools. If Cedar denies, SN is never contacted.
2. **ServiceNow internal verification** — SN's `user_criteria` on KBs and record ACLs on incidents filter results based on the integration user's identity. (When we upgrade to OBO later, SN will see the actual end user.)

```
Frontend ──Bearer──▶ A2A ──claims──▶ ADK ──headers──▶ MCP
                                                       │
                                                       │ 1. Cedar pre-check
                                                       │    Phase 1: RBAC
                                                       │    Phase 2: role + dept
                                                       │       (for param tools)
                                                       │       For update_incident
                                                       │       and KB tools: tool
                                                       │       first fetches metadata
                                                       │       from SN to get dept,
                                                       │       then runs Cedar
                                                       │
                                                       ▼ (only if Cedar allows)
                                                  ServiceNow client
                                                  (Basic auth, fixed API account)
                                                       │
                                                       ▼
                                                 ServiceNow API
                                              2. SN native ACL verification
```

**SN auth via `dev_config.toml`:**

```toml
[servicenow]
instance_url = ""                # empty → mock mode (no extra flag)
# instance_url = "https://devXXXXX.service-now.com"
api_user     = "admin"
api_password = "..."             # via env var in production
```

**Cedar policy additions:**

```cedar
// cedar/policies/rbac.cedar — additions
permit (principal in Role::"admin", action == Action::"call_tool",
        resource in [Tool::"list_knowledge_bases", Tool::"list_articles",
                     Tool::"get_article", Tool::"list_incidents",
                     Tool::"get_incident", Tool::"create_incident",
                     Tool::"update_incident"]);

permit (principal in Role::"developer", action == Action::"call_tool",
        resource in [Tool::"list_knowledge_bases", Tool::"get_article",
                     Tool::"get_incident"]);
// NOTE: list_articles, list_incidents, create_incident, update_incident come via ABAC

permit (principal in Role::"viewer", action == Action::"call_tool",
        resource in [Tool::"list_knowledge_bases", Tool::"get_article"]);
// NOTE: list_articles comes via ABAC

// cedar/policies/abac.cedar — additions
permit (principal in Role::"developer", action == Action::"call_tool",
        resource in [Tool::"list_articles", Tool::"list_incidents",
                     Tool::"create_incident", Tool::"update_incident"])
when {
  principal has department
  && context has target_department
  && principal.department == context.target_department
};

permit (principal in Role::"viewer", action == Action::"call_tool",
        resource == Tool::"list_articles")
when {
  principal has department
  && context has target_department
  && principal.department == context.target_department
};
```

`_ABAC_PHASE1_PASSTHROUGH` additions: `list_articles`, `list_incidents`, `create_incident`, `update_incident`.

---

## Components

### New module — `mcp_server/servicenow.py`

ServiceNow REST client, async via `httpx.AsyncClient`. Mirrors `_run_s3_operation()` style.

```
ServiceNowClient
  __init__(instance_url, api_user, api_password)
  list_knowledge_bases()              GET /api/now/table/kb_knowledge_base
  get_knowledge_base_metadata(kb_id_or_name)   resolve by sys_id or name; returns {sys_id, u_department, name}
  list_articles(kb_sys_id, query)     GET /api/now/table/kb_knowledge?kb=...
  get_article(sys_id)                 GET /api/now/table/kb_knowledge/{sys_id}
  list_incidents(department=None)     GET /api/now/table/incident (no u_department filter for now)
  get_incident(sys_id)                GET /api/now/table/incident/{sys_id}
  create_incident(short_description, description, urgency, **extras)
                                      POST /api/now/table/incident
  update_incident(sys_id, payload)    PUT /api/now/table/incident/{sys_id}

get_servicenow_client() / init_servicenow_client(url, user, pw)   # singleton
```

**Auth:** `Authorization: Basic <b64(user:password)>`. Errors normalized via `_run_sn_operation()` wrapper. **Mock fallback:** empty `instance_url` → `init_servicenow_client()` returns mock backed by `servicenow_mock.py`.

### New module — `mcp_server/servicenow_mock.py`

Module-level dataset: 3 mock KBs (IT/HR/Finance, each with `u_department`), ~9 articles (3 per KB), ~5 incidents (with synthetic dept tags in mock-mode-only fields for testing). Same async interface as `ServiceNowClient`.

### Modified — `mcp_server/server.py`

7 new tools. Pattern for parameterized + dynamic-dept tools (`list_articles`, plus `update_incident` with fetch-then-check):

```python
@mcp.tool(auth=require_cedar("list_articles"))
async def list_articles(kb_identifier: str, query: str = "") -> dict:
    client = get_servicenow_client()
    kb_meta = await client.get_knowledge_base_metadata(kb_identifier)  # SN call #1
    if kb_meta is None:
        return {"error": "[TOOL_DENIAL] knowledge base not found"}
    target_dept = kb_meta.get("u_department")
    decision = cedar_check_with_context("list_articles", {"target_department": target_dept})
    if not decision.allowed:
        return {"error": f"[TOOL_DENIAL] {decision.reason}"}
    return await client.list_articles(kb_meta["sys_id"], query)         # SN call #2

@mcp.tool(auth=require_cedar("update_incident"))
async def update_incident(sys_id: str, payload: dict) -> dict:
    client = get_servicenow_client()
    incident = await client.get_incident(sys_id)                        # SN call #1
    if incident is None:
        return {"error": "[TOOL_DENIAL] incident not found"}
    target_dept = incident.get("u_department")    # may be None in this branch (custom field deferred)
    decision = cedar_check_with_context("update_incident", {"target_department": target_dept})
    if not decision.allowed:
        return {"error": f"[TOOL_DENIAL] {decision.reason}"}
    return await client.update_incident(sys_id, payload)                # SN call #2
```

Updates:
- `_ABAC_PHASE1_PASSTHROUGH` gains `list_articles`, `list_incidents`, `create_incident`, `update_incident`
- Startup: `init_servicenow_client()` from config (or mock if `instance_url` empty)
- **X-Abac-Attrs `department` guard** (lines ~306-308):
  ```python
  abac_attrs = parse_abac_attrs(headers.get("x-abac-attrs", ""))
  abac_attrs.pop("department", None)   # claim-only; reject header override
  claims.update(abac_attrs)
  ```
- **Same guard in `current_user_claims.set(mock_claims)` path** (auth-bypass branch, lines ~230-238)

### Modified — `a2a_server/server.py`

Same `abac_attrs.pop("department", None)` guard wherever X-Abac-Attrs is parsed into `current_abac_attrs`. (Find the analog of mcp_server line 308.)

### `mcp_server/policy.py` — NO CHANGE

`ABAC_CLAIM_KEYS = {"department": str, "archiver": bool}` already in place at line 156-159. `_build_user_entity()` already extracts `department` from claims. (Verified during grilling — earlier spec entry for this file was redundant.)

### Modified — `cedar/schema.cedarschema`

`User.department: String?` already declared. **No KnowledgeBase entity type** (we resolve dynamically from SN, not from static entities). Schema unchanged.

### Modified — `cedar/entities.json`

Add 7 Tool entities (one per SN tool). **No KnowledgeBase entities** (Q13/Q15 decision):

```json
{"uid":{"type":"Tool","id":"list_knowledge_bases"},"attrs":{"sensitivity":"internal","requires_provider":""},"parents":[]},
{"uid":{"type":"Tool","id":"list_articles"},"attrs":{"sensitivity":"internal","requires_provider":""},"parents":[]},
{"uid":{"type":"Tool","id":"get_article"},"attrs":{"sensitivity":"internal","requires_provider":""},"parents":[]},
{"uid":{"type":"Tool","id":"list_incidents"},"attrs":{"sensitivity":"confidential","requires_provider":""},"parents":[]},
{"uid":{"type":"Tool","id":"get_incident"},"attrs":{"sensitivity":"confidential","requires_provider":""},"parents":[]},
{"uid":{"type":"Tool","id":"create_incident"},"attrs":{"sensitivity":"confidential","requires_provider":""},"parents":[]},
{"uid":{"type":"Tool","id":"update_incident"},"attrs":{"sensitivity":"confidential","requires_provider":""},"parents":[]}
```

### Modified — `cedar/policies/rbac.cedar` and `abac.cedar`

As shown in Architecture section.

### Modified — `dev_config.example.toml`

```toml
[servicenow]
instance_url = ""                # empty → mock mode
api_user     = "admin"
api_password = ""                # use env: SERVICENOW_API_PASSWORD
```

### Modified — `requirements.txt`

Add `respx>=0.21`. `httpx` already present.

### Frontend changes

| File | Change |
|---|---|
| `frontend/src/components/SecurityContextPanel.js` | Display `department` from `/me` response (read-only badge next to role). Show "—" if missing. |
| `frontend/src/utils/testScenarios.js` | Add 10 ServiceNow scenarios. |
| `frontend/src/utils/constants.js` | KB names used in scenarios (`IT_KB`, `HR_KB`, `FINANCE_KB`). |
| `frontend/src/components/RBACTestMatrix.js` | No structural change. |

### New docs

| File | Purpose |
|---|---|
| `docs/servicenow-integration.md` | SN setup: dev instance signup, API account, **custom `u_department` field on `kb_knowledge_base` table** (one form edit), 3 dept-tagged KBs with `u_department` populated. **Incident `u_department` NOT added in this branch** (deferred until OBO). |
| `docs/entra-department-claim-mapping.md` | Entra setup: App Registration → Token configuration → optional claim → `department`. Test user dept provisioning. |

### Updated existing docs

| File | Update |
|---|---|
| `CLAUDE.md` | Tool count 11 → 18. SN row in tool permissions table. Document `department` claim path + `X-Abac-Attrs.department` guard. |
| `scratchpad/cedar-abac/06-test-results.md` | Add ServiceNow scenario rows. |
| `README.md` | Mention SN in capabilities. |

---

## Data Flow

**Trace: developer (Entra claim `department=IT`) calls `list_articles(kb_identifier="HR KB")` → DENIED**

```
[1] Frontend → A2A → ADK → MCP (Bearer + X-Assume-Role: developer; X-Abac-Attrs may or may not be set,
                                doesn't matter — department popped before merge)

[2] MCP Server
    UserContextMiddleware:
      claims = dict(token.claims)                     # {department: "IT", ...}
      abac_attrs = parse_abac_attrs(...)
      abac_attrs.pop("department", None)              # NEW guard
      claims.update(abac_attrs)
      current_user_claims.set(claims)                 # department remains "IT" (claim-only)

    Phase 1 require_cedar("list_articles"):
      developer has no RBAC permit (ABAC-only); list_articles IN _ABAC_PHASE1_PASSTHROUGH → True

    Tool body — SN call #1:
      kb_meta = await sn.get_knowledge_base_metadata("HR KB")
                = {"sys_id": "abc...", "u_department": "HR", "name": "HR KB"}
      target_dept = "HR"

    Phase 2 cedar_check_with_context("list_articles", {target_department: "HR"}):
      principal = User(department="IT") in Role::"developer"
      abac.cedar developer rule: principal.department == context.target_department
        → "IT" == "HR" → no permit
      decision.allowed = False, reason="no permit found"

    Tool returns: {"error": "[TOOL_DENIAL] no permit found"}
    SN call #2 (articles fetch) is SKIPPED.

[3] Response back → denialClassifier tags level=tool → orange badge
```

**Happy path (same user, kb_identifier="IT KB"):** SN call #1 returns `u_department: "IT"`; Cedar permits; SN call #2 fetches articles; tool returns list.

**update_incident trace (dev IT tries to update HR's incident):**

```
Phase 1: developer in passthrough → True
Tool SN call #1: get_incident(sys_id) → {u_department: None (deferred in real SN)}
Phase 2: context.target_department = None
  Cedar guard `context has target_department` → false → no permit → DENY
  (In the current branch this means any update from non-admin → denial unless dept is provided)
```

Note for the implementation: since incident `u_department` is deferred until OBO, real-tier `update_incident` only works for admin (no dept condition). Mocked tests inject `u_department` into the mock incident dataset to exercise dev/viewer paths.

---

## Error Handling

Same as v1 spec, plus:

- **Tool-side metadata-fetch failure** (`get_knowledge_base_metadata` returns None) → `{"error": "[TOOL_DENIAL] knowledge base not found"}`. Explicit, not Cedar-denied.
- **Missing `u_department` on KB**: tool calls Cedar with `target_department = None`. Cedar `context has target_department` guard fails → "no permit found". Admin still allowed (no when-clause); dev/viewer denied. Setup guide flags this as misconfiguration.

(All other error paths unchanged from v1.)

---

## Testing

### `tests/test_cedar_smoke.py` — `TestCedarServiceNowPolicies` (~13 tests)

12 from v1 plus:

13. `test_x_abac_attrs_cannot_override_department_claim` — JWT has `department=IT`; X-Abac-Attrs sent with `{"department":"Finance"}`; verify Cedar User has `department="IT"`. Asserts the pop guard.

### `tests/test_servicenow_integration.py` — `TestServiceNowMocked` (~11 tests)

10 from v1 plus:

11. `test_update_incident_fetch_then_check` — dev IT calls `update_incident(sys_id)` where mocked incident has `u_department="HR"`; verify respx records two calls (GET incident, then NO PUT because Cedar denies); response = `[TOOL_DENIAL]`.

### `tests/test_servicenow_integration.py` — `TestServiceNowReal` (4 tests, `@pytest.mark.slow`, KB-only)

1. `test_real_admin_lists_knowledge_bases`
2. `test_real_admin_lists_articles_in_kb`
3. `test_real_admin_gets_specific_article` (sys_id round-trip; read-only)
4. `test_real_servicenow_auth_failure_handled` — bad API key → normalized error

All skip cleanly with `pytest.mark.skipif(not os.getenv("TEST_SERVICENOW_INSTANCE"))`. **Read-only** — no destructive operations.

### `tests/conftest.py` — fixtures

```python
developer_it_token, developer_hr_token, viewer_it_token, developer_no_dept_token,
mock_servicenow, real_servicenow_config
```

### Frontend test matrix — `frontend/src/utils/testScenarios.js`

10 scenarios as in v1.

### Coverage summary

| Layer | Tests added | Closes |
|---|---|---|
| Cedar unit | +13 | gap #3 + X-Abac-Attrs security |
| Mocked integration | +11 | gap #2 + defense-in-depth on update_incident |
| Real `@slow` (KB-only, read-only) | +4 | live SN smoke |
| Frontend matrix | +10 | E2E UX |
| **Total new** | **+38** | repo lifts **80 → 118** automated tests |

---

## Build Sequence (after plan exit)

1. **Branch + scaffold** — `git checkout -b test-integration-servicenow`. Move this spec to `docs/superpowers/specs/2026-05-19-servicenow-integration-abac-design.md`. Commit.
2. **Security fix** — Add `abac_attrs.pop("department", None)` in `mcp_server/server.py` (UserContextMiddleware path + auth-bypass path) and `a2a_server/server.py`. Write `test_x_abac_attrs_cannot_override_department_claim` first (TDD).
3. **Cedar policies + schema** — Edit `cedar/entities.json` (7 Tool entities), `cedar/policies/rbac.cedar`, `cedar/policies/abac.cedar`. Run `pytest tests/test_cedar_smoke.py` — existing tests green.
4. **Cedar unit tests** — Add `TestCedarServiceNowPolicies` (13 tests). Iterate to green.
5. **ServiceNow client** — `mcp_server/servicenow.py` + `servicenow_mock.py`. `_run_sn_operation()` wrapper.
6. **Tool registration** — 7 tools in `mcp_server/server.py`. `require_cedar()` + tool-side metadata fetch + `cedar_check_with_context()`. Update `_ABAC_PHASE1_PASSTHROUGH`.
7. **Mocked integration tests** — `TestServiceNowMocked` (11 tests). Iterate.
8. **Real-tier tests (optional, KB-only read-only)** — `TestServiceNowReal` (4 tests, `@slow`). Document env vars.
9. **Frontend** — Department display in `SecurityContextPanel`. 10 scenarios in `testScenarios.js`.
10. **Docs** — `docs/servicenow-integration.md` (with `u_department` setup on `kb_knowledge_base` only; incident deferred), `docs/entra-department-claim-mapping.md`. Update `CLAUDE.md` tool count + table. Append rows in `scratchpad/cedar-abac/06-test-results.md`.
11. **Verification** — Full test suite + manual smoke through frontend.

---

## Verification

```powershell
# After step 2-4 (Cedar policies + unit + security guard)
uv run pytest tests/test_cedar_smoke.py -v

# After step 7 (mocked integration)
uv run pytest tests/test_servicenow_integration.py::TestServiceNowMocked -v

# After step 8 (real-instance KB-only, env-gated)
$env:TEST_SERVICENOW_INSTANCE = "https://devXXXXX.service-now.com"
$env:TEST_SERVICENOW_USER     = "admin"
$env:TEST_SERVICENOW_PASS     = "<password>"
uv run pytest tests/test_servicenow_integration.py::TestServiceNowReal -v -m slow

# Full regression
uv run pytest tests/ -v
```

**Manual smoke** (after step 6, mock mode):
- `[servicenow].instance_url=""` in dev_config.toml
- Sign in as a developer with `department=IT` in their Entra profile
- "list IT articles" → mock SN returns IT articles
- "list HR articles" → `[TOOL_DENIAL]` orange badge

---

## Risks / Watch-fors

- **`User.department` empty-string vs missing:** `_build_user_entity()` already handles this (only attaches when claim present). Test `test_principal_missing_department_denied` covers it.
- **Entra `department` claim availability:** requires optional claims setup in App Registration AND `department` populated on each test user's profile. Document in `docs/entra-department-claim-mapping.md`.
- **Cognito `custom:department`:** needs User Pool schema update + per-user backfill. Code path handles both providers; setup is operator's responsibility.
- **Phase 1 passthrough growing:** 4 new tools join `delete_s3_object` in `_ABAC_PHASE1_PASSTHROUGH`. Consider renaming the constant later (`_ABAC_PHASE2_REQUIRED` is more descriptive); defer.
- **`update_incident` in this branch:** since incident `u_department` is deferred, real-tier `update_incident` will only work for admin (Cedar permits admin without dept condition). Mocked tests inject `u_department` to exercise dev/viewer denial paths. Document this limitation in the SN setup guide.
- **Two SN calls per `list_articles` and `update_incident`:** ~50-150ms extra latency. Acceptable for POC. Document; potential cache opportunity for KB metadata.
- **Free SN instance hibernation:** dev instances sleep when idle; tokens expire. `@slow` tests skip cleanly on connection error.
- **X-Abac-Attrs guard is a new behavior:** any existing consumers passing `department` in the header (none today) would silently lose that value. Frontend doesn't send `department` in X-Abac-Attrs, so safe.
- **Dynamic KB resolution is brittle if `u_department` field name changes:** lock the field name in `docs/servicenow-integration.md`. Tool reads exactly `u_department` — no fallback.
- **Branch lands functional in stages even if SN not set up:** stages 1-4 (Cedar + security + mocked) work standalone. Real-tier (stage 8) skips if SN env vars absent. Frontend (stage 9) is exercise-able in mock mode.

---

## Post-plan-exit follow-ups (NOT in this branch)

- **OBO upgrade**: when SN configured as Entra OAuth resource, add `mcp_server/servicenow_obo.py` mirroring `graph_obo.py`. Real-tier tests prove per-user identity reaches SN. Add `u_department` to incident table. Update `list_incidents`/`get_incident`/`create_incident`/`update_incident` to use `caller_id.department` joins where appropriate.
- **Cache KB metadata** (5-min TTL?) to eliminate the per-call SN round-trip on `list_articles`.
- **Multi-attribute ABAC beyond dept**: `User.team`, `User.region` etc. as separate branches.
- **Rename `_ABAC_PHASE1_PASSTHROUGH` → `_ABAC_PHASE2_REQUIRED`** for clarity. Standalone hygiene commit.
- **Group overage handling**: still deferred per `scratchpad/mcp-multiidp/05-future-roadmap.md`.

---

## Spec Self-Review (post-grilling)

- ✅ No placeholders / TBDs.
- ✅ Architecture and Components consistent: Cedar pre-check + service-account auth + dynamic KB dept fetch via `u_department`.
- ✅ Scope is one branch with clear staging: stages 1-7 land core; 8 (real-tier) optional; 9-10 polish.
- ✅ Cedar `User.department` empty-string vs missing case explicit (existing `_build_user_entity` handles).
- ✅ `update_incident` defense-in-depth via fetch-then-check, even though incident `u_department` field is deferred (admin-only in real SN until OBO).
- ✅ X-Abac-Attrs guard against dept spoofing added with explicit test.
- ✅ KB metadata extra round-trip acknowledged in Risks.
- ✅ `mcp_server/policy.py` correctly NOT listed as changed (existing `ABAC_CLAIM_KEYS` already includes `department`).
