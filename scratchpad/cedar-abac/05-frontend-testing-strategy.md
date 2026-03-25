# Cedar ABAC: Frontend Testing Strategy

Testing Cedar ABAC via the Security Testing Dashboard (React frontend).
Covers the full chain: **Frontend → A2A Gateway → ADK Agent → MCP Server → Cedar PDP**.

Companion to `04-testing-strategy.md` (unit/integration tests).
Key difference: frontend adds the **archiver toggle dimension** and the **LLM path** (prompt → tool call),
producing ABAC-specific denial tiers beyond simple RBAC.

---

## Cognito IdP Prerequisites

The `archiver` attribute is a **Cognito** custom claim (S3 delete is an AWS use case).

### Setup

1. **User Pool tier**: "Basic features + access token customization" (recommended)
2. **Custom attribute**: `custom:archiver` (String) on User Pool
3. **Access token customization**: Cognito console > User Pool > Token Configuration > map `custom:archiver` → `archiver` claim in access token
4. **Test user**: `archiver@test.com` in `platform-developers` group with `custom:archiver=true`
5. **IAM**: S3 bucket policy allows `s3:DeleteObject` on target bucket

> **Important**: Frontend uses `session.tokens?.accessToken` (`AuthProvider.js:201`), not the ID token. Without access token customization, the `archiver` claim won't be visible to Cedar.

### How archiver reaches Cedar (two paths)

**Path A — Token claim (real auth):**
```
Cognito token { "archiver": "true" }
  → MCP _resolve_context() stores in current_user_claims
    → CedarPolicyEvaluator._build_user_entity() extracts archiver
      → String "true" coerced to bool True
        → Cedar evaluates principal.archiver == true
```

**Path B — Frontend header override (testing):**
```
Frontend archiver checkbox → X-Abac-Attrs: {"archiver": true}
  → A2A Server → ADK Agent → MCP Server
    → _resolve_context() merges into claims
      → CedarPolicyEvaluator sees archiver: true
```

Both paths converge at `current_user_claims.set(claims)` in MCP middleware.

---

## Test Users

| Provider | User | Email | Group | archiver | Role |
|----------|------|-------|-------|----------|------|
| Entra | Adele Vance | AdeleV@2tdgcb.onmicrosoft.com | AI-Agent-Admins | n/a | admin |
| Entra | Diego Siciliani | DiegoS@2tdgcb.onmicrosoft.com | AI-Agent-Developers | n/a | developer |
| Entra | Johanna Lorenz | JohannaL@2tdgcb.onmicrosoft.com | AI-Agent-Viewers | n/a | viewer |
| Cognito | archiver | archiver@test.com | platform-developers | true | developer |

---

## ABAC Attribute Propagation Chain

```
Frontend                    A2A Server                ADK Agent                 MCP Server
─────────                   ──────────                ─────────                 ──────────
SecurityContextPanel        auth_middleware            create_session            UserContextMiddleware
  [archiver checkbox]       parse_abac_attrs()        user:abac_attrs           parse_abac_attrs()
      │                         │                         │                         │
      ▼                         ▼                         ▼                         ▼
  a2aClient.js              current_abac_attrs        session state             claims.update(attrs)
  X-Abac-Attrs header       ContextVar                mcp_header_provider       current_user_claims
      │                         │                         │                         │
      └─────── HTTP ────────────┘──── JSON body ──────────┘──── X-Abac-Attrs ──────┘
```

---

## Frontend Components Modified

| Component | Change | Props |
|-----------|--------|-------|
| `SecurityContextPanel` | Archiver checkbox below role selector | `archiverEnabled`, `onArchiverChange` |
| `App.js` | `archiverEnabled` state, threaded to all children | - |
| `RBACTestMatrix` | ABAC-aware scenarios, `+archiver` badge, reset on toggle | `archiverEnabled` |
| `ChatInterface` | Builds `abacAttrs` from `archiverEnabled` | `archiverEnabled` |
| `ConversationTabs` | Forwards `archiverEnabled` to ChatInterface | `archiverEnabled` |
| `a2aClient.js` | `X-Abac-Attrs` JSON header in `sendA2AMessage()` | `abacAttrs` param |
| `testScenarios.js` | 8 ABAC scenarios, `getScenariosForRole(role, activeAbacAttrs)` | - |

---

## ABAC Test Scenarios (8 scenarios)

All use `delete_s3_object` tool with explicit S3 paths in prompts.

| # | ID | Role | archiver | Prompt Path | Expected | Denial |
|---|-----|------|----------|-------------|----------|--------|
| 1 | s3_delete_admin_archive | admin | off | `archive/old-report.csv` | ALLOW | - |
| 2 | s3_delete_admin_protected | admin | off | `protected/critical.csv` | DENY | TOOL (guardrail) |
| 3 | s3_delete_admin_normal | admin | off | `data/file.csv` | ALLOW | - |
| 4 | s3_delete_dev_archiver_archive | developer | **on** | `archive/old-report.csv` | ALLOW | - |
| 5 | s3_delete_dev_archiver_protected | developer | **on** | `protected/critical.csv` | DENY | TOOL (guardrail) |
| 6 | s3_delete_dev_archiver_normal | developer | **on** | `data/file.csv` | DENY | TOOL (ABAC) |
| 7 | s3_delete_dev_no_archiver | developer | off | `archive/old-report.csv` | DENY | TOOL (ABAC) |
| 8 | s3_delete_viewer | viewer | off | `archive/old-report.csv` | DENY | TOOL (RBAC) |

### Decision Logic (`getScenariosForRole`)

```
1. forceExpectDeny?          → DENY (guardrail — scenarios 2, 5)
2. Role not in rolesAllowed? → DENY (RBAC — scenarios 3*, 6*, 7, 8)
3. ABAC attrs not satisfied? → DENY (ABAC — scenario 7 when role matches but no archiver)
4. Graph OBO disabled?       → DENY (RESOURCE — N/A for S3 tools)
5. Otherwise                 → ALLOW
```

\* Scenarios 3 and 6 have `rolesAllowed: ['admin']` because only admin can delete outside archive/

### LLM Path Risk

The LLM interprets the prompt and calls `delete_s3_object(bucket, key)`. The `key` parameter becomes `context.resource_path` for Cedar evaluation. If the LLM transforms the path (e.g., adds prefix), the Cedar check may produce unexpected results.

**Mitigation**: Prompts are explicit: *"Delete the file archive/old-report.csv from bucket sts-use1-mcp-poc-data"*

---

## Denial Tier Reference

| Badge | Color | Trigger | Layer |
|-------|-------|---------|-------|
| AGENT | Red | HTTP 401/403, `denial_reason` in body | A2A auth middleware |
| TOOL | Orange | `[TOOL_DENIAL]` in response text | MCP `require_cedar()` or `cedar_check_with_context()` |
| SCOPE | Amber | `[SCOPE_DENIAL]` in response text | (not used for ABAC — scope is Graph-only) |
| RESOURCE | Gray | Graph 403, S3 AccessDenied | Graph API / S3 API |

ABAC denials always produce **TOOL** (orange) badges because Cedar denial happens at the MCP tool layer.

---

## Archiver Toggle Interaction Matrix

| Toggle State | Effect on Tests | Header Sent |
|-------------|-----------------|-------------|
| OFF (default) | ABAC scenarios expect DENY for developer | No `X-Abac-Attrs` header |
| ON | Scenarios with `abacAttrs: {archiver: true}` expect ALLOW for developer in archive/ | `X-Abac-Attrs: {"archiver": true}` |

Switching the toggle resets all test matrix results (stale expectations cleared).

---

## Security Context Panel Checks

- [ ] Archiver checkbox visible below role selector
- [ ] Checkbox is unchecked by default
- [ ] Toggling ON sends `X-Abac-Attrs: {"archiver": true}` header (verify in DevTools Network tab)
- [ ] Toggling OFF removes the header entirely
- [ ] `/me` endpoint permissions list shows `delete_s3_object` as denied for developer (Phase 1 RBAC, no context)
- [ ] Token Inspector shows `archiver` claim in payload (Cognito user only, after access token customization)

---

## Test Execution Procedure

### Auth Bypass Mode (quick validation)

1. Set `dev_config.toml`: `disable_auth = true` for all 3 servers
2. Start all 4 services (MCP, ADK, A2A, frontend)
3. Select role: **developer**
4. Toggle archiver: **ON**
5. Run ABAC scenarios (4-7) from test matrix
6. Toggle archiver: **OFF**
7. Run scenario 7 (expect DENY)
8. Switch role: **admin**, run scenarios 1-3

### Real Cognito Auth

1. Sign in as `archiver@test.com` (Cognito)
2. Select role: **developer**
3. Toggle archiver: **ON** (or rely on token claim if access token customization is configured)
4. Run all 8 ABAC scenarios from test matrix
5. Verify Token Inspector shows `archiver` claim
