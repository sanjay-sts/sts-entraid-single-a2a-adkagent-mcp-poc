# MCP Multi-IdP: Frontend Testing Strategy

Testing MCP RBAC via the Security Testing Dashboard (React frontend).
Covers the full chain: **Frontend → A2A Gateway → ADK Agent → MCP Server → Graph API**.

Companion to `04-testing-strategy.md` (MCP Inspector).
Key difference: frontend adds the **scope dimension** (Graph API OAuth scopes)
and the **OBO dimension** (On-Behalf-Of token exchange for Graph API),
producing four denial tiers instead of two.

This document covers **both** OBO-disabled and OBO-enabled modes.
When OBO is disabled, Graph-dependent tools always fail (RESOURCE denial).
When OBO is enabled, Graph-dependent tools succeed if the role allows.

---

## OBO Configuration

OBO (On-Behalf-Of) token exchange allows MCP tools to call Graph API on behalf of the
authenticated user. Without OBO, Graph-dependent tools fail because the user's token
has audience `api://...` instead of `https://graph.microsoft.com`.

### Prerequisites for OBO

1. **`ENTRA_CLIENT_SECRET`** set in `.env` — the app registration's client secret
2. **Delegated Graph permissions** added to the app registration with **admin consent**:
   - `User.Read` — for `get_user_profile`
   - `Files.Read` — for `list_files`
   - `Mail.Send` — for `send_email`
3. MCP server startup log confirms: `"OBO exchanger initialized (tenant: ...)"`.
   Without client secret, log shows: `"OBO disabled -- ENTRA_CLIENT_SECRET not set"`

### `GRAPH_OBO_ENABLED` flag

In `testScenarios.js`, flip `GRAPH_OBO_ENABLED = true` after OBO setup is complete.
This changes the `shouldSucceed` computation for `graphDependency: 'required'` scenarios
from RESOURCE denial to ALLOW.

### How OBO changes the scope dimension

With OBO **disabled**: frontend scope preset is irrelevant for Graph tools — the token
audience is wrong regardless, so Graph always returns 401.

With OBO **enabled**: the MCP server exchanges the user's custom-audience token for a
Graph-scoped token using `OnBehalfOfCredential`. The scopes OBO requests are based on
the **app registration's consented permissions**, not the frontend scope preset. This
means `files_basic` (basic scope, missing `Files.Read`) succeeds just as well as
`files_correct` (files scope) — OBO requests `Files.Read` from Graph directly.

### Observability

- **`_obo_used: true`** in Graph tool responses indicates OBO was used
- **`_obo_used: false`** or absent indicates fallback to user token / token claims
- **`source: "token_claims"`** on `get_user_profile` means Graph failed, showing claims fallback

---

## Test Users

| User | Email | Entra Group | Group GUID | Role |
|------|-------|-------------|------------|------|
| Adele Vance | AdeleV@2tdgcb.onmicrosoft.com | AI-Agent-Admins | f1c467f2-954d-4e9d-8949-53a3492b0c14 | admin |
| Diego Siciliani | DiegoS@2tdgcb.onmicrosoft.com | AI-Agent-Developers | c6097742-e961-405f-9a45-2ca9fc971bd7 | developer |
| Johanna Lorenz | JohannaL@2tdgcb.onmicrosoft.com | AI-Agent-Viewers | a0cd9a0a-da7e-457c-8ca2-237529bb130f | viewer |
| No-group user | (any tenant user not in above groups) | (none) | — | none |

> stsadmin@ is in all 3 groups and resolves to **admin** (highest privilege wins).

---

## Tool × Role × Scope Matrix

| Tool | admin | developer | viewer | Required Graph Scope |
|------|-------|-----------|--------|----------------------|
| get_user_profile | Y | Y | Y | User.Read |
| list_files | Y | Y | N | Files.Read |
| send_email | Y | N | N | Mail.Send |
| delete_resource | Y | N | N | Files.ReadWrite.All |
| get_current_time | Y | N | N | *(none)* |
| convert_timezone | Y | N | N | *(none)* |
| get_time_difference | Y | N | N | *(none)* |

## Scope Presets

| Preset | Scopes Included | Unlocks |
|--------|----------------|---------|
| `basic` | api://..., User.Read | get_user_profile, time tools |
| `files` | + Files.Read | list_files |
| `email` | + Mail.Send | send_email |
| `full` | + Files.Read, Mail.Send | list_files, send_email |
| `destructive` | + Files.ReadWrite.All | delete_resource |

## Full RBAC Test Scenarios (from testScenarios.js)

14 scenarios defined. Each has: id, tool, scopeKey, prompt, rolesAllowed, requiredScopes, graphDependency.

`graphDependency` values:
- `'none'` — tool never calls Graph API (time tools, simulated delete)
- `'fallback'` — calls Graph but falls back to token claims on 401 (get_user_profile)
- `'required'` — calls Graph with no fallback; fails when OBO flow unavailable

`GRAPH_OBO_ENABLED = false` — set to `true` after configuring OBO (see OBO Configuration above).

`shouldSucceed` decision paths:

| # | Condition | Outcome | Notes |
|---|-----------|---------|-------|
| 1 | Role not in `rolesAllowed` | TOOL denial | Role check fires before Graph call |
| 2 | OBO disabled + `graphDependency === 'required'` | RESOURCE denial (Graph 401) | Token audience mismatch |
| 3 | OBO enabled + `graphDependency === 'required'` + role allowed | **ALLOW** | OBO exchanges token for Graph-scoped token |
| 4 | OBO enabled + scope missing in app registration | RESOURCE denial (Graph 403) | Edge case: app lacks consented permission |
| 5 | `graphDependency === 'fallback'` | ALLOW regardless | Without OBO: token claims. With OBO: full Graph profile |
| 6 | `graphDependency === 'none'` | ALLOW if role allowed | No Graph dependency (time tools, simulated delete) |

| # | ID | Tool | Scope Preset | Roles Allowed | Graph Dep | Required Scopes |
|---|-----|------|-------------|---------------|-----------|-----------------|
| 1 | profile_basic | get_user_profile | basic | admin, dev, viewer | fallback | User.Read |
| 2 | files_basic | list_files | basic | admin, dev | required | Files.Read |
| 3 | files_correct | list_files | files | admin, dev | required | Files.Read |
| 4 | email_basic | send_email | basic | admin | required | Mail.Send |
| 5 | email_correct | send_email | email | admin | required | Mail.Send |
| 6 | delete_basic | delete_resource | basic | admin | none | *(none)* |
| 7 | delete_destructive | delete_resource | destructive | admin | none | *(none)* |
| 8 | time_current | get_current_time | basic | admin | none | *(none)* |
| 9 | time_convert | convert_timezone | basic | admin | none | *(none)* |
| 10 | time_diff | get_time_difference | basic | admin | none | *(none)* |
| 11 | viewer_files | list_files | files | admin, dev | required | Files.Read |
| 12 | viewer_email | send_email | email | admin | required | Mail.Send |
| 13 | dev_email | send_email | email | admin | required | Mail.Send |
| 14 | dev_time | get_current_time | basic | admin | none | *(none)* |

**Expected outcome by role** (with `GRAPH_OBO_ENABLED = false`):

| # | ID | Admin | Developer | Viewer |
|---|-----|-------|-----------|--------|
| 1 | profile_basic | ALLOW (fallback to token claims) | ALLOW | ALLOW |
| 2 | files_basic | RESOURCE (Graph 401, no OBO) | RESOURCE (Graph 401) | TOOL deny |
| 3 | files_correct | RESOURCE (Graph 401, no OBO) | RESOURCE (Graph 401) | TOOL deny |
| 4 | email_basic | RESOURCE (Graph 401, no OBO) | TOOL deny | TOOL deny |
| 5 | email_correct | RESOURCE (Graph 401, no OBO) | TOOL deny | TOOL deny |
| 6 | delete_basic | ALLOW (simulated, no Graph) | TOOL deny | TOOL deny |
| 7 | delete_destructive | ALLOW (simulated, no Graph) | TOOL deny | TOOL deny |
| 8 | time_current | ALLOW | TOOL deny | TOOL deny |
| 9 | time_convert | ALLOW | TOOL deny | TOOL deny |
| 10 | time_diff | ALLOW | TOOL deny | TOOL deny |
| 11 | viewer_files | RESOURCE (Graph 401, no OBO) | RESOURCE (Graph 401) | TOOL deny |
| 12 | viewer_email | RESOURCE (Graph 401, no OBO) | TOOL deny | TOOL deny |
| 13 | dev_email | RESOURCE (Graph 401, no OBO) | TOOL deny | TOOL deny |
| 14 | dev_time | ALLOW | TOOL deny | TOOL deny |

**Expected outcome by role** (with `GRAPH_OBO_ENABLED = true`):

| # | ID | Admin | Developer | Viewer |
|---|-----|-------|-----------|--------|
| 1 | profile_basic | ALLOW (full Graph profile, `_obo_used: true`) | ALLOW (full Graph profile) | ALLOW (full Graph profile) |
| 2 | files_basic | ALLOW (`_obo_used: true`) | ALLOW (`_obo_used: true`) | TOOL deny |
| 3 | files_correct | ALLOW (`_obo_used: true`) | ALLOW (`_obo_used: true`) | TOOL deny |
| 4 | email_basic | ALLOW (`_obo_used: true`) | TOOL deny | TOOL deny |
| 5 | email_correct | ALLOW (`_obo_used: true`) | TOOL deny | TOOL deny |
| 6 | delete_basic | ALLOW (simulated, no Graph) | TOOL deny | TOOL deny |
| 7 | delete_destructive | ALLOW (simulated, no Graph) | TOOL deny | TOOL deny |
| 8 | time_current | ALLOW | TOOL deny | TOOL deny |
| 9 | time_convert | ALLOW | TOOL deny | TOOL deny |
| 10 | time_diff | ALLOW | TOOL deny | TOOL deny |
| 11 | viewer_files | ALLOW (`_obo_used: true`) | ALLOW (`_obo_used: true`) | TOOL deny |
| 12 | viewer_email | ALLOW (`_obo_used: true`) | TOOL deny | TOOL deny |
| 13 | dev_email | ALLOW (`_obo_used: true`) | TOOL deny | TOOL deny |
| 14 | dev_time | ALLOW | TOOL deny | TOOL deny |

**Key differences (OBO-disabled → OBO-enabled)**:

| Scenario change | Without OBO | With OBO |
|----------------|-------------|----------|
| Admin + Graph tools (#2-5, 11-13) | RESOURCE (Graph 401) | ALLOW (`_obo_used: true`) |
| Developer + files tools (#2, 3, 11) | RESOURCE (Graph 401) | ALLOW (`_obo_used: true`) |
| Viewer + profile (#1) | ALLOW (token claims) | ALLOW (full Graph profile) |
| All role denials | TOOL deny | TOOL deny (unchanged) |
| Non-Graph tools (#6-10, 14) | ALLOW / TOOL deny | Unchanged |

> **Note**: With OBO, the frontend scope preset becomes less relevant for Graph tools.
> OBO uses the app registration's consented permissions, not the scopes in the user's
> token. This means `files_basic` (basic scope) and `files_correct` (files scope)
> both succeed — OBO requests `Files.Read` from Graph directly.

## Denial Tier Reference

| Badge | Color | Trigger | Layer |
|-------|-------|---------|-------|
| **AGENT** | Red | 401/403 from A2A gateway | A2A Server |
| **TOOL** | Orange | `[TOOL_DENIAL]` in response | MCP Server |
| **SCOPE** | Amber | `[SCOPE_DENIAL]` or Graph 403 | Graph API |
| **RESOURCE** | Purple | Graph API domain error | Graph API |
| *(none)* | — | Success | — |

## Denial Classifier Detail (denialClassifier.js)

Classification order (first match wins):

| Priority | Check | Level | Reason |
|----------|-------|-------|--------|
| 1 | HTTP status 401 or 403 | agent | `responseBody.denial_reason` or `responseBody.error` |
| 2 | Response contains `[TOOL_DENIAL]` | tool | role_denied |
| 3 | Response contains `[SCOPE_DENIAL]` | scope | missing_scopes |
| 4 | Regex `/Role.*cannot use/i` | tool | role_denied |
| 5 | Regex `/Missing scopes/i` or `/Insufficient permissions/i` | scope | missing_scopes |
| 6 | Regex: `/graph_api_unavailable/i`, `/(401\|403).*graph/i`, `/graph.*(401\|403)/i`, `/401.*unauthorized/i`, `/OBO flow/i`, `/insufficient_scope/i`, `/Access is denied/i` | resource | graph_api_denied |
| 7 | Regex `/Access denied/i` (but NOT `/Role.*cannot/i`) | tool | access_denied |
| 8 | None of above | *(null)* | success |

> **OBO note**: With OBO enabled, the `/OBO flow/i` pattern (priority 6) is less likely
> to match — OBO errors are caught in `_get_graph_token()` and result in a `None` return
> (graceful fallback), not error messages containing "OBO flow". The
> `graph_api_unavailable` pattern remains relevant for OBO failure fallback on
> `list_files` and `send_email`.

---

## Dashboard Setup

1. Start all services (MCP → ADK → A2A → Frontend)
2. Open http://localhost:10003
3. Sign in via "Sign In with Microsoft"
4. Select scope preset in conversation tab dropdown (top-right of tab)
5. Role selector appears in **Security Context Panel** (left sidebar) after `/me` loads

---

## Test Suite A: AdeleV (Admin)

### A1: Admin role — Security Context Panel

```
Sign in as: AdeleV@2tdgcb.onmicrosoft.com
Role selector: admin
Scope preset: destructive

Security Context Panel (GET /me):
✓ Role badge: ADMIN (green)
✓ available_roles: ['admin']
✓ Permissions: all 7 tools checked
✓ Groups: f1c467f2... → admin
✓ Token Expiry: countdown running (green > 5 min)
✓ Token Scopes: includes User.Read, Files.Read, Mail.Send, Files.ReadWrite.All
```

### A2: Admin role — RBAC Test Matrix (Run All, destructive scope)

```
Role selector: admin
Scope preset: destructive (ensures all scopes present)
Click: Run All

Expected results (all 14 should show PASS):
| # | Scenario           | Expected  | Denial   | Why                              |
|---|--------------------|-----------|----------|----------------------------------|
| 1 | profile_basic      | ALLOW     | —        | fallback to token claims         |
| 2 | files_basic        | RESOURCE  | Graph401 | OBO not implemented              |
| 3 | files_correct      | RESOURCE  | Graph401 | OBO not implemented              |
| 4 | email_basic        | RESOURCE  | Graph401 | OBO not implemented              |
| 5 | email_correct      | RESOURCE  | Graph401 | OBO not implemented              |
| 6 | delete_basic       | ALLOW     | —        | simulated, no Graph call         |
| 7 | delete_destructive | ALLOW     | —        | simulated, no Graph call         |
| 8 | time_current       | ALLOW     | —        | no Graph dependency              |
| 9 | time_convert       | ALLOW     | —        | no Graph dependency              |
| 10| time_diff          | ALLOW     | —        | no Graph dependency              |
| 11| viewer_files       | RESOURCE  | Graph401 | admin has role, Graph fails      |
| 12| viewer_email       | RESOURCE  | Graph401 | admin has role, Graph fails      |
| 13| dev_email          | RESOURCE  | Graph401 | admin has role, Graph fails      |
| 14| dev_time           | ALLOW     | —        | no Graph dependency              |

Note: scenarios 11-13 are named viewer_*/dev_* but when running as admin,
the admin HAS role access — the denial comes from Graph API, not role check.
```

### A2-OBO: Admin role — RBAC Test Matrix (with OBO enabled)

```
Prerequisites: GRAPH_OBO_ENABLED = true in testScenarios.js
Role selector: admin
Scope preset: destructive
Click: Run All

Expected results (all 14 should show PASS):
| # | Scenario           | Expected  | Denial   | Why                              |
|---|--------------------|-----------|----------|----------------------------------|
| 1 | profile_basic      | ALLOW     | —        | full Graph profile (_obo_used)   |
| 2 | files_basic        | ALLOW     | —        | OBO exchanges token for Graph    |
| 3 | files_correct      | ALLOW     | —        | OBO exchanges token for Graph    |
| 4 | email_basic        | ALLOW     | —        | OBO exchanges token for Graph    |
| 5 | email_correct      | ALLOW     | —        | OBO exchanges token for Graph    |
| 6 | delete_basic       | ALLOW     | —        | simulated, no Graph call         |
| 7 | delete_destructive | ALLOW     | —        | simulated, no Graph call         |
| 8 | time_current       | ALLOW     | —        | no Graph dependency              |
| 9 | time_convert       | ALLOW     | —        | no Graph dependency              |
| 10| time_diff          | ALLOW     | —        | no Graph dependency              |
| 11| viewer_files       | ALLOW     | —        | admin has role, OBO works        |
| 12| viewer_email       | ALLOW     | —        | admin has role, OBO works        |
| 13| dev_email          | ALLOW     | —        | admin has role, OBO works        |
| 14| dev_time           | ALLOW     | —        | no Graph dependency              |

Key difference from A2: scenarios 2-5, 11-13 change from RESOURCE → ALLOW.
All responses for Graph tools include `_obo_used: true`.
```

### A3: Admin — Graph API denial (correct role, Graph returns 401)

```
Role selector: admin
Scope preset: basic  (missing Files.Read, Mail.Send, Files.ReadWrite.All)

Chat prompts and expected denial badges:
"List my OneDrive files"         → RESOURCE (purple) — Graph 401, OBO not implemented
"Send email to test@example.com" → RESOURCE (purple) — Graph 401, OBO not implemented
"Delete resource abc123"         → SUCCESS (no badge) — simulated, never calls Graph
"What time is it in Tokyo?"      → SUCCESS (no badge) — time tools need no scope
"What's my email?"               → SUCCESS (no badge) — fallback to token claims

Note: With OBO not implemented, Graph-dependent tools fail with 401 regardless
of scope preset. The scope distinction only matters once OBO is enabled.
```

### A3-OBO: Admin — Graph tools succeed with OBO

```
Prerequisites: GRAPH_OBO_ENABLED = true
Role selector: admin
Scope preset: basic  (scope preset is irrelevant with OBO)

Chat prompts and expected outcomes:
"List my OneDrive files"         → SUCCESS (no badge) — OBO exchanges token (_obo_used: true)
"Send email to test@example.com" → SUCCESS (no badge) — OBO exchanges token (_obo_used: true)
"Delete resource abc123"         → SUCCESS (no badge) — simulated, never calls Graph
"What time is it in Tokyo?"      → SUCCESS (no badge) — time tools need no scope
"What's my email?"               → SUCCESS (no badge) — full Graph profile (_obo_used: true)

Key difference from A3: Graph-dependent tools now succeed.
The `_obo_used: true` flag in responses confirms OBO was used.
```

### A4: Admin — RBAC Matrix with basic scope

```
Role selector: admin
Scope preset: basic

| Scenario      | Expected  | Denial   | Why                     |
|---------------|-----------|----------|-------------------------|
| files_basic   | RESOURCE  | Graph401 | OBO not implemented     |
| email_basic   | RESOURCE  | Graph401 | OBO not implemented     |
| delete_basic  | ALLOW     | —        | simulated, no Graph     |
| profile_basic | ALLOW     | —        | fallback to token claims|
| time_current  | ALLOW     | —        | no Graph dependency     |
```

### A5: Admin assumes viewer via role switcher

```
Prerequisites: permissions.toml has:
  "AdeleV@2tdgcb.onmicrosoft.com" = { role = "viewer" }

Role selector: switch to viewer

Security Context Panel:
✓ Role badge changes to VIEWER (yellow)
✓ available_roles now shows ['admin', 'viewer']
✓ Permissions: only get_user_profile checked

RBAC Matrix:
✓ Results clear on role switch
✓ Run All — all DENY scenarios for viewer show PASS
```

### A6: No role header (simulate by clearing X-Assume-Role)

```
Note: The role selector in SecurityContextPanel always sends X-Assume-Role.
To test missing role header, use browser DevTools to intercept or
use MCP Inspector (see 04-testing-strategy.md A3).
Not directly testable from the frontend UI.
```

---

## Test Suite B: DiegoS (Developer)

### B1: Developer role — Security Context Panel

```
Sign in as: DiegoS@2tdgcb.onmicrosoft.com
Role selector: developer
Scope preset: full

Security Context Panel (GET /me):
✓ Role badge: DEVELOPER (blue)
✓ available_roles: ['developer']
✓ Permissions: get_user_profile ✓, list_files ✓, others unchecked
✓ Groups: c6097742... → developer
```

### B2: Developer role — RBAC Test Matrix

```
Role selector: developer
Scope preset: full (all scopes present — isolates role-only denials)
Click: Run All

| # | Scenario           | Expected  | Denial   | Why                              |
|---|--------------------|-----------|----------|----------------------------------|
| 1 | profile_basic      | ALLOW     | —        | fallback to token claims         |
| 2 | files_basic        | RESOURCE  | Graph401 | dev has role, OBO not implemented|
| 3 | files_correct      | RESOURCE  | Graph401 | dev has role, OBO not implemented|
| 4 | email_basic        | RESOURCE  | Graph401 | admin-only, but OBO fails first  |
| 5 | email_correct      | TOOL      | role     | developer lacks send_email       |
| 6 | delete_basic       | TOOL      | role     | developer lacks delete_resource  |
| 7 | delete_destructive | TOOL      | role     | developer lacks delete_resource  |
| 8 | time_current       | TOOL      | role     | developer lacks time tools       |
| 9 | time_convert       | TOOL      | role     | developer lacks time tools       |
| 10| time_diff          | TOOL      | role     | developer lacks time tools       |
| 11| viewer_files       | RESOURCE  | Graph401 | dev has role, OBO not implemented|
| 12| viewer_email       | TOOL      | role     | developer lacks send_email       |
| 13| dev_email          | TOOL      | role     | developer lacks send_email       |
| 14| dev_time           | TOOL      | role     | developer lacks time tools       |

Note: files_basic/files_correct/viewer_files — developer HAS role access to
list_files, so the role check passes. Denial comes from Graph API 401 (no OBO).
```

### B2-OBO: Developer role — RBAC Test Matrix (with OBO enabled)

```
Prerequisites: GRAPH_OBO_ENABLED = true
Role selector: developer
Scope preset: full
Click: Run All

| # | Scenario           | Expected  | Denial   | Why                              |
|---|--------------------|-----------|----------|----------------------------------|
| 1 | profile_basic      | ALLOW     | —        | full Graph profile (_obo_used)   |
| 2 | files_basic        | ALLOW     | —        | dev has role + OBO works         |
| 3 | files_correct      | ALLOW     | —        | dev has role + OBO works         |
| 4 | email_basic        | TOOL      | role     | developer lacks send_email       |
| 5 | email_correct      | TOOL      | role     | developer lacks send_email       |
| 6 | delete_basic       | TOOL      | role     | developer lacks delete_resource  |
| 7 | delete_destructive | TOOL      | role     | developer lacks delete_resource  |
| 8 | time_current       | TOOL      | role     | developer lacks time tools       |
| 9 | time_convert       | TOOL      | role     | developer lacks time tools       |
| 10| time_diff          | TOOL      | role     | developer lacks time tools       |
| 11| viewer_files       | ALLOW     | —        | dev has role + OBO works         |
| 12| viewer_email       | TOOL      | role     | developer lacks send_email       |
| 13| dev_email          | TOOL      | role     | developer lacks send_email       |
| 14| dev_time           | TOOL      | role     | developer lacks time tools       |

Key difference from B2: scenarios 2, 3, 11 change from RESOURCE → ALLOW.
Role denials (#4-10, 12-14) are identical — role check is OBO-independent.
```

### B3: Developer — chat denial badges

```
Role selector: developer
Scope preset: full

"What's my email?"              → SUCCESS (no badge) — fallback to token claims
"List my OneDrive files"        → RESOURCE (purple) — Graph 401, OBO not implemented
"What time is it in Tokyo?"     → TOOL (orange) — role restriction
"Send email to test@example.com"→ TOOL (orange) — role restriction
"Delete resource abc123"        → TOOL (orange) — role restriction
```

### B3-OBO: Developer — chat denial badges (with OBO enabled)

```
Prerequisites: GRAPH_OBO_ENABLED = true
Role selector: developer
Scope preset: full

"What's my email?"              → SUCCESS (no badge) — full Graph profile (_obo_used: true)
"List my OneDrive files"        → SUCCESS (no badge) — OBO works, dev has role
"What time is it in Tokyo?"     → TOOL (orange) — role restriction (unchanged)
"Send email to test@example.com"→ TOOL (orange) — role restriction (unchanged)
"Delete resource abc123"        → TOOL (orange) — role restriction (unchanged)

Key difference from B3: "List my OneDrive files" changes from RESOURCE → SUCCESS.
```

### B4: Developer — Graph dependency vs scope

```
Role selector: developer
Scope preset: basic (missing Files.Read)

"List my OneDrive files" → RESOURCE (purple) — Graph 401 (OBO not implemented)
                           Note: with OBO disabled, scope doesn't matter — Graph
                           rejects the token entirely. Once OBO is implemented,
                           this would become a scope-level denial.
```

### B5: Developer tries to assume admin

```
Role selector: attempt to select 'admin'
(admin should not appear in dropdown — available_roles only shows ['developer'])

If manually forced via DevTools headers:
→ TOOL denial: "Cannot assume role 'admin'. Available roles: ['developer']"
```

### B6: Developer with viewer override

```
Prerequisites: permissions.toml has:
  "DiegoS@2tdgcb.onmicrosoft.com" = { role = "viewer" }

Role selector: switch to viewer

Security Context Panel:
✓ available_roles now: ['developer', 'viewer']
✓ Permissions: only get_user_profile checked

Chat: "List my OneDrive files" → TOOL (orange) — viewer cannot list_files
```

---

## Test Suite C: JohannaL (Viewer)

### C1: Viewer role — Security Context Panel

```
Sign in as: JohannaL@2tdgcb.onmicrosoft.com
Role selector: viewer
Scope preset: full

Security Context Panel (GET /me):
✓ Role badge: VIEWER (yellow)
✓ available_roles: ['viewer']
✓ Permissions: only get_user_profile checked
✓ Groups: a0cd9a0a... → viewer
```

### C2: Viewer role — RBAC Test Matrix

```
Role selector: viewer
Scope preset: full (all scopes present — isolates role denials)
Click: Run All

| # | Scenario           | Expected | Denial |
|---|--------------------|----------|--------|
| 1 | profile_basic      | ALLOW    | —      |
| 2 | files_correct      | DENY     | TOOL   |
| 3 | email_correct      | DENY     | TOOL   |
| 4 | delete_correct     | DENY     | TOOL   |
| 5 | time_basic         | DENY     | TOOL   |
| 6 | time_convert       | DENY     | TOOL   |
| 7 | time_diff          | DENY     | TOOL   |
```

### C3: Viewer — chat denial badges

```
Role selector: viewer
Scope preset: full

"What's my email?"              → SUCCESS (no badge)
"List my OneDrive files"        → TOOL (orange)
"What time is it in Tokyo?"     → TOOL (orange)
"Send email to test@example.com"→ TOOL (orange)
"Delete resource abc123"        → TOOL (orange)
```

### C2-OBO / C3-OBO: Viewer with OBO enabled

```
Prerequisites: GRAPH_OBO_ENABLED = true
Role selector: viewer
Scope preset: full

RBAC Matrix (Run All):
| # | Scenario           | Expected | Denial |
|---|--------------------|----------|--------|
| 1 | profile_basic      | ALLOW    | —      | ← full Graph profile (_obo_used: true)
| 2 | files_correct      | DENY     | TOOL   |
| 3 | email_correct      | DENY     | TOOL   |
| 4 | delete_correct     | DENY     | TOOL   |
| 5 | time_basic         | DENY     | TOOL   |
| 6 | time_convert       | DENY     | TOOL   |
| 7 | time_diff          | DENY     | TOOL   |

Chat denial badges:
"What's my email?"              → SUCCESS — full Graph profile (_obo_used: true)
"List my OneDrive files"        → TOOL (orange) — unchanged
"What time is it in Tokyo?"     → TOOL (orange) — unchanged
"Send email to test@example.com"→ TOOL (orange) — unchanged
"Delete resource abc123"        → TOOL (orange) — unchanged

Key difference: profile_basic now returns full Graph profile instead of
token claims fallback. All role denials unchanged — role check fires before Graph.
```

### C4: Viewer promoted via user override

```
Prerequisites: permissions.toml has:
  "JohannaL@2tdgcb.onmicrosoft.com" = { role = "admin" }

Role selector: switch to admin

Security Context Panel:
✓ available_roles: ['admin', 'viewer']
✓ Permissions: all 7 tools checked

Chat: "What time is it in Tokyo?" → SUCCESS (no badge)
```

---

## Test Suite D: No-Group User

### D1: Authenticated but no group — agent-level denial

```
Sign in as: user not in AI-Agent-Admins, Developers, or Viewers
(Any tenant user without group membership)

Expected: A2A gateway blocks with 403 before reaching ADK/MCP

Chat: any message → AGENT (red badge)
Security Context Panel: Role badge shows NONE (red)
HTTP status: 403 in Audit Log
denial_reason in response body: "no_group_membership"
```

### D2: Blocked user

```
Prerequisites: .env has BLOCKED_USERS=<user-object-id>

Sign in as: that user

Chat: any message → AGENT (red badge)
HTTP status: 403
denial_reason: "blocked_user"
```

## Test Suite D3: stsadmin (Multi-Group User)

### D3.1: User in all 3 groups — resolves to highest role

```
Sign in as: stsadmin@2tdgcb.onmicrosoft.com
(Member of AI-Agent-Admins, AI-Agent-Developers, AND AI-Agent-Viewers)

Security Context Panel:
✓ Role badge: ADMIN (green) — highest privilege wins
✓ available_roles: ['admin', 'developer', 'viewer'] (all three)
✓ Groups: shows all 3 group GUIDs with role mappings
✓ Permissions: all 7 tools checked (admin)
```

### D3.2: stsadmin steps down to developer

```
Role selector: switch to developer

Security Context Panel:
✓ Role badge: DEVELOPER (blue)
✓ Permissions: get_user_profile ✓, list_files ✓, others unchecked

Chat: "What time is it?" → TOOL (orange) — developer cannot use time tools
Chat: "List my files"    → RESOURCE (purple) — Graph 401, OBO not implemented
```

### D3.2-OBO: stsadmin as developer (with OBO enabled)

```
Prerequisites: GRAPH_OBO_ENABLED = true
Role selector: switch to developer

Chat: "What time is it?" → TOOL (orange) — developer cannot use time tools (unchanged)
Chat: "List my files"    → SUCCESS (no badge) — dev has role + OBO works (_obo_used: true)
```

### D3.3: stsadmin steps down to viewer

```
Role selector: switch to viewer

Security Context Panel:
✓ Role badge: VIEWER (yellow)
✓ Permissions: only get_user_profile checked

Chat: "List my files"    → TOOL (orange) — viewer cannot list_files
Chat: "What's my email?" → SUCCESS
```

### D3.4: Full RBAC Matrix as each role

```
1. Role: admin, scope: destructive → Run All → all 14 PASS
   - profile_basic: ALLOW (token claims fallback)
   - files/email scenarios: RESOURCE (Graph 401, no OBO)
   - delete/time scenarios: ALLOW (no Graph dependency)
2. Switch role: developer → results clear → Run All → verify:
   - TOOL denials for email/delete/time tools
   - RESOURCE for files scenarios (dev has role, Graph fails)
3. Switch role: viewer → results clear → Run All → verify all non-profile are TOOL deny

With OBO enabled (GRAPH_OBO_ENABLED = true):
1. Role: admin, scope: destructive → Run All → all 14 ALLOW (no denials at all)
2. Switch role: developer → results clear → Run All → verify:
   - ALLOW for profile + files scenarios (OBO works)
   - TOOL denials for email/delete/time tools (unchanged)
3. Switch role: viewer → all non-profile are TOOL deny (unchanged)
   - profile_basic: ALLOW with full Graph profile (_obo_used: true)
```

---

## Test Suite E: Role Switching (Frontend-Specific)

### E1: Switch role without re-login

```
Sign in as: AdeleV@2tdgcb.onmicrosoft.com (admin by default)

1. Role badge shows ADMIN — all 7 permissions checked
2. Click role dropdown → select (if available_roles has multiple)
   OR: use permissions.toml override to add second role

3. Switch role to viewer:
   ✓ Role badge changes immediately to VIEWER
   ✓ Permissions panel updates (only get_user_profile checked)
   ✓ RBAC Matrix results clear automatically
   ✓ No re-login required

4. Send "What time is it?" → TOOL (orange) — viewer cannot use time tools
5. Switch back to admin → send again → SUCCESS
```

### E2: Role selector shows only available roles

```
Sign in as: DiegoS@2tdgcb.onmicrosoft.com

Role dropdown should show: ['developer'] only
(admin and viewer NOT selectable — not in available_roles)

Verify: /me response has "available_roles": ["developer"]
```

### E3: Effective role reflected in Audit Log

```
1. Sign in as AdeleV (admin)
2. Chat: "What time is it?" → Audit Log row shows role: admin
3. Switch role to viewer (with override)
4. Chat: "What time is it?" → Audit Log row shows role: viewer
5. Verify denial badge changes from none (admin) to TOOL (viewer)
```

---

## Test Suite F: Account Switching (Frontend-Specific)

### F1: Add second account

```
1. Sign in as AdeleV (admin)
2. Click "Add Account" button in header
3. Sign in as DiegoS (developer) in popup
4. Account dropdown now shows both accounts

Switch to DiegoS:
✓ Security Context Panel refreshes with DiegoS's role (DEVELOPER)
✓ available_roles updates to ['developer']
✓ Token Inspector shows DiegoS's groups claim
✓ RBAC Matrix results clear

Switch back to AdeleV:
✓ Security Context Panel refreshes back to ADMIN
```

### F2: Per-account role is independent

```
1. Sign in as AdeleV (admin) and DiegoS (developer)
2. While viewing AdeleV: chat "What time is it?" → SUCCESS
3. Switch to DiegoS: chat "What time is it?" → TOOL (orange)
4. Audit Log shows different roles for each request
```

### F3: Multi-tab + multi-account

```
1. Sign in as AdeleV (admin)
2. Open 2 chat tabs:
   Tab 1: scope = basic
   Tab 2: scope = files
3. Switch to DiegoS account
4. Tab 2 chat: "List my OneDrive files" → RESOURCE (Graph 401, no OBO)
   With OBO: → SUCCESS (_obo_used: true) — dev has role, OBO works
5. Switch back to AdeleV
6. Tab 1 chat: "List my OneDrive files" → RESOURCE (Graph 401, no OBO)
   With OBO: → SUCCESS (_obo_used: true) — admin has role, OBO works
```

---

## Test Suite G: Scope × Role Interaction

### G1: Role allows but Graph API fails (RESOURCE denial, not TOOL) — OBO disabled

```
Sign in as: AdeleV (admin)
Scope preset: basic (no Files.Read)
Role selector: admin

"List my OneDrive files" → RESOURCE (purple), NOT TOOL
Rationale: admin has role permission, but Graph API returns 401 because OBO
flow is not implemented. The token audience is api://... not https://graph.microsoft.com.
```

### G1-OBO: Role allows and OBO exchanges token → SUCCESS

```
Prerequisites: GRAPH_OBO_ENABLED = true
Sign in as: AdeleV (admin)
Scope preset: basic (no Files.Read — doesn't matter with OBO)
Role selector: admin

"List my OneDrive files" → SUCCESS (no badge)
Rationale: admin has role permission, and OBO exchanges the user's token for a
Graph-scoped token with Files.Read. The frontend scope preset is irrelevant
because OBO uses the app registration's consented permissions.
Response includes: _obo_used: true
```

### G2: Scope present but role missing (TOOL denial, not SCOPE)

```
Sign in as: DiegoS (developer)
Scope preset: email (has Mail.Send)
Role selector: developer

"Send email to test@example.com" → TOOL (orange), NOT SCOPE
Rationale: scope is present, but developer lacks send_email role permission
```

### G3: Both role and scope missing

```
Sign in as: JohannaL (viewer)
Scope preset: basic (no Files.Read)
Role selector: viewer

"List my OneDrive files" → TOOL (orange)
Rationale: role check (viewer cannot list_files) fires before scope check
```

### G4: Time tools — role-gated, no scope needed

```
Sign in as: AdeleV (admin)
Scope preset: basic (minimal scopes)
Role selector: admin

"What time is it in Tokyo?"  → SUCCESS — time tools require no Graph scope
"Convert 3pm EST to PST"     → SUCCESS
"Time difference NYC London" → SUCCESS
```

### G5-OBO: Scope preset irrelevant with OBO

```
Prerequisites: GRAPH_OBO_ENABLED = true
Sign in as: AdeleV (admin)
Scope preset: basic (minimal scopes — missing Files.Read, Mail.Send)
Role selector: admin

"List my OneDrive files"         → SUCCESS — OBO gets Files.Read from app registration
"Send email to test@example.com" → SUCCESS — OBO gets Mail.Send from app registration
"What's my email?"               → SUCCESS — OBO gets User.Read (full Graph profile)

Demonstrates: with OBO, the frontend scope preset does not gate Graph API access.
The MCP server exchanges the user's token for a Graph-scoped token using
app registration permissions, bypassing the user token's scope list entirely.

All responses include _obo_used: true.
```

---

## Test Suite H: Token Inspector Verification

### H1: Token claims visible

```
Sign in as: AdeleV (admin)
Expand Token Inspector in sidebar

Header section:
✓ alg: RS256
✓ typ: JWT
✓ kid: (key ID string)

Payload section (highlighted fields):
✓ groups: ["f1c467f2-954d-4e9d-8949-53a3492b0c14"]  ← admin group
✓ scp: "access_as_user User.Read ..."
✓ aud: "api://647e61a7-..." or client-id UUID
✓ iss: "https://login.microsoftonline.com/{tenant}/v2.0" or "https://sts.windows.net/{tenant}/"
✓ exp: (unix timestamp, matches countdown in SecurityContextPanel)
✓ preferred_username: "AdeleV@2tdgcb.onmicrosoft.com"
```

### H2: Token changes on account switch

```
1. Token Inspector shows AdeleV's groups: [f1c467f2...]
2. Switch to DiegoS account
3. Token Inspector now shows DiegoS's groups: [c6097742...]
4. iss and aud fields identical (same app registration)
```

### H3: Issuer reflects token version

```
For v2.0 token: iss = "https://login.microsoftonline.com/{tenant}/v2.0"
For v1.0 token: iss = "https://sts.windows.net/{tenant}/"
Both are accepted by MCP server MultiAuth verifier.
```

---

## Test Suite I: Hot Reload

### I1: Group role change without restart

```
1. Sign in as AdeleV (admin group f1c467f2...)
2. SecurityContextPanel shows ADMIN, all 7 permissions
3. Edit permissions.toml: change f1c467f2 mapping from "admin" to "viewer"
4. Click "Refresh" button in SecurityContextPanel (or wait for auto-refresh)
5. GET /me should now return role: viewer, available_roles: ['viewer']
6. Permissions update: only get_user_profile checked
7. Chat: "What time is it?" → TOOL (orange)
```

### I2: User override added without restart

```
1. AdeleV has only admin from group (no override)
2. Role dropdown shows: ['admin'] only
3. Edit permissions.toml: add "AdeleV@2tdgcb.onmicrosoft.com" = { role = "viewer" }
4. Refresh SecurityContextPanel
5. available_roles now: ['admin', 'viewer']
6. Role dropdown shows both options
```

---

## Test Suite J: Audit Log

### J1: Entry recorded per request

```
1. Send 3 chat messages with different roles/scopes
2. Audit Log shows 3 rows with:
   ✓ # (sequential)
   ✓ Time (timestamp)
   ✓ Prompt (truncated to ~50 chars)
   ✓ Scope (preset name)
   ✓ Role (assumed role)
   ✓ HTTP Status (200 or 403)
   ✓ Denial Level (AGENT/TOOL/SCOPE/RESOURCE or —)
   ✓ Latency (ms)
```

### J2: Row expansion

```
Click any Audit Log row:
✓ Full prompt text visible
✓ Full response JSON visible
✓ denial_level and denial_reason fields readable
```

### J3: Export and clear

```
Click "Copy JSON":
✓ Clipboard contains valid JSON array of all entries
✓ Each entry has: timestamp, prompt, scope, role, status, denial_level, latency

Click "Clear":
✓ All rows removed
✓ Counter resets
```

---

## Expected Denial Messages (Frontend Display)

| Scenario | Badge | HTTP | Message in Chat |
|----------|-------|------|-----------------|
| No group membership | AGENT (red) | 403 | "Not a member of any authorized group" |
| Blocked user | AGENT (red) | 403 | "Your account has been blocked" |
| Token missing/expired | AGENT (red) | 401 | "Token has expired" / "Missing Authorization" |
| Role lacks tool access | TOOL (orange) | 200 | "[TOOL_DENIAL] Access denied: Role '...' cannot use this tool" |
| Invalid role selection | TOOL (orange) | 200 | "[TOOL_DENIAL] Cannot assume role '...'. Available roles: [...]" |
| No role header | TOOL (orange) | 200 | "[ROLE_SELECTION] Role selection required..." |
| No roles available | TOOL (orange) | 200 | "[TOOL_DENIAL] No roles available for {email}" |
| Missing Graph scope | SCOPE (amber) | 200 | Response contains Graph API 403 or scope error |
| Non-Entra provider (Graph tool) | *(none)* | 200 | `"error": "provider_not_supported"` — Graph not available for {provider} |
| OBO exchange failed (list_files/send_email) | RESOURCE (purple) | 200 | `"error": "graph_api_unavailable"` with `_obo_used: false` |
| OBO exchange failed (get_user_profile) | *(none)* | 200 | `"source": "token_claims"` with `_obo_used: false` — fallback to claims |
| OBO success (any Graph tool) | *(none)* | 200 | Full Graph response with `_obo_used: true` |

---

## Dashboard Component Quick Reference

| Component | Location | How to use |
|-----------|----------|------------|
| SecurityContextPanel | Left sidebar | Shows live role/groups/permissions from GET /me. Use role dropdown to switch assumed role. |
| Token Inspector | Left sidebar (collapsible) | Expand to see decoded JWT header + payload. Refreshes on account switch. |
| RBAC Test Matrix | Left sidebar (collapsible) | Click Run All to execute all scenarios for the current role. Results clear on role switch. |
| Conversation Tabs | Main area | "+" adds a tab (max 4). Each tab has its own scope preset. Chat history is per-tab. |
| Audit Log | Main area (bottom) | Records every request. Expandable rows, Copy JSON, Clear buttons. |
| AuthStatus / Account Switcher | Header | Dropdown when 2+ accounts. "Add Account" logs in a second user. |

---

## How to Get a Test Token (for curl / DevTools verification)

### Option 1: Token Inspector (simplest)
```
1. Sign in at http://localhost:10003
2. Select "destructive" scope preset
3. Expand Token Inspector in left sidebar
4. Copy the raw token string shown in the panel
```

### Option 2: Browser DevTools Network tab
```
1. Sign in and send a chat message
2. Open DevTools (F12) → Network tab
3. Find the POST request to http://localhost:10000/
4. Headers tab → Authorization: Bearer <token>
5. Copy the token value (after "Bearer ")
```

### Option 3: Browser Local Storage
```
1. Sign in at http://localhost:10003
2. DevTools → Application → Local Storage → http://localhost:10003
3. Find the MSAL cache entry with target containing "access_as_user"
4. Copy the "secret" field value
```

### Token Notes
- Tokens expire in ~75 minutes. Re-acquire before each test session.
- Use the token with `target: "api://647e61a7.../access_as_user"`, NOT the Graph API token
- The Graph API token (aud: 00000003-...) is rejected by MCP server

### Verify token works with curl
```bash
# Check /me endpoint (A2A server)
curl -H "Authorization: Bearer <token>" \
     -H "X-Assume-Role: admin" \
     http://localhost:10000/me | python -m json.tool
```

---

## Test Suite K: UI Behavior & Edge Cases

### K1: Login prompt (unauthenticated state)

```
1. Open http://localhost:10003 without signing in
2. Should see LoginPrompt:
   ✓ "Welcome to the Identity-Aware AI Agent" heading
   ✓ "Sign in with your Microsoft account" subheading
   ✓ Bullet list of 3-tier access control explanation
   ✓ "Sign In with Microsoft" button
3. Dashboard not visible until authenticated
```

### K2: Sidebar collapse/expand toggle

```
1. Sign in — sidebar expanded by default
2. Click hamburger button (◀) to collapse sidebar
   ✓ Sidebar content hidden
   ✓ Arrow changes to ▶
3. Click again to expand
   ✓ SecurityContextPanel, TokenInspector, RBACTestMatrix visible again
```

### K3: Welcome message in empty chat

```
1. Open a new conversation tab
2. Before sending any message:
   ✓ Chat area shows welcome message (not blank)
3. Send first message → welcome message replaced by conversation
```

### K4: Loading indicator during chat

```
1. Send a chat message
2. While waiting for response:
   ✓ "Agent is thinking..." indicator visible
   ✓ Input field disabled
   ✓ Send button disabled
3. After response arrives:
   ✓ Indicator disappears
   ✓ Input field re-enabled
```

### K5: Auto-scroll to latest message

```
1. Send enough messages to fill the chat viewport
2. Send another message
   ✓ Chat auto-scrolls to show latest agent response
```

### K6: Token expiry countdown states

```
Sign in and observe SecurityContextPanel:

✓ Green (expiry-ok): > 5 minutes remaining
✓ Amber (expiry-warning): < 5 minutes remaining
✓ Red (expiry-expired): 0 or negative — shows "EXPIRED"
✓ Countdown updates every 1 second
✓ Format: MM:SS (e.g., "12:30")

To test expiry transitions:
- Wait ~70 minutes for token to approach expiry
- Or inspect the exp claim in Token Inspector and calculate
```

### K7: Auto-selection of highest role on first load

```
1. Sign in as stsadmin@ (in all 3 groups)
2. On first load, before touching role selector:
   ✓ Role auto-set to 'admin' (highest available)
   ✓ SecurityContextPanel shows ADMIN badge
   ✓ No manual selection required
```

### K8: Conversation tab limits

```
1. Start with 1 tab (default)
   ✓ Close button (×) hidden on the single tab
   ✓ "+" button visible

2. Add tabs until 4 tabs exist
   ✓ "+" button disappears at 4 tabs (MAX_TABS)
   ✓ Close button (×) visible on all tabs

3. Close a tab → "+" reappears
4. Close down to 1 tab → close button hidden again
```

### K9: Scope picker dropdown

```
1. Click "+" to add a tab
2. Scope picker dropdown appears with options:
   ✓ basic, files, email, full, destructive
   ✓ Each shows scope list (api:// prefix filtered out)
3. Select a scope → new tab created with that scope
4. Scope picker closes
```

### K10: Per-tab independent state

```
1. Open Tab 1 (basic scope) → send "What's my email?"
2. Open Tab 2 (files scope) → send "List my files"
3. Switch to Tab 1:
   ✓ Tab 1 still shows its own message history
   ✓ Tab 2 messages not visible
4. Switch to Tab 2:
   ✓ Tab 2 shows its own messages
```

### K11: AuditLog collapse/expand

```
1. Audit Log header shows "Audit Log (N)" with entry count
2. Click header to collapse → table hidden, arrow ▶
3. Click again to expand → table visible, arrow ▼
```

### K12: AuditLog HTTP status color coding

```
After running tests:
✓ HTTP 200 rows: normal background
✓ HTTP 403 rows: red/error background (class http-error)
✓ HTTP 401 rows: red/error background
```

### K13: AuditLog prompt truncation

```
1. Send a message longer than 40 characters
2. Audit Log row shows prompt truncated to ~40 chars with "..."
3. Click row to expand → full prompt visible
```

### K14: Clear Audit Log button

```
1. Send some messages → Audit Log has entries
2. "Clear Audit Log" button visible (only when entries > 0)
3. Click Clear → all rows removed, counter resets to 0
4. Button disappears (no entries)
```

---

## Test Suite L: Error Handling

### L1: Network error during chat

```
1. Stop the A2A server (kill terminal)
2. Send a chat message from frontend
3. Expected:
   ✓ System error message appears in red
   ✓ Error message indicates network/connection failure
   ✓ Audit Log records the failed request
   ✓ Chat input re-enabled after error
```

### L2: Token acquisition failure

```
1. Revoke consent or clear MSAL cache in browser storage
2. Attempt to send a chat message
3. Expected:
   ✓ MSAL popup appears for re-authentication (InteractionRequiredAuthError)
   ✓ After popup login, request proceeds normally
   OR: Error shown if popup blocked/dismissed
```

### L3: /me endpoint error + retry

```
1. Stop A2A server while SecurityContextPanel is loading
2. SecurityContextPanel shows error state:
   ✓ Error message visible
   ✓ "Retry" button appears
3. Restart A2A server
4. Click Retry:
   ✓ Security context loads successfully
   ✓ Error clears
   ✓ Role/permissions displayed
```

### L4: Unexpected response format

```
(Hard to trigger from UI — primarily a code robustness test)
1. If A2A response lacks expected fields (parts[], message, etc.)
2. ChatInterface should:
   ✓ Not crash
   ✓ Show fallback "No text response" message
   ✓ Log unexpected format to browser console
```

### L5: Service partially down

```
1. Stop MCP server only (keep A2A + ADK running)
2. Send chat message
3. Expected:
   ✓ ADK agent reports MCP connection error
   ✓ Error visible in chat as system message
   ✓ Not a silent failure — user knows something went wrong
```

### L6: Expired token in-flight

```
1. Wait until token is very close to expiry
2. Send a chat message
3. If token expires mid-request:
   ✓ A2A returns 401 (token_expired)
   ✓ AGENT (red) badge in chat
   ✓ Audit Log shows 401 status
4. MSAL should trigger silent refresh on next request
```

---

## Test Suite N: OBO-Specific Scenarios

### N1: OBO startup verification

```
Check MCP server startup log (logs/mcp_server.log or console):

With ENTRA_CLIENT_SECRET set in .env:
✓ Log message: "OBO exchanger initialized (tenant: <tenant-id>)"

Without ENTRA_CLIENT_SECRET:
✓ Log message: "OBO disabled -- ENTRA_CLIENT_SECRET not set"
```

### N2: `_obo_used` flag in responses

```
Prerequisites: GRAPH_OBO_ENABLED = true, OBO configured
Sign in as: AdeleV (admin)
Role selector: admin

With OBO active:
Chat: "What's my email?"
✓ Response includes full Graph profile (displayName, mail, jobTitle, etc.)
✓ Response includes `_obo_used: true`
✓ No `source: "token_claims"` — real Graph data

Without OBO (disable by removing ENTRA_CLIENT_SECRET, restart MCP):
Chat: "What's my email?"
✓ Response includes `source: "token_claims"`
✓ Response includes `_obo_used: false` (or absent)
✓ Only shows email and role from token claims, not full Graph profile
```

### N3: OBO credential cache

```
Prerequisites: OBO configured
Sign in as: AdeleV (admin)
Role selector: admin

1. Chat: "What's my email?" — check MCP server log for OBO exchange
   ✓ Log shows OBO token exchange activity

2. Chat: "List my OneDrive files" — check MCP server log
   ✓ OBO uses cached credential (OnBehalfOfCredential bound to same assertion)
   ✓ No duplicate credential creation log for same user token

3. Re-acquire token (e.g., change scope preset, wait for silent refresh)
   ✓ New token triggers new OBO credential (different assertion hash)
```

### N4: OBO failure fallback

```
Prerequisites: Set ENTRA_CLIENT_SECRET to an invalid/expired value, restart MCP
Sign in as: AdeleV (admin)
Role selector: admin

Chat: "What's my email?"
✓ get_user_profile: falls back to token claims (not crash)
✓ Response has `source: "token_claims"`, `_obo_used: false`
✓ No 500 error — graceful degradation

Chat: "List my OneDrive files"
✓ list_files: returns `error: "graph_api_unavailable"` (not crash)
✓ Response has `_obo_used: false`
✓ Denial badge: RESOURCE (purple)

Chat: "Send email to test@example.com with subject Test and body Hello"
✓ send_email: fails gracefully
✓ Denial badge: RESOURCE (purple)

Chat: "What time is it in Tokyo?"
✓ time tools: SUCCESS — unaffected by OBO failure (no Graph dependency)
```

### N5: Provider guard (future multi-IdP)

```
Non-Entra user (e.g., Cognito/Auth0 user, when multi-IdP support is active):

Graph tools return provider_not_supported:
✓ get_user_profile → {"error": "provider_not_supported", "provider": "cognito", ...}
✓ list_files → {"error": "provider_not_supported", "provider": "cognito", ...}
✓ send_email → {"error": "provider_not_supported", "provider": "cognito", ...}

Non-Graph tools still work:
✓ delete_resource → SUCCESS (simulated)
✓ get_current_time → SUCCESS
✓ convert_timezone → SUCCESS
✓ get_time_difference → SUCCESS

Note: currently all users are Entra. This scenario is testable only with
dev_config.toml override (set default_provider = "cognito" under [mcp]).
```

---

## Test Suite M: Results Recording

### M1: Save markdown results

```
For each role tested, copy the relevant test suite checklist above.
Mark pass/fail. Save as:
  test_results/YYYY-MM-DD_<role>_frontend_manual.md
```

### M2: Save audit JSON

```
After running RBAC Matrix + chat tests:
1. Click "Copy JSON" in Audit Log
2. Save as:
  test_results/YYYY-MM-DD_<role>_frontend_audit.json
```

### M3: File naming convention

```
test_results/
  YYYY-MM-DD_admin_frontend_manual.md
  YYYY-MM-DD_admin_frontend_audit.json
  YYYY-MM-DD_developer_frontend_manual.md
  YYYY-MM-DD_developer_frontend_audit.json
  YYYY-MM-DD_viewer_frontend_manual.md
  YYYY-MM-DD_viewer_frontend_audit.json
  YYYY-MM-DD_stsadmin_frontend_manual.md   # Multi-group user
  YYYY-MM-DD_stsadmin_frontend_audit.json
```
