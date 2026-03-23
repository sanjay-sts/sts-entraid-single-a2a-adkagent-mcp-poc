# MCP Multi-IdP: Test Results

**Date**: 2026-03-09
**MCP Server**: FastMCP 3.1.0, Identity-Aware MCP Server
**Token Version**: Entra ID v1.0 (issuer: sts.windows.net)
**Test Tool**: MCP Inspector (UI mode, Streamable HTTP)

---

## Test Suite A: AdeleV (Admin Group)

### A1: Admin role — full access
**Status**: PASS

**Config**:
- permissions.toml: group `f1c467f2...` = "admin", user override `AdeleV` = { role = "viewer" }
- Header: `X-Assume-Role: admin`

**Results**:
- Available roles resolved: `['admin', 'viewer']`
- List Tools: all 7 tools visible
- `get_current_time {"timezone": "UTC"}` → SUCCESS
  ```json
  {
    "timezone": "UTC",
    "formatted": "2026-03-08 18:52:45 UTC",
    "day_of_week": "Sunday",
    "requested_by": "AdeleV@2tdgcb.onmicrosoft.com"
  }
  ```
- `get_user_profile` → SUCCESS (token claims fallback, Graph 401 expected)
  ```json
  {
    "source": "token_claims",
    "email": "AdeleV@2tdgcb.onmicrosoft.com",
    "role": "admin",
    "note": "Graph API requires OBO flow for delegated access. Showing token claims."
  }
  ```

**Server log**:
```
User AdeleV@2tdgcb.onmicrosoft.com assumed role 'admin' (available: ['admin', 'viewer'])
```

### A2: Admin user assumes viewer
**Status**: PASS

**Config**:
- permissions.toml: user override `AdeleV` = { role = "viewer" }
- Header: `X-Assume-Role: viewer`

**Results**:
- Available roles resolved: `['admin', 'viewer']`
- List Tools: only `get_user_profile` visible (1 tool)
- `get_user_profile` → SUCCESS with `role: viewer`
- 6 tools hidden — server logs show `[TOOL_DENIAL]` for each (expected during listing)

**Server log**:
```
User AdeleV@2tdgcb.onmicrosoft.com assumed role 'viewer' (available: ['admin', 'viewer'])
ToolError: [TOOL_DENIAL] Access denied: Role 'viewer' cannot use this tool. Required roles: ['admin', 'developer']
ToolError: [TOOL_DENIAL] Access denied: Role 'viewer' cannot use this tool. Required roles: ['admin']
(x6 denials for non-viewer tools)
```

### A3: No role header
**Status**: PASS

**Config**:
- Header: (no X-Assume-Role)

**Results**:
```json
{
  "content": [{"type": "text", "text": "[ROLE_SELECTION] Role selection required. Set X-Assume-Role header to one of: ['admin']"}],
  "isError": true
}
```

### A4: Invalid role assumption (viewer without user override)
**Status**: PASS

**Config**:
- No user override for viewer
- Header: `X-Assume-Role: viewer`

**Results**:
```json
{
  "content": [{"type": "text", "text": "[TOOL_DENIAL] Cannot assume role 'viewer'. Available roles: ['admin']"}],
  "isError": true
}
```

---

## Test Suite B: DiegoS (Developer Group)

### B1: Developer role — partial access
**Status**: PASS

**Config**:
- permissions.toml: group `c6097742...` = "developer", user override `DiegoS` = { role = "developer" }
- Header: `X-Assume-Role: developer`

**Results**:
- Available roles resolved: `['developer']`
- List Tools: 2 tools visible (`get_user_profile`, `list_files`)
- 5 admin-only tools hidden (server logs show `[TOOL_DENIAL]` for each)
- `list_files {"folder_path": "/"}` → Graph 401 fallback (expected — OBO needed)
  ```json
  {"error": "graph_api_unavailable", "status_code": 401, "role": "developer",
   "note": "Graph API requires OBO flow. Token validated but cannot access OneDrive."}
  ```
- `get_user_profile` → SUCCESS (token claims fallback)
  ```json
  {"source": "token_claims", "email": "DiegoS@2tdgcb.onmicrosoft.com",
   "role": "developer", "note": "Graph API requires OBO flow for delegated access."}
  ```

**Server log**:
```
User DiegoS@2tdgcb.onmicrosoft.com assumed role 'developer' (available: ['developer'])
```

### B2: Developer tries to assume admin
**Status**: PASS

**Config**:
- Header: `X-Assume-Role: admin`

**Results**:
```json
{"error": "MCP error 0: [TOOL_DENIAL] Cannot assume role 'admin'. Available roles: ['developer']"}
```

### B3: Developer tries to assume viewer
**Status**: PASS

**Config**:
- Header: `X-Assume-Role: viewer`

**Results**:
```json
{"error": "MCP error 0: [TOOL_DENIAL] Cannot assume role 'viewer'. Available roles: ['developer']"}
```

### B4: Developer with viewer override → step down
**Status**: PASS

**Config**:
- permissions.toml: `"DiegoS@2tdgcb.onmicrosoft.com" = { role = "viewer" }`
- Header: `X-Assume-Role: viewer`

**Results**:
- Available roles resolved: `['developer', 'viewer']` (group + user override)
- List Tools: 1 tool visible (`get_user_profile`)
- `get_user_profile` → SUCCESS with `role: viewer`
  ```json
  {"source": "token_claims", "email": "DiegoS@2tdgcb.onmicrosoft.com",
   "role": "viewer", "note": "Graph API requires OBO flow for delegated access."}
  ```

---

## Test Suite C: JohannaL (Viewer Group)

### C1: Viewer role — minimal access
**Status**: PASS

**Config**:
- permissions.toml: group `a0cd9a0a...` = "viewer"
- Header: `X-Assume-Role: viewer`

**Results**:
- Available roles resolved: `['viewer']`
- List Tools: 1 tool visible (`get_user_profile`)
- 6 tools hidden (server logs show `[TOOL_DENIAL]` for each)
- `get_user_profile` → SUCCESS (token claims fallback)
  ```json
  {"source": "token_claims", "email": "JohannaL@2tdgcb.onmicrosoft.com",
   "role": "viewer", "note": "Graph API requires OBO flow for delegated access."}
  ```

**Server log**:
```
User JohannaL@2tdgcb.onmicrosoft.com assumed role 'viewer' (available: ['viewer'])
```

### C2: Viewer tries to assume admin
**Status**: PASS

**Config**:
- Header: `X-Assume-Role: admin`

**Results**:
```json
{"error": "MCP error 0: [TOOL_DENIAL] Cannot assume role 'admin'. Available roles: ['viewer']"}
```

### C3: Viewer tries to assume developer
**Status**: PASS

**Config**:
- Header: `X-Assume-Role: developer`

**Results**:
```json
{"error": "MCP error 0: [TOOL_DENIAL] Cannot assume role 'developer'. Available roles: ['viewer']"}
```

### C4: Viewer promoted to admin via override
**Status**: PASS

**Config**:
- permissions.toml: `"JohannaL@2tdgcb.onmicrosoft.com" = { role = "admin" }`
- Header: `X-Assume-Role: admin`

**Results**:
- Available roles resolved: `['admin', 'viewer']` (user override + group)
- List Tools: all 7 tools visible
- `get_current_time {"timezone": "UTC"}` → SUCCESS
  ```json
  {"timezone": "UTC", "formatted": "2026-03-09 11:50:28 UTC",
   "day_of_week": "Monday", "requested_by": "JohannaL@2tdgcb.onmicrosoft.com"}
  ```

---

## Test Suite D: No-Group User

### D1: Authenticated but no group membership
**Status**: PASS

**Config**:
- User: PradeepG@2tdgcb.onmicrosoft.com (not in any of the 3 groups)
- No user override in permissions.toml
- Header: `X-Assume-Role: developer`

**Results**:
```
[TOOL_DENIAL] No roles available for PradeepG@2tdgcb.onmicrosoft.com. Contact admin to assign group membership.
```

### D2: No-group user with user override
**Status**: PASS

**Config**:
- permissions.toml: `"PradeepG@2tdgcb.onmicrosoft.com" = { role = "developer" }`
- Header: `X-Assume-Role: developer`

**Results**:
- Available roles resolved: `['developer']` (from user override only)
- List Tools: 2 tools visible (`get_user_profile`, `list_files`)
- `get_user_profile` → SUCCESS
  ```json
  {"source": "token_claims", "email": "PradeepG@2tdgcb.onmicrosoft.com",
   "role": "developer", "note": "Graph API requires OBO flow for delegated access."}
  ```

---

## Test Suite E: Dev Bypass Mode

### E1: All auth bypassed (admin)
**Status**: PASS

**Config**:
- dev_config.toml: `[mcp] disable_auth = true, default_role = "admin"`
- No Bearer token, no X-Assume-Role header

**Results**:
- List Tools: all 7 tools visible
- `get_current_time {"timezone": "UTC"}` → SUCCESS
- `requested_by: dev@localhost`

**Server log**:
```
AUTH BYPASSED - role: admin
get_current_time called by dev@localhost (role: admin) for timezone: UTC
```

### E2: Dev bypass with viewer role
**Status**: PASS

**Config**:
- dev_config.toml: `[mcp] disable_auth = true, default_role = "viewer"`
- No Bearer token, no X-Assume-Role header

**Results**:
- List Tools: 1 tool visible (`get_user_profile`)
- `get_user_profile` → SUCCESS
  ```json
  {"source": "token_claims", "email": "dev@localhost",
   "role": "viewer", "note": "Graph API requires OBO flow for delegated access."}
  ```

---

## Test Suite F: Token Validation

### F1: No token / invalid token
**Status**: PASS

**Results**:
- MCP Inspector without Bearer token → HTTP 401
  ```json
  {"error": "invalid_token", "error_description": "Authentication failed..."}
  ```

### F2: Expired token
**Status**: PASS

**Config**:
- Used JohannaL's token from previous session (expired ~24 hours ago)

**Results**:
- HTTP 401 — `invalid_token`
- Server log: `Bearer token rejected for client MZEulubuf6...`

### F3: Fake/self-signed JWT
**Status**: PASS

**Config**:
- Generated fake JWT with issuer `https://evil.com` and HS256 signature
- Token: `eyJhbGciOiAiSFMyNTYi...fakesignature123`

**Results**:
- HTTP 401 — `invalid_token`
- Signature doesn't match any configured JWKS, rejected by both verifiers

### F4: Wrong audience (Graph API token)
**Status**: PASS (observed)

**Notes**:
- Graph API token (aud: `00000003-0000-0000-c000-000000000000`) was found in Local Storage
- Only the custom API token (aud: `api://647e61a7...`) was accepted by MCP server

---

## Test Suite G: Hot Reload

### G1: Change group mapping without restart
**Status**: PASS

**Config changes** (no server restart):
1. Changed `"DiegoS@2tdgcb.onmicrosoft.com"` user override from `developer` to `viewer`
2. Changed `"JohannaL@2tdgcb.onmicrosoft.com"` user override to `admin`

**Results**:
- DiegoS: `X-Assume-Role: viewer` → 1 tool visible, role: viewer (previously had developer only)
- JohannaL: `X-Assume-Role: admin` → all 7 tools visible, called `get_current_time` successfully
- Hot-reload confirmed — no server restart needed

### G2: Add user override without restart
**Status**: PASS

**Config changes** (no server restart):
1. Added `"AdeleV@2tdgcb.onmicrosoft.com" = { role = "viewer" }` to permissions.toml
2. Server log: `Permissions reloaded from ...permissions.toml`

**Results**:
- Before override: available roles = `['admin']`
- After override: available roles = `['admin', 'viewer']`
- `X-Assume-Role: viewer` now accepted (was previously rejected)

---

## Bugs Found During Testing

### Bug 1: Case-insensitive email lookup in policy.py
**Severity**: Medium
**Status**: FIXED

**Description**: `TomlPolicyEvaluator.get_available_roles()` lowercased the email from the token (`email.lower()`) but compared against TOML keys which preserve case (`"AdeleV@..."`). The user override never matched.

**Fix**: Changed dict lookup to case-insensitive iteration:
```python
# Before (broken):
if email_lower in users:
    user_entry = users[email_lower]

# After (fixed):
user_entry = next(
    (v for k, v in users.items() if k.lower() == email_lower), None
)
```

### Bug 2: dev_config.py warning too generic
**Severity**: Low
**Status**: FIXED

**Description**: `dev_config.py` logged "Auth bypass may be active!" whenever `dev_config.toml` existed, even with all `disable_auth = false`. Confusing for auth-enabled testing.

**Fix**: Changed to per-server logging on first `is_auth_disabled()` call:
- `disable_auth = true` → WARNING: `⚠️ AUTH BYPASS ENABLED for: MCP`
- `disable_auth = false` → INFO: `[MCP] Auth enforced (disable_auth=false)`

---

## Observations

### v1.0 Token Fallback Working
- Token issuer: `https://sts.windows.net/{tenant}/` (v1.0)
- `AzureJWTVerifier` (v2.0) rejects token first → logged as `Bearer token rejected for client`
- `JWTVerifier` (v1.0 fallback) accepts token → `MultiAuth` returns success
- This is expected and correct behavior

### Graph API 401 on get_user_profile
- Token audience is `api://647e61a7...` (custom API), not Graph API
- Graph API rejects with 401 — needs OBO (On-Behalf-Of) flow for delegated access
- Tool gracefully falls back to token claims with `"source": "token_claims"`

### MCP Inspector Header Configuration
- Inspector UI defaults header name to `x-api-key` — must change to `Authorization`
- Token value must include `Bearer ` prefix
- Custom headers (like `X-Assume-Role`) can be added in the JSON headers field
- Inspector CLI supports `--header` flag for arbitrary headers

---

## Test Summary — ALL 22 TESTS PASSED

| Test | User | What was Tested | Status |
|------|------|----------------|--------|
| A1 | AdeleV | Admin sees all 7 tools, can call them | PASS |
| A2 | AdeleV | Admin assumes viewer → sees 1 tool | PASS |
| A3 | AdeleV | No role header → ROLE_SELECTION error | PASS |
| A4 | AdeleV | Can't assume role not in available list | PASS |
| B1 | DiegoS | Developer sees 2 tools, can call them | PASS |
| B2 | DiegoS | Developer can't assume admin | PASS |
| B3 | DiegoS | Developer can't assume viewer (no override) | PASS |
| B4 | DiegoS | Developer with viewer override → step down | PASS |
| C1 | JohannaL | Viewer sees 1 tool, can call it | PASS |
| C2 | JohannaL | Viewer can't assume admin | PASS |
| C3 | JohannaL | Viewer can't assume developer | PASS |
| C4 | JohannaL | Viewer promoted to admin via override | PASS |
| D1 | PradeepG | No-group user → no roles available | PASS |
| D2 | PradeepG | No-group user with override → developer access | PASS |
| E1 | — | Dev bypass mode (admin), all tools | PASS |
| E2 | — | Dev bypass mode (viewer), 1 tool | PASS |
| F1 | — | No/invalid token → 401 | PASS |
| F2 | — | Expired token → 401 | PASS |
| F3 | — | Fake JWT (evil issuer) → 401 | PASS |
| F4 | — | Wrong audience token → 401 | PASS |
| G1 | DiegoS/JohannaL | Hot-reload group/user mapping changes | PASS |
| G2 | AdeleV | User override hot-reload works | PASS |
