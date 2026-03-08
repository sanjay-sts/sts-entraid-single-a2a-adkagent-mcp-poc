# MCP Multi-IdP: Testing Strategy

## Test Users

| User | Email | Entra Group | Group GUID | Group Role | User Override |
|------|-------|-------------|------------|------------|---------------|
| Adele Vance | AdeleV@2tdgcb.onmicrosoft.com | AI-Agent-Admins | f1c467f2-954d-4e9d-8949-53a3492b0c14 | admin | (configurable) |
| Diego Siciliani | DiegoS@2tdgcb.onmicrosoft.com | AI-Agent-Developers | c6097742-e961-405f-9a45-2ca9fc971bd7 | developer | (configurable) |
| Johanna Lorenz | JohannaL@2tdgcb.onmicrosoft.com | AI-Agent-Viewers | a0cd9a0a-da7e-457c-8ca2-237529bb130f | viewer | (none) |
| No-group user | (any user not in above groups) | (none) | — | none | (none) |

## Tool Permission Matrix

| Tool | admin | developer | viewer |
|------|-------|-----------|--------|
| get_user_profile | Y | Y | Y |
| list_files | Y | Y | N |
| send_email | Y | N | N |
| delete_resource | Y | N | N |
| get_current_time | Y | N | N |
| convert_timezone | Y | N | N |
| get_time_difference | Y | N | N |

---

## Test Suite A: AdeleV (Admin Group)

### A1: Admin role — full access
```
User: AdeleV@2tdgcb.onmicrosoft.com
Header: X-Assume-Role: admin
Expected available roles: ['admin'] (group only) or ['admin', 'viewer'] (with user override)

1. List Tools → should see all 7 tools
2. Call get_current_time {"timezone": "UTC"} → SUCCESS
3. Call get_user_profile {} → SUCCESS (token claims fallback)
4. Call send_email {"to":"test@test.com","subject":"Test","body":"Hello"} → SUCCESS (or Graph 401)
5. Call list_files {"folder_path": "/"} → SUCCESS (or Graph 401)
```

### A2: Admin user assumes viewer (user override required)
```
User: AdeleV@2tdgcb.onmicrosoft.com
permissions.toml: "AdeleV@2tdgcb.onmicrosoft.com" = { role = "viewer" }
Header: X-Assume-Role: viewer

1. List Tools → should see only get_user_profile (1 tool)
2. Call get_user_profile → SUCCESS with role: viewer
3. Call get_current_time → should NOT appear in list (hidden)
```

### A3: No role header
```
User: AdeleV@2tdgcb.onmicrosoft.com
Header: (no X-Assume-Role)

1. Call any tool → [ROLE_SELECTION] Role selection required. Set X-Assume-Role header to one of: ['admin']
```

### A4: Invalid role assumption
```
User: AdeleV@2tdgcb.onmicrosoft.com (group gives admin only, no user override for developer)
Header: X-Assume-Role: developer

1. Call any tool → [TOOL_DENIAL] Cannot assume role 'developer'. Available roles: ['admin']
```

---

## Test Suite B: DiegoS (Developer Group)

### B1: Developer role — partial access
```
User: DiegoS@2tdgcb.onmicrosoft.com
Header: X-Assume-Role: developer
Expected available roles: ['developer']

1. List Tools → should see 2 tools: get_user_profile, list_files
2. Call get_user_profile → SUCCESS
3. Call list_files {"folder_path": "/"} → SUCCESS (or Graph 401)
4. Call get_current_time → should NOT appear in list
5. Call send_email → should NOT appear in list
```

### B2: Developer tries to assume admin
```
User: DiegoS@2tdgcb.onmicrosoft.com
Header: X-Assume-Role: admin

1. Call any tool → [TOOL_DENIAL] Cannot assume role 'admin'. Available roles: ['developer']
```

### B3: Developer tries to assume viewer
```
User: DiegoS@2tdgcb.onmicrosoft.com (no viewer in available roles unless user override added)
Header: X-Assume-Role: viewer

1. Call any tool → [TOOL_DENIAL] Cannot assume role 'viewer'. Available roles: ['developer']
```

### B4: Developer with user override to add viewer
```
User: DiegoS@2tdgcb.onmicrosoft.com
permissions.toml: "DiegoS@2tdgcb.onmicrosoft.com" = { role = "viewer" }
Header: X-Assume-Role: viewer

1. Available roles should be ['developer', 'viewer']
2. List Tools → should see only get_user_profile (1 tool)
3. Call get_user_profile → SUCCESS with role: viewer
```

---

## Test Suite C: JohannaL (Viewer Group)

### C1: Viewer role — minimal access
```
User: JohannaL@2tdgcb.onmicrosoft.com
Header: X-Assume-Role: viewer
Expected available roles: ['viewer']

1. List Tools → should see 1 tool: get_user_profile
2. Call get_user_profile → SUCCESS with role: viewer
3. All other tools → should NOT appear in list
```

### C2: Viewer tries to assume admin
```
User: JohannaL@2tdgcb.onmicrosoft.com
Header: X-Assume-Role: admin

1. Call any tool → [TOOL_DENIAL] Cannot assume role 'admin'. Available roles: ['viewer']
```

### C3: Viewer tries to assume developer
```
User: JohannaL@2tdgcb.onmicrosoft.com
Header: X-Assume-Role: developer

1. Call any tool → [TOOL_DENIAL] Cannot assume role 'developer'. Available roles: ['viewer']
```

### C4: Viewer promoted via user override
```
User: JohannaL@2tdgcb.onmicrosoft.com
permissions.toml: "JohannaL@2tdgcb.onmicrosoft.com" = { role = "admin" }
Header: X-Assume-Role: admin

1. Available roles should be ['admin', 'viewer']
2. List Tools → should see all 7 tools
3. Call get_current_time → SUCCESS
```

---

## Test Suite D: No-Group User

### D1: Authenticated but no group membership
```
User: (user not in any of the 3 groups, no user override)
Header: X-Assume-Role: viewer

1. Call any tool → [TOOL_DENIAL] No roles available for {email}. Contact admin to assign group membership.
```

### D2: No-group user with user override
```
User: (same user)
permissions.toml: "nogroup@2tdgcb.onmicrosoft.com" = { role = "developer" }
Header: X-Assume-Role: developer

1. Available roles: ['developer']
2. List Tools → should see 2 tools
3. Call get_user_profile → SUCCESS
```

---

## Test Suite E: Dev Bypass Mode

### E1: All auth bypassed
```
dev_config.toml: [mcp] disable_auth = true, default_role = "admin"

1. Connect MCP Inspector without token or headers
2. List Tools → should see all 7 tools
3. Call get_current_time → SUCCESS, requested_by: dev@localhost
4. Log shows: AUTH BYPASSED - role: admin
```

### E2: Bypass with viewer role
```
dev_config.toml: [mcp] disable_auth = true, default_role = "viewer"

1. List Tools → should see only get_user_profile
2. Call get_user_profile → SUCCESS, role: viewer
```

---

## Test Suite F: Token Validation

### F1: No token
```
1. Connect MCP Inspector without Bearer token
2. Should get HTTP 401 — "invalid_token"
```

### F2: Expired token
```
1. Use a token that has passed its exp claim
2. Should get HTTP 401 — token expired
```

### F3: Fake/self-signed JWT
```
1. Create JWT with fake issuer and signature
2. Should get HTTP 401 — signature doesn't match any configured JWKS
```

### F4: Wrong audience
```
1. Use a Graph API token (aud: 00000003-0000-0000-c000-000000000000)
2. Should get HTTP 401 — audience mismatch
```

---

## Test Suite G: Hot Reload

### G1: Change group mapping without restart
```
1. permissions.toml: "f1c467f2..." = "admin"
2. AdeleV with X-Assume-Role: admin → SUCCESS
3. Edit permissions.toml: "f1c467f2..." = "viewer" (no restart)
4. AdeleV with X-Assume-Role: admin → [TOOL_DENIAL] Cannot assume role 'admin'
5. AdeleV with X-Assume-Role: viewer → SUCCESS, sees only get_user_profile
```

### G2: Add user override without restart
```
1. AdeleV has only group role (admin)
2. Add to permissions.toml: "AdeleV@..." = { role = "viewer" }
3. AdeleV with X-Assume-Role: viewer → SUCCESS (now has ['admin', 'viewer'])
```

---

## Expected Denial Messages

| Scenario | Error Prefix | Message Pattern |
|----------|-------------|-----------------|
| No role header | `[ROLE_SELECTION]` | "Role selection required. Set X-Assume-Role header to one of: [...]" |
| No roles available | `[TOOL_DENIAL]` | "No roles available for {email}. Contact admin." |
| Invalid role selection | `[TOOL_DENIAL]` | "Cannot assume role '{role}'. Available roles: [...]" |
| Role doesn't have tool access | `[TOOL_DENIAL]` | "Access denied: Role '{role}' cannot use this tool. Required roles: [...]" |
| Untrusted provider | HTTP 401 | FastMCP built-in rejection |
| Wrong audience | HTTP 401 | FastMCP built-in rejection |

## MCP Inspector Configuration

### UI Mode
- **Transport**: Streamable HTTP
- **URL**: `http://localhost:10002/mcp`
- **Auth Header Name**: `Authorization` (change from default `x-api-key`)
- **Token Value**: `Bearer {token}` (include "Bearer " prefix)
- **Custom Headers**: Add as JSON in the headers field:
  ```json
  {
    "Authorization": "Bearer {token}",
    "X-Assume-Role": "admin"
  }
  ```

### CLI Mode
```bash
npx @modelcontextprotocol/inspector --cli http://localhost:10002/mcp \
  --transport http \
  --method tools/list \
  --header "Authorization: Bearer {token}" \
  --header "X-Assume-Role: admin"
```

## How to Get a Test Token

### Option 1: From frontend
```
1. Start frontend: cd frontend && npm start
2. Log in with test user (AdeleV, DiegoS, or JohannaL)
3. Open browser DevTools → Application → Local Storage
4. Find the access token entry with target: "api://647e61a7.../access_as_user"
5. Copy the "secret" field value — that's the JWT
```

### Option 2: Via Azure CLI
```bash
az login --username AdeleV@2tdgcb.onmicrosoft.com
az account get-access-token --resource api://647e61a7-50c8-43e1-ad7d-99db051ffd4a --query accessToken -o tsv
```

### Token Notes
- Tokens expire after ~75 minutes. Re-acquire before each test session.
- Use the token with `target: "api://647e61a7.../access_as_user"`, NOT the Graph API token (`target: "email Files.Read..."`)
- The Graph API token has `aud: 00000003-...` which will be rejected by the MCP server
