# MCP Multi-IdP: Testing Strategy

## Test 1: Role Selection Required
```
1. Start MCP server with auth enabled
2. MCP Inspector: connect with Bearer token but NO X-Assume-Role header
3. Call any tool → should get [ROLE_SELECTION] error listing available roles
4. Add X-Assume-Role: admin header → tool should work
5. Add X-Assume-Role: viewer header → admin-only tools should get [TOOL_DENIAL]
```

## Test 2: Role Selection Validation
```
1. User is in "developer" group only (not admin)
2. Set X-Assume-Role: admin → should get [TOOL_DENIAL] "Cannot assume role 'admin'"
3. Set X-Assume-Role: developer → should work for developer-allowed tools
4. Set X-Assume-Role: viewer → should get [TOOL_DENIAL] (viewer not in available roles)
```

## Test 3: Group-to-Role Policy
```
1. Add your Entra group GUID to permissions.toml [group_rules.entra] as "admin"
2. Restart MCP server (or wait for hot reload)
3. With X-Assume-Role: admin → should work
4. Change group mapping to "viewer" in permissions.toml
5. With X-Assume-Role: admin → should fail (no longer available)
6. Add your email to [users] as override → should make role available again
```

## Test 4: Trusted Provider Rejection
```
1. Create a self-signed JWT with a fake issuer
2. Send it as Bearer token to MCP server
3. Should get 401/403 — signature doesn't match any configured JWKS
```

## Test 5: Dev Bypass Mode
```
1. Set disable_auth=true in dev_config.toml
2. Connect MCP Inspector without token or role header
3. All tools should work with admin role (bypass skips role selection)
```

## Test 6 (future): Second IdP
```
1. Add JWTVerifier for Cognito/Auth0 to _build_auth()
2. Get a token from that IdP
3. Map the provider's groups in permissions.toml [group_rules.cognito]
4. Send token with X-Assume-Role header → should validate and work
```

## Expected Denial Messages

| Scenario | Error Prefix | Message Pattern |
|----------|-------------|-----------------|
| No role header | `[ROLE_SELECTION]` | "Role selection required. Set X-Assume-Role header to one of: [...]" |
| No roles available | `[TOOL_DENIAL]` | "No roles available for {email}. Contact admin." |
| Invalid role selection | `[TOOL_DENIAL]` | "Cannot assume role '{role}'. Available roles: [...]" |
| Role doesn't have tool access | `[TOOL_DENIAL]` | "Role '{role}' cannot use this tool. Required roles: [...]" |
| Untrusted provider | HTTP 401/403 | FastMCP built-in rejection |

## MCP Inspector Configuration

For testing with MCP Inspector v0.21.1+:
- **Connection URL**: `http://localhost:10002/mcp`
- **Auth**: Bearer token (paste Entra ID token)
- **Custom Headers**: `X-Assume-Role: admin` (or `developer`, `viewer`)

## How to Get a Test Token

Option 1: From frontend
```
1. Start frontend (npm start in frontend/)
2. Log in with Entra ID
3. Open browser dev tools → Application → Local Storage
4. Find the access token
```

Option 2: Via Azure CLI
```bash
az login
az account get-access-token --resource api://{CLIENT_ID} --query accessToken -o tsv
```
