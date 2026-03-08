# MCP Multi-IdP: Future Roadmap & TODO

## Immediate TODOs (This Iteration)

- [ ] Create `mcp_server/policy.py` (PolicyEvaluator interface + TomlPolicyEvaluator)
- [ ] Create `permissions.toml` and `permissions.example.toml`
- [ ] Add `permissions.toml` to `.gitignore`
- [ ] Replace `TokenValidationMiddleware` with `AzureJWTVerifier` + `RemoteAuthProvider`
- [ ] Add `UserContextMiddleware` with role selection (`X-Assume-Role`)
- [ ] Remove `require_scopes_from_token()` from all tool decorators
- [ ] Remove `current_user_scopes` ContextVar
- [ ] Delete custom JWKS fetching code (~128 lines)
- [ ] Test with MCP Inspector + Entra ID token
- [ ] Test role selection flow
- [ ] Test dev bypass mode

## Near-Term (Next Iteration)

### Add Second IdP Provider
- [ ] Add `JWTVerifier` for Cognito or Auth0 to `_build_auth()`
- [ ] Add `[group_rules.cognito]` or `[group_rules.auth0]` to permissions.toml
- [ ] Test with real tokens from second IdP
- [ ] Verify same permission model works across IdPs

### Group Overage Resolution (Entra ID)
- [ ] Implement Graph API `/me/memberOf` call for group overage
- [ ] Cache group memberships (per-user, TTL-based)
- [ ] This requires OBO or app-level Graph permissions

### A2A Server Multi-IdP
- [ ] Generalize `auth_middleware` in `a2a_server/server.py`
- [ ] Replace hardcoded `JWKS_URIS`, `VALID_ISSUERS`, `ALLOWED_GROUPS`
- [ ] Use same `permissions.toml` or shared permission store
- [ ] A2A doesn't have FastMCP built-in auth — needs custom OIDC validator

### ADK Agent Cleanup
- [ ] Remove `_determine_role()` from `adk_agent/agent.py`
- [ ] Accept role from A2A context (already resolved by A2A server)
- [ ] ADK agent becomes fully IdP-agnostic

### Frontend Changes
- [ ] Add IdP selector on login page (Option A: multiple buttons)
- [ ] Add role selector dropdown (show available roles from `/me` endpoint)
- [ ] Update `GET /me` to return available roles
- [ ] Pass selected role via header to A2A server

## Medium-Term

### ABAC Policies (Tier 2)
- [ ] Add `[policies]` section to `permissions.toml` for per-tool attribute checks
- [ ] Example: `[policies.delete_resource] business_hours_only = true`
- [ ] Extend `check_access()` to evaluate policies
- [ ] Still file-based, but more expressive than bare RBAC

### OBO (On-Behalf-Of) for Entra ID
- [ ] Implement token exchange in MCP server for Graph API tools
- [ ] Only activates when provider = Entra AND client secret configured
- [ ] Tools that need Graph: `get_user_profile`, `list_files`, `send_email`
- [ ] Other providers' tools fall back to token claims
- [ ] Requires: client secret in Azure Portal + ~50 lines of token exchange code

### Permission Management API
- [ ] `GET /admin/permissions` — list all user/group mappings
- [ ] `POST /admin/permissions` — add/update mapping
- [ ] `DELETE /admin/permissions` — remove mapping
- [ ] Admin-only, authenticated
- [ ] Replaces manual TOML editing

## Long-Term

### Policy Engine Integration (Tier 3)
- [ ] **OPA (Open Policy Agent)**: Deploy as sidecar, write Rego policies
  - Ideal for: Kubernetes deployments, cloud-native
  - Implement `OpaPolicyEvaluator`
  - Example Rego policy for tool access
- [ ] **AWS Cedar**: Embed via `cedar-py`, write Cedar policies
  - Ideal for: AWS-native, formal verification needs
  - Implement `CedarPolicyEvaluator`
  - Entity-based policies with type-safe schemas
- [ ] Policy testing framework — test policies independently from code

### Database-Backed Permission Store
- [ ] Migrate from TOML to database (PostgreSQL/SQLite)
- [ ] Schema: `user_permissions(email, role, source, updated_at)`
- [ ] Schema: `group_role_mappings(provider, group_id, role)`
- [ ] Implement `DatabasePolicyEvaluator`
- [ ] Admin UI for managing permissions
- [ ] Audit trail (who changed what, when)

### Multi-Tenant Agent Platform
- [ ] Per-tenant permission stores
- [ ] Per-tenant IdP configuration
- [ ] Tenant isolation at MCP tool level
- [ ] Cross-tenant agent-to-agent calls

### Agent-to-Agent Authentication
- [ ] A2A supports mTLS for agent-to-agent trust
- [ ] Service account tokens for cross-agent calls
- [ ] Agent identity separate from user identity

---

## Key Documentation Links

- [FastMCP Authentication Overview](https://gofastmcp.com/servers/auth/authentication)
- [Token Verification (JWTVerifier)](https://gofastmcp.com/servers/auth/token-verification)
- [Authorization (auth= callables)](https://gofastmcp.com/servers/authorization)
- [Azure Entra ID Integration](https://gofastmcp.com/integrations/azure)
- [AzureJWTVerifier API](https://gofastmcp.com/python-sdk/fastmcp-server-auth-providers-azure)
- [MultiAuth API](https://gofastmcp.com/python-sdk/fastmcp-server-auth-auth)
- [Remote OAuth (RemoteAuthProvider)](https://gofastmcp.com/servers/auth/remote-oauth)

## FastMCP Built-in Auth Providers Reference

| Provider | Class | Import |
|----------|-------|--------|
| Azure/Entra ID | `AzureProvider` | `fastmcp.server.auth.providers.azure` |
| Azure JWT only | `AzureJWTVerifier` | `fastmcp.server.auth.providers.azure` |
| Generic OIDC | `OIDCProxy` | `fastmcp.server.auth.oidc_proxy` |
| Generic JWT | `JWTVerifier` | `fastmcp.server.auth.providers.jwt` |
| Auth0 | `Auth0Provider` | `fastmcp.server.auth.providers.auth0` |
| Google | `GoogleProvider` | `fastmcp.server.auth.providers.google` |
| GitHub | `GitHubProvider` | `fastmcp.server.auth.providers.github` |
| AWS Cognito | `AWSProvider` | `fastmcp.server.auth.providers.aws` |
| Multi-provider | `MultiAuth` | `fastmcp.server.auth` |
| Remote OAuth | `RemoteAuthProvider` | `fastmcp.server.auth` |
| Debug/testing | `DebugTokenVerifier` | `fastmcp.server.auth` |
| Static tokens | `StaticTokenVerifier` | `fastmcp.server.auth` |

## Design Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Group-to-role vs user-to-role | Groups PRIMARY | Scales better, aligns with enterprise IAM |
| Role selection | User selects explicitly | Least-privilege principle, like AWS AssumeRole |
| Policy engine | Interface now, OPA/Cedar later | No external deps now, clean swap point |
| IdP scope checks | Removed | IdP scopes ≠ agent permissions; agent owns its own |
| MCP-only scope | Yes | Isolate risk, test with MCP Inspector, adapt layers later |
| Group overage | Detect + warn | Graph API call deferred to OBO iteration |
