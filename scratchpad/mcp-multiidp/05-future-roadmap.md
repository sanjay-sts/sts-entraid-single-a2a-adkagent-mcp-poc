# MCP Multi-IdP: Future Roadmap & TODO

## Completed: Multi-IdP MCP Auth (Previous Iteration)

- [x] Create `mcp_server/policy.py` (PolicyEvaluator interface + TomlPolicyEvaluator)
- [x] Create `permissions.toml` and `permissions.example.toml`
- [x] Add `permissions.toml` to `.gitignore`
- [x] Replace `TokenValidationMiddleware` with `AzureJWTVerifier` + `RemoteAuthProvider`
- [x] Add `UserContextMiddleware` with role selection (`X-Assume-Role`)
- [x] Remove `require_scopes_from_token()` from all tool decorators
- [x] Remove `current_user_scopes` ContextVar
- [x] Delete custom JWKS fetching code (~128 lines)
- [x] Test with MCP Inspector + Entra ID token (22/22 tests passed)
- [x] Test role selection flow
- [x] Test dev bypass mode
- [x] Fix case-insensitive email lookup in policy.py
- [x] Fix dev_config.py per-server logging

## Completed: Frontend Role Switching (Previous Iteration)

See `08-role-switching-plan.md` for full details.

- [x] A2A server: Add `current_assumed_role` ContextVar, extract X-Assume-Role from headers
- [x] A2A server: Forward role to ADK in /chat and /session request bodies
- [x] A2A server: Enhance GET /me to return `available_roles`
- [x] ADK agent: Update `mcp_header_provider` to include X-Assume-Role
- [x] ADK agent: Accept role in /session and /chat endpoints, update session state
- [x] Frontend: Add role dropdown in SecurityContextPanel (from available_roles)
- [x] Frontend: Send X-Assume-Role header on all A2A requests
- [x] Frontend: Update RBACTestMatrix to use selected role
- [x] Frontend: Update ChatInterface to pass X-Assume-Role
- [x] Frontend: Update testScenarios.js denial expectations
- [x] End-to-end testing through UI

## Near-Term (Next Iteration)

### Add Second IdP Provider — DONE (Cognito)
- [x] Add `JWTVerifier` for Cognito to `_build_auth()`
- [x] Add `[group_rules.cognito]` to permissions.toml
- [x] Test with real tokens from Cognito
- [x] Verify same permission model works across IdPs

### Group Overage Resolution (Entra ID)
- [ ] Implement Graph API `/me/memberOf` call for group overage
- [ ] Cache group memberships (per-user, TTL-based)
- [ ] This requires OBO or app-level Graph permissions

### A2A Server Multi-IdP — DONE
- [x] Generalized `auth_middleware` with `TokenValidator` + `IdPConfig` dataclass
- [x] Replaced hardcoded values with env-var-driven `IDP_CONFIGS`
- [x] Uses shared `CedarPolicyEvaluator` (via `permissions.toml` + Cedar policies)
- [x] Custom OIDC validation via `TokenValidator` class

### ADK Agent Cleanup
- [ ] Remove `_determine_role()` from `adk_agent/agent.py`
- [ ] Accept role from A2A context (already resolved by A2A server)
- [ ] ADK agent becomes fully IdP-agnostic

### Frontend Changes
- [x] Add role selector dropdown (show available roles from `/me` endpoint) — see 08-role-switching-plan.md
- [x] Update `GET /me` to return available roles — see 08-role-switching-plan.md
- [x] Pass selected role via header to A2A server — see 08-role-switching-plan.md
- [ ] Add IdP selector on login page (for multi-IdP, after Auth0 integration)

## Medium-Term

### ABAC Policies (Tier 2) — DONE (via Cedar, not TOML)
- [x] Implemented Cedar-based ABAC instead of TOML `[policies]` section
- [x] `CedarPolicyEvaluator` in `mcp_server/policy.py` replaces `require_role()`
- [x] Cedar policies in `cedar/policies/` (rbac.cedar, abac.cedar, guardrails.cedar)
- [x] Demo: developer + archiver attribute → delete S3 objects in `archive/` only
- [x] Forbid guardrail: no delete in `protected/` (overrides even admin)
- [x] A2A server uses shared `CedarPolicyEvaluator` — eliminated `GROUP_TO_ROLE`, `TOOL_ROLES`, `ROLE_PRIORITY` duplication
- [x] Batch evaluation via `check_access_batch()` + `is_authorized_batch()`
- [x] 28 Cedar tests passing
- See `scratchpad/cedar-abac/` for full design and implementation docs

### OBO (On-Behalf-Of) for Entra ID — DONE (previous iteration)
- [x] Implemented in `mcp_server/graph_obo.py` (GraphOBOExchanger)
- [x] Only activates when provider = Entra AND client secret configured
- [x] Tools that need Graph: `get_user_profile`, `list_files`, `send_email`
- [x] Other providers' tools fall back to token claims

### Permission Management API
- [ ] `GET /admin/permissions` — list all user/group mappings
- [ ] `POST /admin/permissions` — add/update mapping
- [ ] `DELETE /admin/permissions` — remove mapping
- [ ] Admin-only, authenticated
- [ ] Replaces manual TOML editing

## Long-Term

### Policy Engine Integration (Tier 3) — PARTIALLY DONE
- [ ] **OPA (Open Policy Agent)**: Deferred — recommended for platform guardrails (K8s, mesh, CI/CD), not day-to-day tool auth
- [x] **AWS Cedar**: Implemented via `cedarpy` (embedded, in-process)
  - `CedarPolicyEvaluator` in `mcp_server/policy.py`
  - Cedar schema in `cedar/schema.cedarschema` (AgentAuth namespace)
  - Entity-based policies with User, Role, Tool entities
  - Both A2A and MCP servers use Cedar as single PDP
- [x] Policy testing framework — 28 tests in `tests/test_cedar_smoke.py`

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
| Policy engine | Cedar implemented, OPA deferred | Cedar for runtime ABAC, OPA for platform guardrails later |
| IdP scope checks | Removed | IdP scopes ≠ agent permissions; agent owns its own |
| MCP-only scope | Yes | Isolate risk, test with MCP Inspector, adapt layers later |
| Group overage | Detect + warn | Graph API call deferred to OBO iteration |
