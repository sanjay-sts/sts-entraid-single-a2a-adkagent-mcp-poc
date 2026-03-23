# Identity-Aware AI Agent System

## Project Overview

A secure, multi-tier AI agent system where user identity propagates from frontend authentication through the agent layer down to resource APIs. Access control is enforced at three independent levels (agent, tool, resource), providing defense in depth. Supports multiple Identity Providers (Entra ID, AWS Cognito).

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  React Frontend │───▶│   A2A Server    │───▶│   Google ADK    │───▶│   FastMCP        │
│  (MSAL/Amplify) │    │   (Gateway)     │    │   Agent         │    │   Tools          │
│  Port: 10003    │    │   Port: 10000   │    │   Port: 10001   │    │   Port: 10002    │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
        │                      │                      │                      │
        │  IdP Token           │  Token Validation    │  User Context        │  Token Access
        │  (Authorization)     │  + Agent-Level ACL   │  + Tool-Level ACL    │  + Resource ACL
        ▼                      ▼                      ▼                      ▼
   ┌────────────────────────────────────┐   ┌────────────────────────────────────┐
   │    Microsoft Graph API             │   │         AWS S3 API                 │
   │    (Entra OBO Token Exchange)      │   │    (Server-side AWS credentials)   │
   └────────────────────────────────────┘   └────────────────────────────────────┘
```

## Technology Stack

| Component | Technology | Port |
|-----------|------------|------|
| Frontend | React 18 + MSAL.js 3.6 + AWS Amplify 6 | 10003 |
| Gateway | A2A Protocol (FastAPI + a2a-sdk) | 10000 |
| Agent | Google ADK + LiteLLM + Claude Haiku 4.5 (Bedrock) | 10001 |
| Tools | FastMCP (stateless HTTP) | 10002 |
| Authorization | Cedar (cedarpy) — RBAC + ABAC policy engine | - |
| Identity | Entra ID + AWS Cognito | - |
| Resources | Microsoft Graph API, AWS S3 | - |

## Project Structure

```
/
├── a2a_server/
│   └── server.py              # A2A gateway — auth middleware, task executor, /me endpoint (Cedar PDP)
├── adk_agent/
│   └── agent.py               # Google ADK agent — session mgmt, streaming, retry
├── mcp_server/
│   ├── server.py              # FastMCP tools — Cedar ABAC auth, UserContextMiddleware, 12 tools
│   ├── graph_obo.py           # OBO token exchange for Graph API — GraphOBOExchanger singleton
│   └── policy.py              # PolicyEvaluator interface + TomlPolicyEvaluator + CedarPolicyEvaluator
├── cedar/
│   ├── schema.cedarschema     # Cedar entity types: User, Role, Tool, S3Folder + actions
│   ├── entities.json          # Static entities: 3 roles + 12 tools
│   └── policies/
│       ├── rbac.cedar         # RBAC permit policies (admin/developer/viewer → tools)
│       ├── abac.cedar         # ABAC policy (developer + archiver → delete in archive/)
│       └── guardrails.cedar   # Forbid policies (no delete in protected/)
├── frontend/
│   ├── src/
│   │   ├── App.js             # Dashboard layout shell — sidebar + main area
│   │   ├── App.css            # Dark theme dashboard styles
│   │   ├── AuthProvider.js    # Unified auth provider (Entra + Cognito)
│   │   ├── authConfig.js      # MSAL config + scope presets
│   │   ├── cognitoConfig.js   # AWS Cognito Amplify config
│   │   ├── index.js           # React entry point
│   │   ├── components/
│   │   │   ├── AuthStatus.js        # Multi-account switcher dropdown
│   │   │   ├── LoginPrompt.js       # Sign-in prompt with provider selection
│   │   │   ├── SecurityContextPanel.js  # Role selector, groups, scopes, expiry countdown
│   │   │   ├── TokenInspector.js    # JWT header/payload decoder (display only)
│   │   │   ├── ConversationTabs.js  # Multi-tab chat with per-tab scope (max 4)
│   │   │   ├── ChatInterface.js     # Chat with denial tagging + latency tracking
│   │   │   ├── RBACTestMatrix.js    # One-click test grid with pass/fail
│   │   │   ├── AuditLog.js          # Request history table with denial tiers
│   │   │   └── DenialIndicator.js   # Color-coded denial badge component
│   │   └── utils/
│   │       ├── a2aClient.js         # A2A JSON-RPC client + audit entry builder
│   │       ├── constants.js         # Shared constants (A2A_SERVER_URL, PROVIDER_LABELS)
│   │       ├── denialClassifier.js  # HTTP status + response → denial tier classification
│   │       ├── testScenarios.js     # Predefined test prompts with expected outcomes
│   │       └── tokenDecoder.js      # JWT base64url decode helper
│   └── package.json
├── tests/
│   ├── conftest.py            # Pytest fixtures (mock tokens, Cognito helpers)
│   ├── test_access_control.py # Access control tests
│   └── test_security_dashboard.py # Dashboard tests
├── dev_config.py              # Shared TOML config loader for auth bypass
├── dev_config.example.toml    # Template for dev_config.toml (committed, defaults false)
├── permissions.example.toml   # Template for permissions.toml (group-to-role mapping)
├── pyproject.toml             # Python project config (uv)
├── requirements.txt           # Python dependencies
└── CLAUDE.md                  # This file
```

## Security Model

### Three-Tier Access Control

| Level | Location | Mechanism | Denies When |
|-------|----------|-----------|-------------|
| **Agent** | A2A Server | Multi-IdP JWT validation, group membership, blocklist | User blocked, not in allowed group, or invalid token |
| **Tool** | MCP Server | FastMCP built-in auth + `auth=` callables + `UserContextMiddleware` | Token invalid, role not assumed, or role lacks tool permission |
| **Resource** | Graph API / S3 | OAuth scopes (Graph), IAM policies (S3) | Token missing required scope or AWS access denied |

### Role Hierarchy & Tool Permissions

```
admin      → All 12 tools (delete_s3_object blocked in protected/ by forbid guardrail)
developer  → get_user_profile, list_files, list_s3_buckets, list_s3_objects, get_s3_object_info
             + delete_s3_object (only with archiver=true attribute, only in archive/ path)
viewer     → get_user_profile, get_s3_object_info
```

Tool permissions are declared as Cedar policies in `cedar/policies/` and enforced via `auth=require_cedar("tool_name")` on each `@mcp.tool()` decorator in `mcp_server/server.py`. ABAC tools (e.g., `delete_s3_object`) additionally call `cedar_check_with_context()` inside the tool function for path-based access control.

### Role Assignment

Roles are defined in `permissions.toml` (gitignored; copy from `permissions.example.toml`). Group-to-role mapping is per-provider:

```toml
[group_rules.entra]
"<admin-group-guid>" = "admin"

[group_rules.cognito]
"platform-admins" = "admin"

[users]
# "user@company.com" = { role = "admin" }  # Optional overrides

[defaults]
unknown_users = "none"
```

Role selection: Users set `X-Assume-Role` header. `UserContextMiddleware` validates against available roles. For tool listing, highest-priority role is used automatically.

## Key Code Patterns

### Token Validation (Multi-IdP)

**A2A Server** (`a2a_server/server.py`) — `TokenValidator` class with `IdPConfig` dataclass:
- Detects IdP from `iss` claim, routes to matching JWKS endpoints
- Supports Cognito's non-standard `client_id` audience claim
- JWKS cached, auto-cleared on key-not-found

**MCP Server** (`mcp_server/server.py`) — FastMCP built-in `MultiAuth`:
- `AzureJWTVerifier` for Entra v2.0 + `JWTVerifier` fallback for v1.0
- `JWTVerifier` for Cognito (audience omitted; validated in middleware)

### Auth Data Propagation

```
Frontend (Bearer token + X-Assume-Role header)
  → A2A Server (ContextVars: current_user_claims, current_access_token, current_assumed_role)
    → ADK Agent (session state: user:access_token, user:role, user:email, user:groups)
      → MCP Server (ContextVars: current_user_token, current_user_role, current_user_email, current_user_provider, current_user_groups, current_user_claims)
```

Each tier uses `ContextVar` for async-safe auth propagation. The MCP server runs in stateless HTTP mode (`stateless_http=True`), so `ContextVar`s are used instead of `ctx.get_state()`.

### LLM Configuration

```python
# adk_agent/agent.py:113
model=LiteLlm(model="bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0")
```

- `RunConfig(max_llm_calls=4)` prevents infinite loops
- Rate limit retry: 3 attempts with 30s/60s/90s backoff
- API key: `AWS_BEARER_TOKEN_BEDROCK` (12-hour token, refresh before expiry)

### MCP Header Provider

```python
# adk_agent/agent.py:54-70
def mcp_header_provider(readonly_context: ReadonlyContext) -> Dict[str, str]:
    # Injects Authorization + X-Assume-Role from ADK session state
```

Sync function called by `McpToolset` on every MCP request.

### OBO Token Exchange

When `ENTRA_CLIENT_SECRET` is set, Graph tools exchange the user's custom-audience token for a Graph-scoped token via `GraphOBOExchanger` (`mcp_server/graph_obo.py`). When OBO is unavailable:
- `get_user_profile` falls back to token claims
- `list_files`, `send_email` return informative errors
- Non-Entra users get `{"error": "provider_not_supported"}`

Helper functions in `mcp_server/server.py`:
- `_require_entra_provider()` — returns error dict for non-Entra users
- `_get_effective_graph_token(scope)` — returns `(token, obo_used)` tuple

### S3 Tools

S3 tools use server-side AWS credentials (not user tokens). `_run_s3_operation()` wraps boto3 calls with `asyncio.to_thread()` and standardized error handling.

### Frontend Auth Provider

`AuthProvider.js` wraps both MSAL (Entra) and Amplify (Cognito) behind a single `useAuth()` hook:
```javascript
{ provider, isAuthenticated, user, getAccessToken, login, logout, switchProvider }
```

Provider selection is persisted in `localStorage`. The A2A client (`a2aClient.js`) centralizes JSON-RPC calls, denial classification, and audit entry creation.

### Denial Classification

`denialClassifier.js` classifies responses into four tiers:
1. HTTP 401/403 → `agent` (reads `denial_reason` from response body)
2. `[TOOL_DENIAL]` in response → `tool`
3. `[SCOPE_DENIAL]` in response → `scope`
4. Graph 403 / `insufficient_scope` / S3 errors → `resource`

## API Endpoints

### A2A Server (port 10000)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/` | Bearer | A2A JSON-RPC endpoint (`message/send`) |
| GET | `/me` | Bearer | User security context (role, groups, permissions) |
| GET | `/.well-known/agent-card.json` | No | Agent card discovery |
| GET | `/health` | No | Health check |

### ADK Agent (port 10001)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/session` | Bearer | Create user session with identity context |
| POST | `/chat` | Bearer | Send message, get buffered response |
| POST | `/chat/stream` | Bearer | Send message, get SSE streaming response |
| GET | `/health` | No | Health check |

### MCP Server (port 10002)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/mcp` | Bearer | Streamable HTTP MCP endpoint (stateless) |

## Environment Variables

### Backend (.env)

```bash
# Microsoft Entra ID
ENTRA_CLIENT_ID=<app-registration-client-id>
ENTRA_TENANT_ID=<directory-tenant-id>
ENTRA_CLIENT_SECRET=<client-secret>  # Required for OBO Graph token exchange

# AWS Cognito
COGNITO_USER_POOL_ID=<user-pool-id>
COGNITO_CLIENT_ID=<app-client-id>
COGNITO_REGION=us-east-1

# Access Control Group IDs (Entra security groups)
ADMIN_GROUP_ID=<guid>
DEVELOPER_GROUP_ID=<guid>
VIEWER_GROUP_ID=<guid>

# Cognito group names (defaults shown)
COGNITO_ADMIN_GROUP=platform-admins
COGNITO_DEVELOPER_GROUP=platform-developers
COGNITO_VIEWER_GROUP=platform-viewers

# Blocked users (comma-separated user IDs)
BLOCKED_USERS=

# Server Ports
A2A_SERVER_PORT=10000
ADK_SERVER_PORT=10001
MCP_SERVER_PORT=10002
FRONTEND_PORT=10003

# AWS (for S3 tools and Bedrock LLM)
AWS_REGION=us-east-1
AWS_BEARER_TOKEN_BEDROCK=<12-hour-token>
```

### Frontend (frontend/.env)

```bash
REACT_APP_ENTRA_CLIENT_ID=<app-registration-id>
REACT_APP_ENTRA_TENANT_ID=<directory-tenant-id>
REACT_APP_A2A_SERVER_URL=http://localhost:10000

# Cognito (optional)
REACT_APP_COGNITO_USER_POOL_ID=<user-pool-id>
REACT_APP_COGNITO_CLIENT_ID=<app-client-id>
REACT_APP_COGNITO_DOMAIN=<hosted-ui-domain>
```

## Development Workflow

### Starting Services

```bash
# Terminal 1: MCP Server
uv run python mcp_server/server.py

# Terminal 2: ADK Agent
uv run python adk_agent/agent.py

# Terminal 3: A2A Gateway
uv run python a2a_server/server.py

# Terminal 4: Frontend
cd frontend && npm start
```

### Auth Bypass for Local Testing

Copy `dev_config.example.toml` to `dev_config.toml` and set `disable_auth = true` per server. Restart affected servers. `dev_config.toml` is gitignored.

### Running Tests

```bash
uv run pytest tests/test_access_control.py -v
```

## Timeouts & Constants

| Constant | Value | Location |
|----------|-------|----------|
| ADK chat timeout | 60s | `a2a_server/server.py:351` |
| ADK session timeout | 30s | `a2a_server/server.py:403` |
| MCP connection timeout | 30s | `adk_agent/agent.py:89` |
| MCP SSE read timeout | 60s | `adk_agent/agent.py:90` |
| max_llm_calls | 4 | `adk_agent/agent.py:145` |
| Rate limit retries | 3 | `adk_agent/agent.py:280` |
| Rate limit base delay | 30s | `adk_agent/agent.py:281` |
| OBO credential cache | 128 | `mcp_server/graph_obo.py:33` |

## Error Responses

### A2A Server

| Status | `denial_reason` | Trigger |
|--------|-----------------|---------|
| 401 | `missing_token` | No `Authorization` header |
| 401 | `invalid_format` | Not `Bearer` prefix |
| 401 | `token_expired` | JWT `exp` in past |
| 401 | `validation_failed` | Any other JWT failure |
| 403 | `blocked_user` | User ID in `BLOCKED_USERS` |
| 403 | `no_group_membership` | No matching group claim |

### MCP Server (ToolError)

| Error Pattern | Trigger |
|---------------|---------|
| `[ROLE_SELECTION] Role selection required...` | Tool call without `X-Assume-Role` |
| `[TOOL_DENIAL] Cannot assume role '...'` | Role not available to user |
| `[TOOL_DENIAL] No roles available...` | No group/user mappings |
| `[TOOL_DENIAL] Access denied: Cedar denied: ...` | Cedar policy denied access for this role/tool |

## Conventions

1. **Token propagation**: Always via `Authorization: Bearer` headers, never in JSON payloads
2. **State prefix**: `user:` prefix for ADK session state persistence
3. **Context variables**: `ContextVar` for async-safe auth data (A2A: 3 vars, MCP: 6 vars)
4. **Stateless MCP**: `stateless_http=True` — no server-side session, ContextVars only
5. **Port range**: 10000+ to avoid conflicts
6. **Permission store**: `permissions.toml` is gitignored; group-to-role mappings are per-provider
7. **Multi-IdP**: Provider detected from `iss` claim; group mappings under `[group_rules.<provider>]`
8. **Graph API constants**: `GRAPH_API_BASE` in `mcp_server/server.py`
9. **Extracted helpers**: `_extract_bearer_token()` (ADK), `_make_task_event()` / `_extract_user_info()` (A2A), `_require_entra_provider()` / `_get_effective_graph_token()` / `require_cedar()` / `cedar_check_with_context()` (MCP), `detect_provider()` (shared in `dev_config.py`)
10. **Frontend shared utilities**: `a2aClient.js` centralizes API calls + `buildAuditEntry()`; `constants.js` holds `A2A_SERVER_URL` and `PROVIDER_LABELS`
11. **Lazy logger formatting**: Use `logger.info("msg: %s", val)` not f-strings in hot paths

## Logging

| Server | File | Level |
|--------|------|-------|
| A2A Gateway | `logs/a2a_server.log` | DEBUG |
| ADK Agent | `logs/adk_agent.log` | DEBUG |
| MCP Server | `logs/mcp_server.log` | INFO |

## Known Limitations

| Limitation | Impact |
|-----------|--------|
| Frontend uses buffered `/chat` not `/chat/stream` | Response shown all at once |
| Session service in-memory | Lost on restart |
| JWKS cache never time-invalidated (A2A) | Stale keys possible (auto-clears on miss) |
| No rate limiting | Could be abused |
| `delete_resource` simulated | Logs only, doesn't delete |
| httpx client per request | No connection pooling |
| Group overage not handled | Entra >150 groups → logged but not fetched via Graph |
