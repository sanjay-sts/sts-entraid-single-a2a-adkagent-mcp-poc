# Identity-Aware AI Agent System

## Project Overview

A secure, multi-tier AI agent system where user identity propagates from frontend authentication through the agent layer down to resource APIs. Access control is enforced at three independent levels (agent, tool, resource), providing defense in depth. Supports multiple Identity Providers (Entra ID, AWS Cognito).

It also carries **agent** identity across agent-to-agent calls, with the principal type (human behind the call, or not) derived from which tokens are present rather than declared. See "Multi-Agent Identity" below — the rules listed there are load-bearing, not stylistic.

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
| Orchestrator | FastAPI, no LLM (agent tier) | 10004 |
| Peer agent | FastAPI, no LLM (agent tier) | 10005 |
| Identity | Entra ID + AWS Cognito | - |
| Resources | Microsoft Graph API, AWS S3 | - |

The agent tier is optional — the human path runs without it. See "Multi-Agent Identity" below.

## Project Structure

```
/
├── a2a_server/
│   └── server.py              # A2A gateway — auth middleware, task executor, /me endpoint
├── adk_agent/
│   └── agent.py               # Google ADK agent — session mgmt, streaming, retry
├── mcp_server/
│   ├── server.py              # FastMCP tools — built-in auth, UserContextMiddleware, 10 tools
│   ├── graph_obo.py           # OBO token exchange for Graph API — GraphOBOExchanger singleton
│   └── policy.py              # PolicyEvaluator interface + TomlPolicyEvaluator
├── agent_common/              # Shared agent-identity contract — imported by every service
│   ├── principal.py           # Pure claim validation + principal derivation (no I/O)
│   ├── jwt_validator.py       # Entra JWKS signature/issuer/audience/expiry verification
│   ├── registry.py            # Agent identities + call graph (who may call whom)
│   ├── tokens.py              # Cert-backed app tokens + per-hop OBO exchange
│   ├── outbound.py            # build_agent_headers() — the only place the 2-header contract is built
│   └── config.py              # Shared BLOCKED_USERS parsing
├── orchestrator_agent/
│   └── server.py              # Fan-out to peer + gateway (:10004, no LLM)
├── peer_agent/
│   └── server.py              # Minimal subagent, callee and caller both (:10005, no LLM)
├── pki/
│   └── generate_certs.py      # Mini-CA + per-agent key pairs (pki/certs/ is gitignored)
├── event_trigger.py           # M2M entry point — CLI, no human, no user token
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

### Multi-Agent Identity

Every inter-agent call carries the caller's own certificate-backed Entra app token (`Authorization: Bearer`), and — only when a human is upstream — an OBO-exchanged user token (`X-Delegated-User-Token`). **Principal type is derived from which tokens are present, never declared by the caller.** There is no field on the wire that sets it.

| Principal | When | Authorized by | Graph tools |
|---|---|---|---|
| `delegated` | a human is upstream | the human's role (groups → `[group_rules]`) | allowed |
| `machine` | event-triggered, no human | the agent's role (app id → `[agent_rules]`) | `no_delegated_user` |

Both tokens are **audience-narrowed per hop** — each agent mints fresh credentials for its callee rather than forwarding what it received. Forwarding the inbound user token would hand the callee a token minted for *us*, replayable anywhere we can be called. The exchange keeps the human in `sub`: delegation, not impersonation.

Agents authenticate with an x509 certificate (`pki/certs/`, gitignored), never a client secret. Setup: `docs/ENTRA_AGENT_SETUP.md`.

**Rules that must not be quietly relaxed:**

1. **Signature first, claims second.** `azp`/`roles`/`aud` are attacker-supplied strings until `EntraJWTValidator` has verified the token. Never reorder these.
2. **`is_app_token()` fails closed.** It reads `idtyp == "app"` and nothing else. Do not add a "no `preferred_username`, therefore a machine" fallback — a tenant that omits that optional claim would have its humans reclassified as machines. Missing `idtyp` means agent calls are refused until it is configured, and that is the intended behaviour.
3. **Machine role resolution ignores group claims.** An app registration controls its own optional claims, so an agent promotable by a `groups` claim could grant itself any role in the tenant.
4. **A failed token exchange is a failure, not a fallback.** Proceeding without the user token silently downgrades that hop to machine privileges — a different principal than the caller asked for, with a 200 and nothing to say so.
5. **Build outbound headers with `build_agent_headers()`.** Do not hand-roll them in a new caller.
6. **Authenticate before parsing the body.** An unauthenticated request should never reach a parser.

### Role Hierarchy & Tool Permissions

```
admin      → All 10 tools
developer  → get_user_profile, list_files, list_s3_buckets, list_s3_objects, get_s3_object_info
viewer     → get_user_profile, get_s3_object_info
```

Tool permissions are declared via `auth=require_role(...)` on each `@mcp.tool()` decorator in `mcp_server/server.py`.

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
      → MCP Server (ContextVars: current_user_token, current_user_role, current_user_email, current_user_provider)
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

### Orchestrator (port 10004)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/dispatch` | Bearer agent token + optional `X-Delegated-User-Token` | Fan out to peer + gateway |
| GET | `/health` | No | Health check |

Returns `{principal_type, acting_agent, on_behalf_of, subagents}`. Each `subagents` entry is `{ok, status, response, error}` — `ok` is explicit so a refused leg is not shape-indistinguishable from a successful one. Both keys are always present, so membership proves nothing; check `ok`.

### Peer Agent (port 10005)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/invoke` | Bearer agent token + optional `X-Delegated-User-Token` | Actions: `status`, `echo`, `call_gateway` |
| GET | `/health` | No | Health check |

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
ORCHESTRATOR_PORT=10004
PEER_AGENT_PORT=10005

# Agent identities (one Entra app registration each; the gateway reuses ENTRA_CLIENT_ID)
AGENT_ORCHESTRATOR_CLIENT_ID=<guid>
AGENT_PEER_CLIENT_ID=<guid>
AGENT_EVENT_TRIGGER_CLIENT_ID=<guid>
AGENT_CERT_DIR=pki/certs          # default
AGENT_REQUIRED_ROLE=Agent.Invoke  # default

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

Agent tier (optional — the human path runs without it; needs `docs/ENTRA_AGENT_SETUP.md` and `uv run python pki/generate_certs.py`):

```bash
# Terminal 5: Peer agent
uv run python peer_agent/server.py

# Terminal 6: Orchestrator
uv run python orchestrator_agent/server.py

# Fire a machine-principal chain (no human anywhere in it)
uv run python event_trigger.py --task status
```

Exit codes: `0` dispatched and resolved a machine principal, `1` could not run, `2` the orchestrator refused, `3` it worked but a human appeared in a chain that should have none.

### Auth Bypass for Local Testing

Copy `dev_config.example.toml` to `dev_config.toml` and set `disable_auth = true` per server. Restart affected servers. `dev_config.toml` is gitignored.

### Running Tests

```bash
uv run pytest tests/ -m "not integration" -v   # the whole unit suite
uv run pytest tests/ -m integration -v         # real tenant + all services; skips cleanly otherwise
```

`tests/test_access_control.py` and `test_security_dashboard.py` need the servers running and real `TEST_*_TOKEN`s — connection errors from those two on a bare checkout are expected, not a regression.

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

Agent-caller path (gateway, orchestrator, peer — all use the same denial shape):

| Status | `denial_reason` | Trigger |
|--------|-----------------|---------|
| 401 | `validation_failed` | Signature, issuer, expiry — **or audience**, which is checked here first |
| 403 | `not_an_agent_token` | Token is not `idtyp=app` where one is required |
| 403 | `wrong_audience` | Claim-level audience check. Unreachable for a live token; see the limitation above |
| 403 | `unknown_agent` | `azp` not in the callee's allow-list (`agent_common/registry.py`) |
| 403 | `agent_not_authorized` | Caller lacks the `Agent.Invoke` app role |
| 403 | `delegated_token_not_a_user` | `X-Delegated-User-Token` carried an app-only token |
| 403 | `blocked_user` | Rider token's `sub` in `BLOCKED_USERS` — checked independently at every hop |

### MCP Server (ToolError)

| Error Pattern | Trigger |
|---------------|---------|
| `[ROLE_SELECTION] Role selection required...` | Tool call without `X-Assume-Role` |
| `[TOOL_DENIAL] Cannot assume role '...'` | Role not available to user |
| `[TOOL_DENIAL] No roles available...` | No group/user mappings |
| `[TOOL_DENIAL] Access denied: Role '...' cannot use this tool` | Role not in `auth=require_role(...)` |

## Conventions

1. **Token propagation**: Always via `Authorization: Bearer` headers, never in JSON payloads
2. **State prefix**: `user:` prefix for ADK session state persistence
3. **Context variables**: `ContextVar` for async-safe auth data (A2A: 3 vars, MCP: 6 vars — the last two are `current_principal_type` and `current_agent_id`). Every path that sets any of them must set *all* of them: stateless HTTP reuses contexts, and a stale `machine` left behind by a previous request would refuse a human's Graph call for no visible reason
4. **Stateless MCP**: `stateless_http=True` — no server-side session, ContextVars only
5. **Port range**: 10000+ to avoid conflicts
6. **Permission store**: `permissions.toml` is gitignored; group-to-role mappings are per-provider
7. **Multi-IdP**: Provider detected from `iss` claim; group mappings under `[group_rules.<provider>]`
8. **Graph API constants**: `GRAPH_API_BASE` in `mcp_server/server.py`
9. **Extracted helpers**: `_extract_bearer_token()` (ADK), `_make_task_event()` / `_extract_user_info()` (A2A), `_require_entra_provider()` / `_get_effective_graph_token()` (MCP)
10. **Frontend shared utilities**: `a2aClient.js` centralizes API calls + `buildAuditEntry()`; `constants.js` holds `A2A_SERVER_URL` and `PROVIDER_LABELS`
11. **Lazy logger formatting**: Use `logger.info("msg: %s", val)` not f-strings in hot paths
12. **Agent identity**: certificates only, never client secrets. `pki/certs/` is gitignored and must stay so
13. **Shared agent contract**: anything both an agent caller and an agent callee rely on belongs in `agent_common/`, not copied. The independent *checks* stay duplicated on purpose — no hop trusts a hop it cannot see — but the code performing them does not
14. **Exception text never reaches an agent caller**: log the detail, return a stable reason string. Exception text carries internal URLs and configuration, and the caller is another service, not an operator

## Logging

| Server | File | Level |
|--------|------|-------|
| A2A Gateway | `logs/a2a_server.log` | DEBUG |
| ADK Agent | `logs/adk_agent.log` | DEBUG |
| MCP Server | `logs/mcp_server.log` | INFO |
| Orchestrator | `logs/orchestrator.log` | INFO |
| Peer Agent | `logs/peer_agent.log` | INFO |

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
| Agent hops run over plain HTTP — no mTLS | A rogue squatting a callee's port can harvest bearer tokens and replay them at the real callee. Largest open gap in the agent tier; closed in Phase 2 |
| MCP server shares the gateway's app registration | Per-hop audience narrowing stops one hop short — the token MCP validates was minted for the gateway. Confused-deputy gap, predates the agent work |
| Integration tests written but never run | Nothing has yet proven Entra accepts a certificate assertion from these app registrations. Blocked on the one-time tenant-admin setup |
| Two JWT validators | Gateway `TokenValidator` (multi-IdP, no JWKS TTL) vs `agent_common/jwt_validator.py` (Entra-only, has a TTL). They differ in behaviour, not just code |
| Cross-hop replay is `401 validation_failed`, not `403 wrong_audience` | The signature validator checks audience before the claim-level check does. Both exist; don't write tests expecting the 403 |
