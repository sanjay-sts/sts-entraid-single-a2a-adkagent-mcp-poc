# Identity-Aware AI Agent System

## Project Overview

This project implements a **secure, multi-tier AI agent system** where user identity propagates from frontend authentication through the agent layer down to resource APIs. The architecture enforces access control at three independent levels, providing defense in depth.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  React Frontend │───▶│   A2A Server    │───▶│   Google ADK    │───▶│   FastMCP       │
│  (MSAL.js)      │    │   (Gateway)     │    │   Agent         │    │   Tools         │
│  Port: 10003    │    │   Port: 10000   │    │   Port: 10001   │    │   Port: 10002   │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
        │                      │                      │                      │
        │  Entra ID Token      │  Token Validation    │  User Context        │  Token Access
        │  (Authorization)     │  + Agent-Level ACL   │  + Tool-Level ACL    │  + Resource ACL
        ▼                      ▼                      ▼                      ▼
   ┌─────────────────────────────────────────────────────────────────────────────────────┐
   │                              Microsoft Graph API                                      │
   │                         (Resource-Level Scope Enforcement)                           │
   └─────────────────────────────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component | Technology | Port | Purpose |
|-----------|------------|------|---------|
| Frontend | React 18 + MSAL.js 3.6 | 10003 | User authentication, token acquisition |
| Gateway | A2A Protocol (FastAPI + a2a-sdk) | 10000 | Agent discovery, agent-level ACL, streaming |
| Agent | Google ADK + LiteLLM + Claude Sonnet 4 | 10001 | LLM orchestration, tool calling, retry |
| Tools | FastMCP | 10002 | Tool execution, token propagation |
| Identity | Microsoft Entra ID | - | OAuth 2.0, group claims, scopes |
| Resources | Microsoft Graph API | - | User data, files, email |

## Project Structure

```
/
├── a2a_server/
│   └── server.py              # A2A gateway (568 lines) - auth middleware, task executor
├── adk_agent/
│   └── agent.py               # Google ADK agent (443 lines) - session mgmt, streaming, retry
├── mcp_server/
│   └── server.py              # FastMCP tools (561 lines) - 1 middleware, auth decorators, 7 tools
├── frontend/
│   ├── public/
│   │   └── index.html         # HTML entry point
│   ├── src/
│   │   ├── App.js             # Dashboard layout shell - sidebar + main area
│   │   ├── App.css            # Dark theme dashboard styles (~1130 lines)
│   │   ├── authConfig.js      # MSAL config + scope presets (basic/files/email/full/destructive)
│   │   ├── index.js           # MSAL provider setup (30 lines)
│   │   ├── components/
│   │   │   ├── AuthStatus.js        # Multi-account switcher dropdown
│   │   │   ├── LoginPrompt.js       # Sign-in prompt (extracted from App.js)
│   │   │   ├── SecurityContextPanel.js  # Role badge, groups, scopes, expiry countdown
│   │   │   ├── TokenInspector.js    # JWT header/payload decoder (display only)
│   │   │   ├── ConversationTabs.js  # Multi-tab chat with per-tab scope (max 4)
│   │   │   ├── ChatInterface.js     # Chat with denial tagging + latency tracking
│   │   │   ├── RBACTestMatrix.js    # One-click test grid with pass/fail
│   │   │   ├── AuditLog.js          # Request history table with denial tiers
│   │   │   └── DenialIndicator.js   # Color-coded denial badge component
│   │   └── utils/
│   │       ├── tokenDecoder.js      # JWT base64url decode helper
│   │       ├── denialClassifier.js  # HTTP status + response → denial tier classification
│   │       └── testScenarios.js     # Predefined test prompts with expected outcomes
│   ├── package.json           # React dependencies
│   └── .env.example           # Frontend env template
├── tests/
│   ├── __init__.py            # Package marker
│   ├── test_access_control.py # Access control tests (339 lines)
│   └── conftest.py            # Pytest fixtures (50 lines)
├── logs/                      # Runtime logs (auto-created)
│   ├── a2a_server.log
│   ├── adk_agent.log
│   └── mcp_server.log
├── scratchpad/
│   └── singleagent/
│       └── single_agent_adk_mcp.md  # Implementation guide (1630 lines)
├── dev_config.py              # Shared TOML config loader for auth bypass (~45 lines)
├── dev_config.example.toml    # Template for dev_config.toml (committed, defaults false)
├── .env.example               # Backend env template
├── .gitignore                 # Git ignore rules
├── pyproject.toml             # Python project config (uv)
├── requirements.txt           # Python dependencies
├── README.md                  # Setup guide
├── TESTING.md                 # Comprehensive testing guide (481 lines)
└── CLAUDE.md                  # This file
```

## Current Status & Known Issues

### Streaming Support

| Component | Status | Notes |
|-----------|--------|-------|
| A2A Server | Enabled | `AgentCapabilities(streaming=True)` in agent card |
| ADK Agent | Has endpoint | `/chat/stream` for SSE streaming |
| Frontend | Not using stream | Uses buffered `/chat` endpoint |

### Local Testing with A2A / MCP Inspector

The A2A Inspector and MCP Inspector cannot send Bearer tokens, causing 401s and ToolError spam.

**Solution**: Copy `dev_config.example.toml` to `dev_config.toml` and set `disable_auth = true` for the servers you want to bypass. Restart the servers.

```bash
cp dev_config.example.toml dev_config.toml
# Edit dev_config.toml — set disable_auth = true under [a2a], [adk], [mcp]
```

**How it works**:
- `dev_config.py` (shared loader) reads `dev_config.toml` using stdlib `tomllib`
- Each server imports `is_auth_disabled()` and `get_section()` from `dev_config.py`
- When `disable_auth = true`, the server sets mock auth context and skips JWT validation
- MCP server's `on_list_tools()` hook also sets bypass context so `auth=` callables pass during tool listing
- `dev_config.toml` is gitignored; `dev_config.example.toml` ships with all options set to `false`
- Prominent WARNING banners are logged when bypass is active

**Configuration sections**: `[a2a]`, `[adk]`, `[mcp]` — each has `disable_auth` boolean. The `[mcp]` section also has `default_role`, `default_email`, and `default_scopes` to control the mock identity.

### Deprecation Warning

A2A Inspector uses old endpoint `/.well-known/agent.json`. The a2a-sdk now prefers `/.well-known/agent-card.json`. Both currently work.

### Token Validation (v1.0 and v2.0 Support)

The system supports both Entra ID v1.0 and v2.0 tokens. Microsoft Graph API returns v1.0 tokens even when requesting via v2.0 endpoints.

**Supported JWKS endpoints** (`a2a_server/server.py:64-68`, `mcp_server/server.py:52-56`):
```python
JWKS_URIS = [
    f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys",  # v2.0
    f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys",       # v1.0
    "https://login.microsoftonline.com/common/discovery/keys",             # common
]
```

**Supported issuers** (`a2a_server/server.py:69-72`, `mcp_server/server.py:57-60`):
```python
VALID_ISSUERS = [
    f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",  # v2.0 issuer
    f"https://sts.windows.net/{TENANT_ID}/",                # v1.0 issuer (Graph tokens)
]
```

**Custom API audience support** (`a2a_server/server.py:150-153`, `mcp_server/server.py:177-180`):
```python
valid_audiences = [
    CLIENT_ID,
    f"api://{CLIENT_ID}",  # Custom API scope audience
]
```

## Security Model

### Three-Tier Access Control

| Level | Location | Mechanism | Code Location | Denies Access When |
|-------|----------|-----------|---------------|-------------------|
| **Agent** | A2A Server | Group membership, blocklist | `a2a_server/server.py:444-539` | User blocked or not in allowed group |
| **Tool** | FastMCP | Per-tool `auth=` callables | `mcp_server/server.py:208-236` | User role lacks tool permission |
| **Resource** | Graph API | OAuth scopes | External | Token missing required scope |

### Role Hierarchy & Permissions

```
admin      → All tools: get_user_profile, list_files, send_email, delete_resource,
                        get_current_time, convert_timezone, get_time_difference
developer  → Subset: get_user_profile, list_files
viewer     → Limited: get_user_profile only
```

**Tool Permissions** (declared via FastMCP 3 `auth=` decorator, `mcp_server/server.py:244-494`):
```python
@mcp.tool(auth=[require_role("admin", "developer", "viewer"), require_scopes_from_token("User.Read")])
async def get_user_profile() -> dict: ...

@mcp.tool(auth=[require_role("admin", "developer"), require_scopes_from_token("Files.Read")])
async def list_files(folder_path: str = "/") -> dict: ...

@mcp.tool(auth=[require_role("admin"), require_scopes_from_token("Mail.Send")])
async def send_email(to: str, subject: str, body: str) -> dict: ...

@mcp.tool(auth=[require_role("admin"), require_scopes_from_token("Files.ReadWrite.All")])
async def delete_resource(resource_id: str) -> dict: ...

# Time tools -- role only (no Graph scopes needed)
@mcp.tool(auth=require_role("admin"))
async def get_current_time(timezone: str = "UTC") -> dict: ...
@mcp.tool(auth=require_role("admin"))
async def convert_timezone(...) -> dict: ...
@mcp.tool(auth=require_role("admin"))
async def get_time_difference(...) -> dict: ...
```

Custom auth callables (`require_role`, `require_scopes_from_token`) read from ContextVars set by `TokenValidationMiddleware`. They raise `ToolError` with descriptive messages on denial.

### Group-to-Role Mapping

Roles derived from Entra ID security group membership (highest privilege wins):
- `ADMIN_GROUP_ID` -> `admin`
- `DEVELOPER_GROUP_ID` -> `developer`
- `VIEWER_GROUP_ID` -> `viewer`

## Data Flow

```
User         Frontend           A2A Gateway        ADK Agent          MCP Server       Graph API
  │              │                   │                  │                   │               │
  1: Send msg    │                   │                  │                   │               │
  └─────────────>│                   │                  │                   │               │
                 │ 2: acquireToken() │                  │                   │               │
                 │ (MSAL.js)         │                  │                   │               │
                 │                   │                  │                   │               │
                 3: POST / + Bearer  │                  │                   │               │
                 └──────────────────>│                  │                   │               │
                                     │ 4: Validate JWT  │                   │               │
                                     │ Check blocklist  │                   │               │
                                     │ Verify groups    │                   │               │
                                     │                  │                   │               │
                                     5: POST /chat     │                   │               │
                                     └─────────────────>│                   │               │
                                                        │ 6: Store context  │               │
                                                        │ in session state  │               │
                                                        │                   │               │
                                                        7: Call MCP tool   │               │
                                                        └──────────────────>│               │
                                                                            │ 8: Validate   │
                                                                            │ role + scopes │
                                                                            │               │
                                                                            9: Graph API   │
                                                                            └──────────────>│
                                                                            │<──────────────│
                                                        │<──────────────────│               │
                                     │<─────────────────│                   │               │
                 │<──────────────────│                  │                   │               │
  │<─────────────│                   │                  │                   │               │
```

## API Endpoints

### A2A Server (port 10000)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/agent-card.json` | No | Agent card discovery (preferred) |
| GET | `/.well-known/agent.json` | No | Agent card discovery (legacy) |
| GET | `/health` | No | Health check |
| GET | `/docs` | No | OpenAPI docs UI |
| GET | `/openapi.json` | No | OpenAPI schema |
| POST | `/` | Bearer | A2A JSON-RPC endpoint (`message/send`) |
| GET | `/me` | Bearer | User security context (role, groups, permissions) |
| OPTIONS | `*` | No | CORS preflight |

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
| POST | `/mcp` | Bearer (in MCP headers) | Streamable HTTP MCP endpoint (stateless) |

## Inter-Service Communication

| From | To | Method | Timeout | Client Pattern |
|------|----|--------|---------|----------------|
| A2A Server | ADK Agent | `POST /session` | 30s | `httpx.AsyncClient()` per request |
| A2A Server | ADK Agent | `POST /chat` | 60s | `httpx.AsyncClient()` per request |
| ADK Agent | MCP Server | MCP over Streamable HTTP | 30s conn / 60s SSE | `McpToolset` with `header_provider` |
| MCP Server | Graph API | `GET/POST` various | httpx default | `httpx.AsyncClient()` per request |

> **Note**: All `httpx.AsyncClient()` instances are created per request (no connection pooling). Each `async with httpx.AsyncClient() as client:` block opens and closes a new connection.

## Key Code Patterns

### LLM Model Configuration

```python
# adk_agent/agent.py:101
model=LiteLlm(model="anthropic/claude-sonnet-4-20250514")
```

The agent uses Claude Sonnet 4 via LiteLLM. API key mapping (`adk_agent/agent.py:44-46`):
```python
# Map CLAUDE_API_KEY to ANTHROPIC_API_KEY for LiteLLM compatibility
if os.getenv("CLAUDE_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
    os.environ["ANTHROPIC_API_KEY"] = os.getenv("CLAUDE_API_KEY")
```

Loop prevention: `RunConfig(max_llm_calls=4)` at `adk_agent/agent.py:130`.

Rate limit retry: 3 attempts with 30s/60s/90s backoff (`adk_agent/agent.py:264-296`).

### ADK: MCP Header Provider

```python
# adk_agent/agent.py:49-61
def mcp_header_provider(readonly_context: ReadonlyContext) -> Dict[str, str]:
    """Provides Authorization header for MCP calls from session state."""
    if readonly_context and readonly_context.state:
        access_token = readonly_context.state.get("user:access_token", "")
        if access_token:
            return {"Authorization": f"Bearer {access_token}"}
    return {}
```

This **sync** function is called by `McpToolset` on every MCP request to inject the user's Bearer token from ADK session state.

### ADK: McpToolset Configuration

```python
# adk_agent/agent.py:77-96
self.mcp_toolset = McpToolset(
    connection_params=StreamableHTTPConnectionParams(
        url=MCP_SERVER_URL,
        timeout=30.0,
        sse_read_timeout=60.0,
    ),
    tool_filter=[
        "get_user_profile", "list_files", "send_email", "delete_resource",
        "get_current_time", "convert_timezone", "get_time_difference",
    ],
    header_provider=mcp_header_provider,
)
```

The `tool_filter` whitelist controls which MCP tools are exposed to the LLM. The `header_provider` injects per-request auth.

### ADK: Session Token Refresh

```python
# adk_agent/agent.py:257-261
# Update access token in the storage directly
# user: prefixed keys are stored in user_state with prefix stripped
self.session_service.user_state.setdefault("identity-agent", {}).setdefault(user_id, {})["access_token"] = access_token
```

Between chat requests, the A2A server may forward a fresh token. This directly manipulates `InMemorySessionService.user_state` to update the token without recreating the session.

### FastMCP: Context Variables

```python
# mcp_server/server.py:25-28
current_user_token: ContextVar[str] = ContextVar("current_user_token", default="")
current_user_role: ContextVar[str] = ContextVar("current_user_role", default="none")
current_user_email: ContextVar[str] = ContextVar("current_user_email", default="")
current_user_scopes: ContextVar[list] = ContextVar("current_user_scopes", default=[])
```

The MCP server uses 4 `ContextVar`s (vs A2A server's 2) because FastMCP runs in **stateless HTTP mode** (`stateless_http=True`), meaning `ctx.get_state()` / `ctx.set_state()` are not available. Middleware sets these variables; tools read them.

### FastMCP: Token Access in Tools

```python
# mcp_server/server.py:244-250
@mcp.tool(auth=[require_role("admin", "developer", "viewer"), require_scopes_from_token("User.Read")])
async def get_user_profile() -> dict:
    """Fetch the current user's Microsoft Graph profile."""
    access_token = current_user_token.get()
    user_email = current_user_email.get()
    user_role = current_user_role.get()
```

Tools read auth context from `ContextVar`s set by middleware, not from `ctx.get_state()`. Authorization is enforced by `auth=` callables on each tool decorator.

**Graph API Fallback**: `get_user_profile` returns token claims with `"source": "token_claims"` when Graph API returns 401/403 (`mcp_server/server.py:265-272`). This happens because the token uses a custom API audience, not the Graph API audience (OBO flow would be needed).

### FastMCP: Middleware + Auth Decorators

```python
# mcp_server/server.py:239-241
mcp = FastMCP(name="Identity-Aware MCP Server")
mcp.add_middleware(TokenValidationMiddleware())   # Validates JWT, sets ContextVars
# Per-tool auth via @mcp.tool(auth=...) replaces ToolAuthorizationMiddleware
```

**Execution order**: Middleware `on_call_tool` (sets ContextVars) → `auth=` callables (read ContextVars, enforce role/scopes) → tool function.

**Auth helpers** (`mcp_server/server.py:208-236`):
- `require_role(*roles)` -- checks `current_user_role` ContextVar; raises `ToolError` prefixed with `[TOOL_DENIAL]`
- `require_scopes_from_token(*scopes)` -- checks `current_user_scopes` ContextVar; raises `ToolError` prefixed with `[SCOPE_DENIAL]`
- These prefixes survive LLM paraphrasing and enable frontend denial classification

### FastMCP: Stateless HTTP Mode

```python
# mcp_server/server.py:553-560
mcp.run(
    transport="streamable-http",
    host="0.0.0.0",
    port=int(os.getenv("MCP_SERVER_PORT", 10002)),
    path="/mcp",
    stateless_http=True,  # No session required
)
```

Stateless mode means each MCP request is independent -- no server-side session. This is why `ContextVar`s are used instead of `ctx.get_state()` for passing auth data from middleware to tools.

### Google ADK: Session State

```python
# adk_agent/agent.py:148-154
# Use "user:" prefix for persistence across interactions
initial_state = {
    "user:access_token": access_token,
    "user:email": user_info.get("email", user_info.get("preferred_username", "")),
    "user:name": user_info.get("name", user_info.get("displayName", "")),
    "user:groups": user_info.get("groups", []),
    "user:role": role,
}
```

### A2A: Agent Card Configuration

```python
# a2a_server/server.py:364-433
agent_card = AgentCard(
    name="Identity-Aware AI Agent",
    description="An AI agent with Entra ID authentication that enforces role-based access control via MCP tools.",
    url=f"http://localhost:{A2A_SERVER_PORT}/",
    version="1.0.0",
    defaultInputModes=["text/plain"],
    defaultOutputModes=["text/plain", "application/json"],
    capabilities=AgentCapabilities(streaming=True),
    security=[{"bearer": []}],
    security_schemes={
        "bearer": SecurityScheme(root=HTTPAuthSecurityScheme(
            scheme="bearer",
            bearer_format="JWT",
            description="Entra ID JWT token authentication",
        ))
    },
    skills=[...],
)
```

### Agent Card Skills

| ID | Name | Access | Example Queries |
|----|------|--------|-----------------|
| `identity_info` | Identity Information | All authenticated | "What's my email?", "Who am I?" |
| `permissions` | Permission Check | All authenticated | "What are my permissions?", "What can I do?" |
| `graph_profile` | Microsoft Graph Profile | All (User.Read) | "Show my Microsoft profile" |
| `onedrive_files` | OneDrive Files | Admin/Developer (Files.Read) | "List my files" |
| `time_current` | Current Time | Admin only | "What time is it in Tokyo?" |
| `time_convert` | Timezone Converter | Admin only | "Convert 3pm EST to PST" |
| `time_difference` | Timezone Difference | Admin only | "Time difference between NYC and London" |

### A2A: Context Variables for Auth Propagation

```python
# a2a_server/server.py:20-21
from contextvars import ContextVar

current_user_claims: ContextVar[dict] = ContextVar("current_user_claims", default={})
current_access_token: ContextVar[str] = ContextVar("current_access_token", default="")

# Set in auth middleware (line 520-521)
current_user_claims.set(claims)
current_access_token.set(token)

# Access in IdentityAwareAgentExecutor (line 205-206)
user_claims = current_user_claims.get()
access_token = current_access_token.get()
```

### React/MSAL: Token Acquisition

```javascript
// frontend/src/App.js:92-110
const getAccessToken = useCallback(async () => {
    const scopes = graphScopes[selectedScopes];
    try {
        const response = await instance.acquireTokenSilent({ scopes, account });
        return response.accessToken;
    } catch (error) {
        if (error instanceof InteractionRequiredAuthError) {
            const response = await instance.acquireTokenPopup({ scopes });
            return response.accessToken;
        }
        throw error;
    }
}, [instance, account, selectedScopes]);
```

### Custom API Scope Configuration

```javascript
// frontend/src/authConfig.js:27-39
const API_SCOPE = `api://${process.env.REACT_APP_ENTRA_CLIENT_ID}/access_as_user`;

export const graphScopes = {
  basic: [API_SCOPE, 'User.Read'],
  files: [API_SCOPE, 'User.Read', 'Files.Read'],
  email: [API_SCOPE, 'User.Read', 'Mail.Send'],
  full: [API_SCOPE, 'User.Read', 'Files.Read', 'Mail.Send'],
  destructive: [API_SCOPE, 'User.Read', 'Files.Read', 'Files.ReadWrite.All', 'Mail.Send'],
};
```

### A2A: IdentityAwareAgentExecutor

```python
# a2a_server/server.py:198-359
class IdentityAwareAgentExecutor(AgentExecutor):
    """Agent executor that forwards requests to the ADK agent with user context."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        # Get user context from context variables
        user_claims = current_user_claims.get()
        access_token = current_access_token.get()

        # Ensure session, call ADK agent, emit task status events
        ...

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        # Emit canceled status
        ...

    async def _ensure_session(self, user_id: str, user_claims: dict, access_token: str) -> str:
        # Create session with ADK agent if not exists
        ...
```

## Environment Variables

### Backend (.env)

```bash
# Microsoft Entra ID
ENTRA_CLIENT_ID=<app-registration-client-id>
ENTRA_TENANT_ID=<directory-tenant-id>

# Access Control Group IDs
ADMIN_GROUP_ID=<admin-security-group-id>
DEVELOPER_GROUP_ID=<developer-security-group-id>
VIEWER_GROUP_ID=<viewer-security-group-id>

# Optional Blocklist (comma-separated user IDs)
BLOCKED_USERS=

# Server Ports
A2A_SERVER_PORT=10000
ADK_SERVER_PORT=10001
MCP_SERVER_PORT=10002
FRONTEND_PORT=10003

# LLM API Key (for Claude via LiteLLM)
# Set either CLAUDE_API_KEY or ANTHROPIC_API_KEY
# adk_agent/agent.py:44-46 auto-maps CLAUDE_API_KEY -> ANTHROPIC_API_KEY
CLAUDE_API_KEY=<anthropic-api-key>
```

> **Stale .env.example**: The `.env.example` file still references `ENTRA_AUTHORITY` and `GOOGLE_API_KEY`. Neither is used by any Python code. `ENTRA_AUTHORITY` is only used in `frontend/src/authConfig.js` (hardcoded there). The agent uses Claude via LiteLLM, not Google AI.

### Frontend (frontend/.env)

```bash
REACT_APP_ENTRA_CLIENT_ID=<app-registration-id>
REACT_APP_ENTRA_TENANT_ID=<directory-tenant-id>
REACT_APP_A2A_SERVER_URL=http://localhost:10000
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

### Health Checks

```bash
curl http://localhost:10000/health  # A2A Gateway
curl http://localhost:10001/health  # ADK Agent
curl http://localhost:10002/health  # MCP Server (if exposed)
```

### Agent Card Discovery

```bash
# New endpoint (preferred)
curl http://localhost:10000/.well-known/agent-card.json

# Legacy endpoint (deprecated but works)
curl http://localhost:10000/.well-known/agent.json
```

### Running Tests

```bash
# Requires all services running
uv run pytest tests/test_access_control.py -v
```

## Current Limitations & TODOs

| Limitation | Impact | Location |
|-----------|--------|----------|
| Frontend not using stream endpoint | UI shows response all at once | `frontend/src/App.js` |
| Session service in-memory | Lost on service restart | `adk_agent/agent.py:68` |
| JWKS cache never invalidated | Could use stale keys (but clears on key-not-found) | `a2a_server/server.py:91-105` |
| No rate limiting | Could be abused | All servers |
| MCP delete_resource simulated | Only logs, doesn't delete | `mcp_server/server.py:338-345` |
| A2A Inspector requires auth bypass | Can't test without workaround | `a2a_server/server.py` |
| httpx client per request | No connection pooling between services | All inter-service calls |
| Stale `.env.example` | Still lists `ENTRA_AUTHORITY` and `GOOGLE_API_KEY` | `.env.example` |
| Graph API needs OBO flow | `get_user_profile` falls back to token claims | `mcp_server/server.py:265-272` |

## Timeouts & Configuration Constants

| Constant | Value | Location | Notes |
|----------|-------|----------|-------|
| ADK chat timeout | 60s | `a2a_server/server.py:265` | A2A -> ADK `/chat` call |
| ADK session timeout | 30s | `a2a_server/server.py:353` | A2A -> ADK `/session` call |
| MCP connection timeout | 30s | `adk_agent/agent.py:80` | `StreamableHTTPConnectionParams.timeout` |
| MCP SSE read timeout | 60s | `adk_agent/agent.py:81` | `StreamableHTTPConnectionParams.sse_read_timeout` |
| max_llm_calls | 4 | `adk_agent/agent.py:130` | Prevents infinite LLM loops |
| Rate limit max retries | 3 | `adk_agent/agent.py:264` | For Claude API rate limits |
| Rate limit base delay | 30s | `adk_agent/agent.py:265` | Backoff: 30s, 60s, 90s |

## Error Responses

### A2A Server (`a2a_server/server.py`)

| Status | Error Key | Message | `denial_level` | `denial_reason` | Trigger |
|--------|-----------|---------|-----------------|------------------|---------|
| 401 | `unauthorized` | Missing Authorization header | `agent` | `missing_token` | No `Authorization` header |
| 401 | `unauthorized` | Invalid Authorization format | `agent` | `invalid_format` | Not `Bearer` prefix |
| 401 | `token_expired` | Token has expired | `agent` | `token_expired` | JWT `exp` claim in past |
| 401 | `auth_failed` | (dynamic) | `agent` | `validation_failed` | Any other JWT validation failure |
| 403 | `access_denied` | Your account has been blocked | `agent` | `blocked_user` | User ID in `BLOCKED_USERS` |
| 403 | `access_denied` | Not a member of any authorized group | `agent` | `no_group_membership` | No matching group claim |

### ADK Agent (`adk_agent/agent.py`)

| Status | Detail | Trigger |
|--------|--------|---------|
| 401 | Missing or invalid Authorization header | No Bearer token on `/session`, `/chat`, or `/chat/stream` |
| 400 | user_id is required | Missing `user_id` in `/session` body |
| 400 | message, user_id, and session_id are required | Missing fields in `/chat` or `/chat/stream` body |

### MCP Server (`mcp_server/server.py`) -- ToolError exceptions

| Error Pattern | Trigger |
|---------------|---------|
| `Missing or invalid Authorization header` | No Bearer token in MCP request headers |
| `Token validation failed: {details}` | JWT validation fails (bad signature, expired, wrong audience) |
| `[TOOL_DENIAL] Access denied: Role '{role}' cannot use this tool. Required roles: [...]` | User role not in `auth=require_role(...)` |
| `[SCOPE_DENIAL] Insufficient permissions: Missing scopes [...]` | Token missing scopes in `auth=require_scopes_from_token(...)` |

## Logging

All servers log to both console and files in the `logs/` directory:

| Server | Log File | Log Level |
|--------|----------|-----------|
| A2A Gateway | `logs/a2a_server.log` | DEBUG |
| ADK Agent | `logs/adk_agent.log` | DEBUG |
| MCP Server | `logs/mcp_server.log` | INFO |

Logs are useful for debugging token validation issues. Key log messages:
- `Token claims (unverified): iss=..., aud=...` - Shows token claims before validation
- `Token validated successfully using key from...` - Successful validation
- `Access denied: Role '...' cannot use tool '...'` - Permission denial

## Important Conventions

1. **Token Propagation**: Always pass user tokens via `Authorization: Bearer` headers, never in JSON payloads
2. **State Prefix**: Use `user:` prefix for ADK session state to ensure persistence
3. **Error Handling**: Return structured errors with `error` and `message` fields
4. **Scope Checking**: Check both role AND scopes before allowing tool execution
5. **JWKS Caching**: Cache JWKS responses to avoid repeated fetches; cache clears on key-not-found errors
6. **Port Range**: Use 10000+ ports to avoid conflicts with common services
7. **Context Variables**: Use `ContextVar` for passing auth data across async boundaries (A2A server and MCP server)
8. **Test Tokens**: Tests use HS256 mock tokens (not RS256), so they cannot validate real Entra ID token signatures
9. **Client ID Sync**: Frontend `REACT_APP_ENTRA_CLIENT_ID` and backend `ENTRA_CLIENT_ID` must be the same value

### A2A Server: `/me` Endpoint

```python
# a2a_server/server.py - GET /me
# Returns authenticated user's security context
# Goes through auth middleware (requires valid Bearer token)
@app.get("/me")
async def get_me(request: Request):
    claims = current_user_claims.get()
    role = _determine_role(claims.get("groups", []))
    # Returns: user info, security context, permission matrix, tool scopes
```

The `/me` endpoint reuses the same role determination logic as the ADK agent and MCP server. It provides the frontend Security Context Panel with real-time role, group, scope, and permission data.

### Frontend: Denial Classification

```javascript
// frontend/src/utils/denialClassifier.js
// Classifies denials into four tiers based on HTTP status and response content:
// 1. HTTP 401/403 → level: 'agent' (reads denial_reason from response body)
// 2. Response contains '[TOOL_DENIAL]' → level: 'tool'
// 3. Response contains '[SCOPE_DENIAL]' → level: 'scope'
// 4. Graph API 403 / insufficient_scope → level: 'resource'
// 5. Otherwise → null (success)
```

### Frontend: Security Testing Dashboard

The frontend is a Security Testing Dashboard with these components:

| Component | File | Purpose |
|-----------|------|---------|
| SecurityContextPanel | `components/SecurityContextPanel.js` | Calls `GET /me`, shows role/groups/scopes/expiry |
| TokenInspector | `components/TokenInspector.js` | Decodes JWT for display (never for auth) |
| RBACTestMatrix | `components/RBACTestMatrix.js` | One-click test grid with predefined scenarios |
| ConversationTabs | `components/ConversationTabs.js` | Multi-tab chat, per-tab scope selection |
| ChatInterface | `components/ChatInterface.js` | Chat with denial tagging + latency |
| AuditLog | `components/AuditLog.js` | Request history with denial tiers |
| DenialIndicator | `components/DenialIndicator.js` | Color-coded badge (AGENT/TOOL/SCOPE/RESOURCE) |
| AuthStatus | `components/AuthStatus.js` | Multi-account switcher |

## Verification Checklist

### Agent-Level (a2a_server/server.py:444-539)
- [ ] Unauthenticated requests return 401
- [ ] Blocked users receive 403
- [ ] Users without allowed group receive 403
- [ ] Valid users can send messages

### Tool-Level (mcp_server/server.py:208-236, auth= decorators)
- [ ] Viewer cannot use `send_email` or `delete_resource`
- [ ] Developer cannot use `send_email`
- [ ] Admin can use all tools (including time tools)
- [ ] Viewer/developer cannot use time tools (`get_current_time`, `convert_timezone`, `get_time_difference`)
- [ ] Denials return clear error messages

### Resource-Level (Microsoft Graph)
- [ ] Missing `Files.Read` scope -> 403 on file operations
- [ ] Missing `Mail.Send` scope -> 403 on email operations
- [ ] Error messages indicate missing scopes

### Security Testing Dashboard
- [ ] `GET /me` returns correct role, groups, permissions for authenticated user
- [ ] Security Context Panel shows live token expiry countdown
- [ ] Token Inspector decodes JWT header and payload correctly
- [ ] RBAC Test Matrix scenarios show PASS for all expected outcomes
- [ ] Denial badges show correct tier: AGENT (red), TOOL (orange), SCOPE (amber), RESOURCE (purple)
- [ ] Multi-tab conversations maintain independent scope and message history
- [ ] Audit Log records all requests with denial classification and latency
- [ ] Account switcher updates Security Context Panel on account change

## External Documentation

- [FastMCP Documentation](https://gofastmcp.com)
- [Google ADK Documentation](https://google.github.io/adk-docs/)
- [A2A Protocol Specification](https://github.com/a2aproject/A2A)
- [MSAL.js Documentation](https://learn.microsoft.com/en-us/entra/msal/overview)
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview)
