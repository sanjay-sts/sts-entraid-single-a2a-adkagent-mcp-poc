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
| Agent | Google ADK | 10001 | LLM orchestration, tool calling |
| Tools | FastMCP | 10002 | Tool execution, token propagation |
| Identity | Microsoft Entra ID | - | OAuth 2.0, group claims, scopes |
| Resources | Microsoft Graph API | - | User data, files, email |

## Project Structure

```
/
├── a2a_server/
│   └── server.py              # A2A gateway (409 lines) - auth middleware, task executor
├── adk_agent/
│   └── agent.py               # Google ADK agent (289 lines) - session mgmt, streaming
├── mcp_server/
│   └── server.py              # FastMCP tools (256 lines) - 2 middleware, 4 tools
├── frontend/
│   ├── src/
│   │   ├── App.js             # React chat UI (267 lines) - token acquisition
│   │   ├── authConfig.js      # MSAL configuration (36 lines)
│   │   └── index.js           # MSAL provider setup (31 lines)
│   ├── package.json           # React dependencies
│   └── .env.example           # Frontend env template
├── tests/
│   ├── test_access_control.py # Access control tests (340 lines)
│   └── conftest.py            # Pytest fixtures (51 lines)
├── scratchpad/
│   └── singleagent/
│       └── single_agent_adk_mcp.md  # Implementation guide (1630 lines)
├── .env.example               # Backend env template
├── requirements.txt           # Python dependencies
├── README.md                  # Setup guide
├── TESTING.md                 # Comprehensive testing guide (482 lines)
└── CLAUDE.md                  # This file
```

## Current Status & Known Issues

### Streaming Support

| Component | Status | Notes |
|-----------|--------|-------|
| A2A Server | ✅ Enabled | `AgentCapabilities(streaming=True)` in agent card |
| ADK Agent | ✅ Has endpoint | `/chat/stream` for SSE streaming |
| Frontend | ⚠️ Not using stream | Uses buffered `/chat` endpoint |

### Local Testing with A2A Inspector

The A2A Inspector requires authentication bypass for local testing:

**Issue**: POST requests to `/` return `401 Unauthorized` because:
- A2A Inspector doesn't send Bearer tokens
- Auth middleware requires token for all endpoints except agent card

**Workaround**: Add to auth middleware allowed paths in `a2a_server/server.py:315`:
```python
if request.url.path in [
    "/.well-known/agent.json",
    "/.well-known/agent-card.json",  # Add new path
    "/health",
    "/docs",
    "/openapi.json",
]:
    return await call_next(request)
```

**For full local testing bypass** (development only):
```python
# Add at start of auth_middleware
if os.getenv("DISABLE_AUTH") == "true":
    return await call_next(request)
```

### Deprecation Warning

A2A Inspector uses old endpoint `/.well-known/agent.json`. The a2a-sdk now prefers `/.well-known/agent-card.json`. Both currently work.

## Security Model

### Three-Tier Access Control

| Level | Location | Mechanism | Code Location | Denies Access When |
|-------|----------|-----------|---------------|-------------------|
| **Agent** | A2A Server | Group membership, blocklist | `a2a_server/server.py:310-380` | User blocked or not in allowed group |
| **Tool** | FastMCP | Role-based permissions | `mcp_server/server.py:123-154` | User role lacks tool permission |
| **Resource** | Graph API | OAuth scopes | External | Token missing required scope |

### Role Hierarchy & Permissions

```
admin      → All tools: get_user_profile, list_files, send_email, delete_resource
developer  → Subset: get_user_profile, list_files
viewer     → Limited: get_user_profile only
```

**Tool Permission Matrix** (defined in `mcp_server/server.py:28-33`):
```python
TOOL_PERMISSIONS = {
    "get_user_profile": {"required_scopes": ["User.Read"], "allowed_roles": ["admin", "developer", "viewer"]},
    "list_files": {"required_scopes": ["Files.Read"], "allowed_roles": ["admin", "developer"]},
    "send_email": {"required_scopes": ["Mail.Send"], "allowed_roles": ["admin"]},
    "delete_resource": {"required_scopes": ["Files.ReadWrite.All"], "allowed_roles": ["admin"]},
}
```

### Group-to-Role Mapping

Roles derived from Entra ID security group membership (highest privilege wins):
- `ADMIN_GROUP_ID` → `admin`
- `DEVELOPER_GROUP_ID` → `developer`
- `VIEWER_GROUP_ID` → `viewer`

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

## Key Code Patterns

### FastMCP: Token Access in Tools

```python
# mcp_server/server.py:164-166
from fastmcp.server.dependencies import CurrentContext
from fastmcp.server.context import Context

@mcp.tool
async def get_user_profile(ctx: Context = CurrentContext()) -> dict:
    access_token = await ctx.get_state("access_token")
    user_id = await ctx.get_state("user_id")
```

### FastMCP: Middleware Chain

```python
# mcp_server/server.py:159-160
mcp.add_middleware(TokenValidationMiddleware())   # Validates JWT, extracts claims
mcp.add_middleware(ToolAuthorizationMiddleware()) # Checks role + scopes
```

### Google ADK: Session State

```python
# adk_agent/agent.py:75-79
# Use "user:" prefix for persistence across interactions
session.state["user:access_token"] = access_token
session.state["user:email"] = user_info.get("email", "")
session.state["user:role"] = determined_role
```

### A2A: Agent Card Configuration

```python
# a2a_server/server.py:257-288
agent_card = AgentCard(
    name="Identity-Aware AI Agent",
    url=f"http://localhost:{A2A_SERVER_PORT}/",
    defaultInputModes=["text/plain"],
    defaultOutputModes=["text/plain", "application/json"],
    capabilities=AgentCapabilities(streaming=True),
    skills=[...],
)
```

### React/MSAL: Token Acquisition

```javascript
// frontend/src/App.js:95-112
const getAccessToken = async () => {
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
};
```

## Environment Variables

### Backend (.env)

```bash
# Microsoft Entra ID
ENTRA_CLIENT_ID=<app-registration-client-id>
ENTRA_TENANT_ID=<directory-tenant-id>
ENTRA_AUTHORITY=https://login.microsoftonline.com/<tenant-id>

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

# LLM API Key (for Google ADK)
GOOGLE_API_KEY=<gemini-api-key>

# Development only
DISABLE_AUTH=false
```

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
| Session service in-memory | Lost on service restart | `adk_agent/agent.py:31` |
| JWKS cache never invalidated | Could use stale keys | `a2a_server/server.py:60-70` |
| No rate limiting | Could be abused | All servers |
| MCP delete_resource simulated | Only logs, doesn't delete | `mcp_server/server.py:240-246` |
| A2A Inspector requires auth bypass | Can't test without workaround | `a2a_server/server.py` |

## Important Conventions

1. **Token Propagation**: Always pass user tokens via `Authorization: Bearer` headers, never in JSON payloads
2. **State Prefix**: Use `user:` prefix for ADK session state to ensure persistence
3. **Error Handling**: Return structured errors with `error` and `message` fields
4. **Scope Checking**: Check both role AND scopes before allowing tool execution
5. **JWKS Caching**: Cache JWKS responses to avoid repeated fetches
6. **Port Range**: Use 10000+ ports to avoid conflicts with common services

## Verification Checklist

### Agent-Level (a2a_server/server.py)
- [ ] Unauthenticated requests return 401
- [ ] Blocked users receive 403
- [ ] Users without allowed group receive 403
- [ ] Valid users can send messages

### Tool-Level (mcp_server/server.py)
- [ ] Viewer cannot use `send_email` or `delete_resource`
- [ ] Developer cannot use `send_email`
- [ ] Admin can use all tools
- [ ] Denials return clear error messages

### Resource-Level (Microsoft Graph)
- [ ] Missing `Files.Read` scope → 403 on file operations
- [ ] Missing `Mail.Send` scope → 403 on email operations
- [ ] Error messages indicate missing scopes

## External Documentation

- [FastMCP Documentation](https://gofastmcp.com)
- [Google ADK Documentation](https://google.github.io/adk-docs/)
- [A2A Protocol Specification](https://github.com/a2aproject/A2A)
- [MSAL.js Documentation](https://learn.microsoft.com/en-us/entra/msal/overview)
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview)
