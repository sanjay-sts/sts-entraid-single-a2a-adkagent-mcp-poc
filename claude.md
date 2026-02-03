# Identity-Aware AI Agent System

## Project Overview

This project implements a **secure, multi-tier AI agent system** where user identity propagates from frontend authentication through the agent layer down to resource APIs. The architecture enforces access control at three independent levels, providing defense in depth.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  React Frontend │───▶│   A2A Server    │───▶│   Google ADK    │───▶│   FastMCP       │
│  (MSAL.js)      │    │   (Gateway)     │    │   Agent         │    │   Tools         │
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

| Component | Technology | Purpose |
|-----------|------------|---------|
| Frontend | React + MSAL.js | User authentication, token acquisition |
| Gateway | A2A Protocol (FastAPI) | Agent discovery, agent-level ACL |
| Agent | Google ADK | LLM orchestration, tool calling |
| Tools | FastMCP | Tool execution, token propagation |
| Identity | Microsoft Entra ID | OAuth 2.0, group claims, scopes |
| Resources | Microsoft Graph API | User data, files, email |

## Dependencies

### Python (Backend)
```
fastmcp[auth]     # MCP server with authentication support
google-adk        # Google Agent Development Kit
a2a-sdk           # Agent-to-Agent Protocol SDK
pyjwt             # JWT token validation
httpx             # Async HTTP client
uvicorn           # ASGI server
python-dotenv     # Environment variables
```

### JavaScript (Frontend)
```
@azure/msal-browser   # MSAL.js core
@azure/msal-react     # React bindings for MSAL
```

## Security Model

### Three-Tier Access Control

| Level | Location | Mechanism | Denies Access When |
|-------|----------|-----------|-------------------|
| **Agent** | A2A Server | Group membership, blocklist | User blocked or not in allowed group |
| **Tool** | FastMCP | Role-based permissions | User role lacks tool permission |
| **Resource** | Graph API | OAuth scopes | Token missing required scope |

### Role Hierarchy

```
admin      → All tools: get_user_profile, list_files, send_email, delete_resource
developer  → Subset: get_user_profile, list_files
viewer     → Limited: get_user_profile only
```

### Group-to-Role Mapping

Roles are derived from Entra ID security group membership:
- `ADMIN_GROUP_ID` → `admin`
- `DEVELOPER_GROUP_ID` → `developer`
- `VIEWER_GROUP_ID` → `viewer`

## Project Structure

```
/
├── a2a_server/
│   └── server.py          # A2A gateway with auth middleware
├── adk_agent/
│   └── agent.py           # Google ADK agent with MCP integration
├── mcp_server/
│   └── server.py          # FastMCP tools with token validation
├── frontend/
│   ├── src/
│   │   ├── App.js         # Main React component with chat UI
│   │   ├── authConfig.js  # MSAL configuration
│   │   └── index.js       # MSAL provider setup
│   └── .env               # Frontend environment variables
├── tests/
│   └── test_access_control.py  # Access control verification tests
├── .env                   # Backend environment variables
└── claude.md              # This file
```

## Key Code Patterns

### FastMCP: Token Access in Tools

```python
from fastmcp.server.dependencies import get_http_headers, CurrentContext
from fastmcp.server.context import Context

# Pattern 1: Direct header access
@mcp.tool
def my_tool():
    headers = get_http_headers()
    token = headers.get("authorization", "").replace("Bearer ", "")

# Pattern 2: Context injection with state (preferred)
@mcp.tool
async def my_tool(ctx: Context = CurrentContext()):
    user_id = await ctx.get_state("user_id")
    access_token = await ctx.get_state("access_token")
```

### FastMCP: Middleware for Validation

```python
from fastmcp.server.middleware import Middleware, MiddlewareContext

class TokenValidationMiddleware(Middleware):
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        # Validate token, set context state
        ctx = context.fastmcp_context
        await ctx.set_state("user_id", validated_claims["sub"])
        return await call_next(context)

mcp.add_middleware(TokenValidationMiddleware())
```

### Google ADK: Session State for User Context

```python
# Store user context with user: prefix for persistence
session.state["user:access_token"] = access_token
session.state["user:email"] = user_info.get("email", "")
session.state["user:role"] = determined_role

# Access in tools via ToolContext
def my_tool(tool_context: ToolContext) -> dict:
    email = tool_context.state.get("user:email")
```

### A2A: Agent Card with OAuth Security

```python
from a2a.types import AgentCard, OAuth2SecurityScheme, OAuthFlows

agent_card = AgentCard(
    securitySchemes={
        "entra_oauth": OAuth2SecurityScheme(
            flows=OAuthFlows(
                authorizationCode=AuthorizationCodeOAuthFlow(
                    authorizationUrl="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
                    tokenUrl="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                    scopes={"User.Read": "Read user profile", ...}
                )
            )
        )
    },
    security=[{"entra_oauth": ["openid", "profile", "User.Read"]}]
)
```

### React/MSAL: Token Acquisition

```javascript
// Silent acquisition with popup fallback
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

```bash
# Microsoft Entra ID
ENTRA_CLIENT_ID=<app-registration-client-id>
ENTRA_TENANT_ID=<directory-tenant-id>
ENTRA_AUTHORITY=https://login.microsoftonline.com/<tenant-id>

# Access Control Group IDs
ADMIN_GROUP_ID=<admin-security-group-id>
DEVELOPER_GROUP_ID=<developer-security-group-id>
VIEWER_GROUP_ID=<viewer-security-group-id>

# Server Ports
A2A_SERVER_PORT=8000
ADK_SERVER_PORT=8001
MCP_SERVER_PORT=8002
FRONTEND_PORT=3000
```

## Development Workflow

### Starting Services

```bash
# Terminal 1: MCP Server
python mcp_server/server.py

# Terminal 2: ADK Agent
python adk_agent/agent.py

# Terminal 3: A2A Gateway
python a2a_server/server.py

# Terminal 4: Frontend
cd frontend && npm start
```

### Testing Access Control

```bash
pip install pytest pytest-asyncio httpx
pytest tests/test_access_control.py -v
```

## Verification Checklist

### Agent-Level
- [ ] Unauthenticated requests return 401
- [ ] Blocked users receive 403
- [ ] Users without allowed group receive 403
- [ ] Valid users can send messages

### Tool-Level
- [ ] Viewer cannot use `send_email` or `delete_resource`
- [ ] Developer cannot use `send_email`
- [ ] Admin can use all tools
- [ ] Denials return clear error messages

### Resource-Level
- [ ] Missing `Files.Read` scope → 403 on file operations
- [ ] Missing `Mail.Send` scope → 403 on email operations
- [ ] Error messages indicate missing scopes

## Important Conventions

1. **Token Propagation**: Always pass user tokens via `Authorization: Bearer` headers, never in JSON payloads
2. **State Prefix**: Use `user:` prefix for ADK session state to ensure persistence
3. **Error Handling**: Return structured errors with `error` and `message` fields
4. **Scope Checking**: Check both role AND scopes before allowing tool execution
5. **JWKS Caching**: Cache JWKS responses to avoid repeated fetches

## External Documentation

- [FastMCP Documentation](https://gofastmcp.com)
- [Google ADK Documentation](https://google.github.io/adk-docs/)
- [A2A Protocol Specification](https://github.com/a2aproject/A2A)
- [MSAL.js Documentation](https://learn.microsoft.com/en-us/entra/msal/overview)
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview)
