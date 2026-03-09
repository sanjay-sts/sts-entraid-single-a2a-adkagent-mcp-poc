# Identity-Aware AI Agent System

A secure, multi-tier AI agent system where user identity propagates from frontend authentication through the agent layer down to resource APIs. The architecture enforces access control at three independent levels, providing defense in depth.

## Table of Contents

- [System Design](#system-design)
- [Current State](#current-state)
- [Architecture Diagrams](#architecture-diagrams)
- [Authentication Flow](#authentication-flow)
- [Multi-Turn Conversation Flow](#multi-turn-conversation-flow)
- [Context and Auth Passing](#context-and-auth-passing)
- [RBAC (Role-Based Access Control)](#rbac-role-based-access-control)
- [API Reference](#api-reference)
- [Setup Guide](#setup-guide)
- [Testing](#testing)

---

## System Design

### Overview

This system implements an identity-aware AI agent using:
- **Frontend**: React with MSAL.js for Microsoft Entra ID authentication
- **Gateway**: A2A Protocol server for agent discovery and request routing
- **Agent**: Google ADK with Claude Sonnet 4 via LiteLLM
- **Tools**: FastMCP server providing identity-aware tools

### Technology Stack

| Component | Technology | Port | Purpose |
|-----------|------------|------|---------|
| Frontend | React 18 + MSAL.js 3.6 | 10003 | User authentication, token acquisition |
| Gateway | A2A Protocol (FastAPI + a2a-sdk) | 10000 | Agent discovery, agent-level ACL, streaming |
| Agent | Google ADK + LiteLLM + Claude Sonnet 4 | 10001 | LLM orchestration, tool calling |
| Tools | FastMCP (Stateless HTTP) | 10002 | Tool execution, token propagation |
| Identity | Microsoft Entra ID | - | OAuth 2.0, group claims, scopes |
| Resources | Microsoft Graph API | - | User data, files, email |

### Three-Tier Security Model

| Level | Location | Mechanism | Enforced By | Denies Access When |
|-------|----------|-----------|-------------|-------------------|
| **1. Agent** | A2A Server | Group membership, blocklist | `auth_middleware` | User blocked or not in allowed group |
| **2. Tool** | FastMCP | Role-based permissions (RBAC) | Built-in auth (JWT verification) + `auth=require_role()` decorators + `UserContextMiddleware` | Token invalid, role not assumed, or role lacks tool permission |
| **3. Resource** | Graph API | OAuth scopes | Microsoft Graph | Token missing required scope |

---

## Current State

### Working Features

| Feature | Status | Notes |
|---------|--------|-------|
| Entra ID Authentication | ✅ Working | MSAL.js popup/silent token acquisition |
| Custom API Scope | ✅ Working | `api://{client-id}/access_as_user` |
| Token Validation (v1.0 & v2.0) | ✅ Working | Supports both Entra ID token versions |
| A2A Protocol | ✅ Working | Agent card discovery, message/send |
| ADK + Claude Sonnet 4 | ✅ Working | Via LiteLLM, no looping issues |
| MCP Tools (Stateless) | ✅ Working | Token passed via header_provider |
| Multi-turn Conversations | ✅ Working | Session state preserved in ADK |
| RBAC Enforcement | ✅ Working | Three-tier access control |

### Known Limitations

| Limitation | Impact | Location |
|-----------|--------|----------|
| Graph API returns 401 | Using token claims fallback | MCP tools |
| Session in-memory only | Lost on restart | ADK Agent |
| No streaming to frontend | Full response only | Frontend |

---

## Architecture Diagrams

### System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                    USER BROWSER                                       │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                         React Frontend (Port 10003)                              │ │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────────────┐   │ │
│  │  │   MSAL.js    │───▶│ Auth State   │───▶│  Chat Interface                  │   │ │
│  │  │  (Login)     │    │ (Token)      │    │  - Send messages                 │   │ │
│  │  └──────────────┘    └──────────────┘    │  - Display responses             │   │ │
│  │         │                   │            │  - Scope selection               │   │ │
│  │         ▼                   ▼            └──────────────────────────────────┘   │ │
│  │  ┌─────────────────────────────────────────────────────────────────────────┐    │ │
│  │  │              Microsoft Entra ID (OAuth 2.0 + OIDC)                      │    │ │
│  │  │  - Token issuance (custom API scope + Graph scopes)                     │    │ │
│  │  │  - Group claims in token                                                │    │ │
│  │  └─────────────────────────────────────────────────────────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          │ HTTP POST + Bearer Token
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              A2A Gateway (Port 10000)                                │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                         auth_middleware                                       │   │
│  │  1. Validate JWT signature (JWKS from Entra ID)                              │   │
│  │  2. Check blocklist (BLOCKED_USERS)                                          │   │
│  │  3. Verify group membership (ALLOWED_GROUPS)                                 │   │
│  │  4. Set ContextVar: current_user_claims, current_access_token                │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                          │                                           │
│                                          ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                    IdentityAwareAgentExecutor                                 │   │
│  │  1. Extract user claims from ContextVar                                       │   │
│  │  2. Ensure ADK session exists for user                                        │   │
│  │  3. Forward request to ADK Agent                                              │   │
│  │  4. Emit TaskStatusUpdateEvent with response                                  │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          │ HTTP POST + Bearer Token
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              ADK Agent (Port 10001)                                  │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                         Session Management                                    │   │
│  │  - InMemorySessionService                                                     │   │
│  │  - Session state: user:access_token, user:email, user:role, user:groups      │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                          │                                           │
│                                          ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                    LlmAgent (Claude Sonnet 4 via LiteLLM)                     │   │
│  │  - Processes user message                                                     │   │
│  │  - Decides which tools to call                                               │   │
│  │  - Formats final response                                                     │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                          │                                           │
│                                          ▼                                           │
│  ┌────────────────────────┐    ┌────────────────────────────────────────────────┐   │
│  │    Local Tools         │    │              McpToolset                         │   │
│  │  - get_identity_info   │    │  - header_provider injects Bearer token        │   │
│  │  - check_my_permissions│    │  - Calls FastMCP server                        │   │
│  └────────────────────────┘    └────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          │ HTTP POST + Bearer Token (from header_provider)
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              FastMCP Server (Port 10002)                             │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                      FastMCP Built-in Auth (MultiAuth)                        │   │
│  │  1. AzureJWTVerifier (v2.0) — auto-configured from Azure app registration  │   │
│  │  2. JWTVerifier (v1.0 fallback) — for sts.windows.net issuer tokens         │   │
│  │  3. Validates JWT signature, issuer, audience, expiry via JWKS              │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                          │                                           │
│                                          ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                      UserContextMiddleware                                    │   │
│  │  1. Detect IdP provider from iss claim (entra/cognito/auth0)                │   │
│  │  2. Extract email, groups from validated token claims                        │   │
│  │  3. Resolve available roles via TomlPolicyEvaluator (permissions.toml)      │   │
│  │  4. Validate X-Assume-Role header against available roles                   │   │
│  │  5. Set ContextVars: current_user_token, current_user_role, current_user_email│  │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                          │                                           │
│                                          ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                      Per-Tool Auth Decorators                                │   │
│  │  1. auth=require_role() checks user role via ContextVar                      │   │
│  │  2. Raises ToolError with [TOOL_DENIAL] prefix on denial                    │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
│                                          │                                           │
│                                          ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                              MCP Tools                                        │   │
│  │  - get_user_profile      (all roles)                                         │   │
│  │  - list_files            (admin, developer)                                  │   │
│  │  - send_email            (admin only)                                        │   │
│  │  - delete_resource       (admin only)                                        │   │
│  │  - get_current_time      (admin only)                                        │   │
│  │  - convert_timezone      (admin only)                                        │   │
│  │  - get_time_difference   (admin only)                                        │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
                                          │ (Optional) Graph API calls with user token
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              Microsoft Graph API                                     │
│  - /me (User.Read scope)                                                            │
│  - /me/drive/root/children (Files.Read scope)                                       │
│  - /me/sendMail (Mail.Send scope)                                                   │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### Request Flow Diagram

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  User    │     │ Frontend │     │   A2A    │     │   ADK    │     │   MCP    │
│ Browser  │     │  React   │     │ Gateway  │     │  Agent   │     │  Server  │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │                │
     │  1. Login      │                │                │                │
     │───────────────▶│                │                │                │
     │                │ 2. MSAL        │                │                │
     │                │ acquireToken   │                │                │
     │                │───────────────▶│ Entra ID      │                │
     │                │◀───────────────│ (Token)       │                │
     │                │                │                │                │
     │  3. Send msg   │                │                │                │
     │───────────────▶│                │                │                │
     │                │ 4. POST /      │                │                │
     │                │ + Bearer token │                │                │
     │                │───────────────▶│                │                │
     │                │                │ 5. Validate    │                │
     │                │                │    JWT         │                │
     │                │                │ 6. Check       │                │
     │                │                │    groups      │                │
     │                │                │                │                │
     │                │                │ 7. POST /chat  │                │
     │                │                │ + Bearer token │                │
     │                │                │───────────────▶│                │
     │                │                │                │ 8. Store token │
     │                │                │                │    in session  │
     │                │                │                │                │
     │                │                │                │ 9. LLM decides │
     │                │                │                │    tool call   │
     │                │                │                │                │
     │                │                │                │ 10. MCP call   │
     │                │                │                │ + Bearer token │
     │                │                │                │───────────────▶│
     │                │                │                │                │ 11. Validate
     │                │                │                │                │     JWT
     │                │                │                │                │ 12. Check
     │                │                │                │                │     role
     │                │                │                │                │ 13. Execute
     │                │                │                │                │     tool
     │                │                │                │◀───────────────│
     │                │                │                │ 14. Tool result│
     │                │                │                │                │
     │                │                │                │ 15. LLM formats│
     │                │                │                │     response   │
     │                │                │◀───────────────│                │
     │                │                │ 16. Response   │                │
     │                │◀───────────────│                │                │
     │                │ 17. A2A result │                │                │
     │◀───────────────│                │                │                │
     │ 18. Display    │                │                │                │
     │                │                │                │                │
```

---

## Authentication Flow

### Initial Authentication

```
1. User clicks "Sign In with Microsoft"
2. MSAL.js opens popup to Entra ID login
3. User authenticates with credentials/MFA
4. Entra ID returns tokens:
   - ID Token (user identity)
   - Access Token (with custom API scope + Graph scopes)
5. MSAL.js caches tokens in browser storage
6. Frontend shows authenticated state
```

### Token Acquisition for Requests

```javascript
// Frontend: authConfig.js
const API_SCOPE = `api://${clientId}/access_as_user`;

export const graphScopes = {
  basic: [API_SCOPE, 'User.Read'],
  files: [API_SCOPE, 'User.Read', 'Files.Read'],
  email: [API_SCOPE, 'User.Read', 'Mail.Send'],
  full: [API_SCOPE, 'User.Read', 'Files.Read', 'Mail.Send'],
  destructive: [API_SCOPE, 'User.Read', 'Files.Read', 'Files.ReadWrite.All', 'Mail.Send'],
};

// Token acquisition (cached, no re-prompt unless expired)
const token = await instance.acquireTokenSilent({ scopes, account });
```

### Token Validation

**A2A Server** — manual JWT validation:

```python
# a2a_server/server.py — manual JWKS fetching, supports v1.0 and v2.0 tokens
JWKS_URIS = [
    f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys",
    f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys",
    "https://login.microsoftonline.com/common/discovery/keys",
]
VALID_ISSUERS = [
    f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
    f"https://sts.windows.net/{TENANT_ID}/",
]
```

**MCP Server** — FastMCP 3.1 built-in auth with `MultiAuth`:

```python
# mcp_server/server.py — uses FastMCP's built-in auth providers
# v2.0 verifier (primary)
AzureJWTVerifier(client_id=CLIENT_ID, tenant_id=TENANT_ID, required_scopes=["access_as_user"])

# v1.0 verifier (fallback for sts.windows.net issuer tokens)
JWTVerifier(
    jwks_uri=f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys",
    issuer=f"https://sts.windows.net/{TENANT_ID}/",
    audience=[CLIENT_ID, f"api://{CLIENT_ID}"],
    required_scopes=["access_as_user"],
)
# Composed via MultiAuth — tries v2.0 first, falls back to v1.0
```

---

## Multi-Turn Conversation Flow

### Token Revalidation Per Request

| Layer | Action | Frequency | Cached? |
|-------|--------|-----------|---------|
| **Frontend** | `acquireTokenSilent()` | Every request | Yes (MSAL cache) |
| **A2A Server** | JWT signature validation | Every request | JWKS cached |
| **A2A Server** | Group membership check | Every request | No |
| **ADK Agent** | Store token in session | Every request | Session state |
| **MCP Server** | JWT signature validation | Every tool call | JWKS cached |
| **MCP Server** | Role permission check | Every tool call | No |

### Session State in ADK

```python
# Session state stored with user: prefix for persistence
session.state = {
    "user:access_token": "<jwt_token>",      # Updated each request
    "user:email": "user@domain.com",
    "user:name": "User Name",
    "user:groups": ["group-id-1", "group-id-2"],
    "user:role": "admin"                      # Derived from groups
}
```

### Multi-Turn Example

```
Turn 1: "What's my email?"
  ├─ Token validated at A2A (cached JWKS)
  ├─ Session created in ADK
  ├─ Local tool: get_identity_info
  └─ Response: "Your email is user@domain.com"

Turn 2: "What time is it in Tokyo?"
  ├─ Token validated at A2A (same JWKS)
  ├─ Session retrieved (same session_id)
  ├─ Token updated in session state
  ├─ MCP tool: get_current_time
  │   ├─ Token validated at MCP (cached JWKS)
  │   └─ Role check: admin required ✓
  └─ Response: "The time in Tokyo is..."

Turn 3: "List my files"
  ├─ Token validated at A2A
  ├─ Session retrieved
  ├─ MCP tool: list_files
  │   ├─ Token validated at MCP
  │   └─ Role check: admin/developer required ✓
  └─ Response: "Your files are..."
```

---

## Context and Auth Passing

### A2A Server → ADK Agent

```python
# A2A Server uses ContextVar to pass auth data
current_user_claims: ContextVar[dict] = ContextVar("current_user_claims", default={})
current_access_token: ContextVar[str] = ContextVar("current_access_token", default="")

# Set in auth_middleware
current_user_claims.set(claims)
current_access_token.set(token)

# Read in IdentityAwareAgentExecutor
user_claims = current_user_claims.get()
access_token = current_access_token.get()

# Forward to ADK Agent via HTTP
POST /chat
{
    "message": "user message",
    "user_id": "sub-claim-value",
    "session_id": "session-uuid"
}
Headers: Authorization: Bearer <token>
```

### ADK Agent → MCP Server

```python
# McpToolset uses header_provider for dynamic auth
def mcp_header_provider(readonly_context: ReadonlyContext) -> Dict[str, str]:
    if readonly_context and readonly_context.state:
        access_token = readonly_context.state.get("user:access_token", "")
        if access_token:
            return {"Authorization": f"Bearer {access_token}"}
    return {}

# McpToolset configuration
self.mcp_toolset = McpToolset(
    connection_params=StreamableHTTPConnectionParams(url=MCP_SERVER_URL),
    header_provider=mcp_header_provider,  # Injects token per-request
)
```

### MCP Server Context Variables

```python
# MCP Server stores validated claims in ContextVar (stateless mode — no ctx.get_state())
current_user_token: ContextVar[str] = ContextVar("current_user_token", default="")
current_user_role: ContextVar[str] = ContextVar("current_user_role", default="none")
current_user_email: ContextVar[str] = ContextVar("current_user_email", default="")

# Set by UserContextMiddleware, read by tools and auth= callables
@mcp.tool(auth=require_role("admin"))
async def get_current_time(timezone: str = "UTC") -> dict:
    user_role = current_user_role.get()
    user_email = current_user_email.get()
    # ... tool logic
```

---

## RBAC (Role-Based Access Control)

### Role Hierarchy

```
admin      → Full access to all tools
developer  → Access to profile and file tools
viewer     → Access to profile tools only
none       → No tool access (agent-level denied)
```

### Group-to-Role Mapping (permissions.toml)

Roles are defined in `permissions.toml` (agent-owned, gitignored). Copy from `permissions.example.toml`:

```toml
# permissions.toml — Agent-owned role assignments
# Group-to-role mapping is the PRIMARY mechanism.
# User-level overrides are optional for exceptions.

[group_rules.entra]
"<admin-group-guid>" = "admin"
"<developer-group-guid>" = "developer"
"<viewer-group-guid>" = "viewer"

[group_rules.cognito]
# "platform-admins" = "admin"  # Future: Cognito groups

[group_rules.auth0]
# "admin" = "admin"  # Future: Auth0 roles

[users]
# Optional direct user overrides (case-insensitive email lookup)
# "user@company.com" = { role = "admin" }

[defaults]
unknown_users = "none"
```

The `TomlPolicyEvaluator` (`mcp_server/policy.py`) resolves available roles from group claims and user overrides, with hot-reload on file change. Role priority: admin > developer > viewer.

**Role selection**: Users must set `X-Assume-Role` header for MCP tool calls. `UserContextMiddleware` validates the assumed role against available roles. For tool listing, the highest-priority role is used automatically.

> **Note**: The A2A server still uses `GROUP_TO_ROLE` from env vars (`ADMIN_GROUP_ID`, etc.) for agent-level access control. The MCP server uses `permissions.toml` for tool-level RBAC.

### Tool Permission Matrix

| Tool | Allowed Roles | Description |
|------|---------------|-------------|
| `get_user_profile` | admin, developer, viewer | Fetch Microsoft Graph profile (or token claims fallback) |
| `list_files` | admin, developer | List OneDrive files |
| `send_email` | admin | Send email via Graph |
| `delete_resource` | admin | Delete resources |
| `get_current_time` | admin | Get time in timezone |
| `convert_timezone` | admin | Convert between timezones |
| `get_time_difference` | admin | Compare timezone offsets |

### Permission Enforcement Code

```python
# MCP Server: Per-tool auth= decorators (require_role only — IdP scope checking removed)
@mcp.tool(auth=require_role("admin", "developer", "viewer"))
async def get_user_profile() -> dict: ...

@mcp.tool(auth=require_role("admin", "developer"))
async def list_files(folder_path: str = "/") -> dict: ...

@mcp.tool(auth=require_role("admin"))
async def send_email(to: str, subject: str, body: str) -> dict: ...

# Auth helper
def require_role(*allowed_roles):
    # Reads current_user_role ContextVar (set by UserContextMiddleware)
    # Raises: "[TOOL_DENIAL] Access denied: Role '...' cannot use this tool. Required roles: [...]"
    ...
```

### Access Denied Examples

```
No X-Assume-Role header:
  → [ROLE_SELECTION] Role selection required. Set X-Assume-Role header to one of: ['admin']

Viewer tries to list files:
  → [TOOL_DENIAL] Access denied: Role 'viewer' cannot use this tool. Required roles: ['admin', 'developer']

Developer tries to send email:
  → [TOOL_DENIAL] Access denied: Role 'developer' cannot use this tool. Required roles: ['admin']

User tries to assume a role they don't have:
  → [TOOL_DENIAL] Cannot assume role 'admin'. Available roles: ['developer']

No-group user (not in permissions.toml):
  → [TOOL_DENIAL] No roles available for user@domain.com. Contact admin to assign group membership.

User without groups at A2A gateway:
  → 403 {"error": "access_denied", "denial_level": "agent", "denial_reason": "no_group_membership"}

Blocked user:
  → 403 {"error": "access_denied", "denial_level": "agent", "denial_reason": "blocked_user"}
```

---

## API Reference

### A2A Server (Port 10000)

#### Agent Card Discovery

```http
GET /.well-known/agent-card.json
```

Response:
```json
{
  "name": "Identity-Aware AI Agent",
  "description": "An AI agent with Entra ID authentication...",
  "url": "http://localhost:10000/",
  "version": "1.0.0",
  "capabilities": {"streaming": true},
  "skills": [...]
}
```

#### Send Message (A2A Protocol)

```http
POST /
Authorization: Bearer <token>
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "method": "message/send",
  "params": {
    "message": {
      "messageId": "msg-123",
      "role": "user",
      "parts": [{"type": "text", "text": "What time is it?"}]
    }
  },
  "id": "req-123"
}
```

Response:
```json
{
  "id": "req-123",
  "jsonrpc": "2.0",
  "result": {
    "id": "task-uuid",
    "kind": "task",
    "status": {
      "state": "completed",
      "message": {
        "kind": "message",
        "role": "agent",
        "parts": [{"kind": "text", "text": "The current time is..."}]
      }
    }
  }
}
```

#### Health Check

```http
GET /health
```

#### Security Context

```http
GET /me
Authorization: Bearer <token>
```

Response:
```json
{
  "user": { "email": "user@domain.com", "name": "User Name", "oid": "..." },
  "security": {
    "role": "developer",
    "groups": ["group-id-1"],
    "group_names": { "group-id-1": "developer" },
    "token_scopes": ["User.Read", "Files.Read"],
    "token_expiry": 1741363200,
    "issuer": "https://login.microsoftonline.com/{tenant}/v2.0"
  },
  "permissions": {
    "get_user_profile": true, "list_files": true, "send_email": false,
    "delete_resource": false, "get_current_time": false,
    "convert_timezone": false, "get_time_difference": false
  },
  "tool_scopes": {
    "get_user_profile": ["User.Read"], "list_files": ["Files.Read"],
    "send_email": ["Mail.Send"], "delete_resource": ["Files.ReadWrite.All"],
    "get_current_time": [], "convert_timezone": [], "get_time_difference": []
  }
}
```

### ADK Agent (Port 10001)

#### Create Session

```http
POST /session
Authorization: Bearer <token>
Content-Type: application/json

{
  "user_id": "user-sub-claim",
  "user_info": {
    "email": "user@domain.com",
    "name": "User Name",
    "groups": ["group-id-1"]
  }
}
```

Response:
```json
{"session_id": "session-uuid"}
```

#### Chat

```http
POST /chat
Authorization: Bearer <token>
Content-Type: application/json

{
  "message": "What's my email?",
  "user_id": "user-sub-claim",
  "session_id": "session-uuid"
}
```

Response:
```json
{
  "response": "Your email is user@domain.com",
  "session_id": "session-uuid"
}
```

### MCP Server (Port 10002)

#### MCP Endpoint

```http
POST /mcp
Authorization: Bearer <token>
Content-Type: application/json

# Standard MCP protocol messages
```

#### Available Tools

| Tool | Parameters | Returns |
|------|------------|---------|
| `get_user_profile` | (none) | User profile from Graph or token claims |
| `list_files` | `folder_path?: string` | List of file names |
| `send_email` | `to, subject, body` | Send status |
| `delete_resource` | `resource_id` | Delete status |
| `get_current_time` | `timezone?: string` | Time info with epoch |
| `convert_timezone` | `time_str, from_timezone, to_timezone` | Converted time |
| `get_time_difference` | `timezone1, timezone2` | Offset difference |

---

## Setup Guide

### Prerequisites

- Python 3.10+
- Node.js 18+
- Microsoft Entra ID tenant
- Anthropic API key (for Claude)

### 1. Microsoft Entra ID Configuration

1. Create app registration in [Entra admin center](https://entra.microsoft.com)
2. Configure platform: Single-page application
   - Redirect URIs: `http://localhost:10003`, `http://localhost:10003/redirect`
3. Expose an API:
   - Add scope: `access_as_user`
   - Application ID URI: `api://{client-id}`
4. API Permissions:
   - `openid`, `profile`, `User.Read`, `Files.Read`, `Mail.Send`
5. Token configuration:
   - Add groups claim (Security groups)
6. Create security groups:
   - Admin Group, Developer Group, Viewer Group

### 2. Environment Setup

```bash
# Backend (.env)
cp .env.example .env

# Required variables:
ENTRA_CLIENT_ID=<app-registration-client-id>
ENTRA_TENANT_ID=<directory-tenant-id>
ADMIN_GROUP_ID=<admin-security-group-object-id>
DEVELOPER_GROUP_ID=<developer-security-group-object-id>
VIEWER_GROUP_ID=<viewer-security-group-object-id>
ANTHROPIC_API_KEY=<your-anthropic-api-key>

# Frontend (frontend/.env)
cd frontend && cp .env.example .env

REACT_APP_ENTRA_CLIENT_ID=<app-registration-client-id>
REACT_APP_ENTRA_TENANT_ID=<directory-tenant-id>

# MCP Permissions (group-to-role mapping)
cp permissions.example.toml permissions.toml
# Edit permissions.toml with your Entra ID security group GUIDs
```

### 3. Install Dependencies

```bash
# Backend
pip install -r requirements.txt
# or with uv:
uv pip install -r requirements.txt

# Frontend
cd frontend && npm install
```

### 4. Run Services

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

### 5. Access Application

- Frontend: http://localhost:10003
- A2A Gateway: http://localhost:10000
- Agent Card: http://localhost:10000/.well-known/agent-card.json

---

## Security Testing Dashboard

The frontend includes a comprehensive Security Testing Dashboard for testing and visualizing the three-tier access control system.

### Dashboard Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Security Context Panel | Left sidebar | Shows role, groups, scopes, token expiry countdown |
| Token Inspector | Left sidebar (collapsible) | Decodes JWT header/payload for display |
| RBAC Test Matrix | Left sidebar | One-click test grid with pass/fail tracking |
| Conversation Tabs | Main area | Multi-tab chat with per-tab scope selection (max 4) |
| Audit Log | Main area (bottom) | Request history with denial classification |
| Denial Indicator | Inline badges | Color-coded denial tier: AGENT (red), TOOL (orange), RESOURCE (purple) |
| Account Switcher | Header | Multi-account support for testing different roles |

### Denial Classification

Denials are automatically classified into four tiers:

| Tier | Detected By | Example |
|------|------------|---------|
| AGENT | HTTP 401/403 + `denial_level` in response body | User not in any group |
| TOOL | `[TOOL_DENIAL]` tag in response text | Viewer trying `list_files` |
| RESOURCE | Graph API 403 in response text | Insufficient Graph permissions |

### Frontend File Structure

```
frontend/src/
  App.js                      # Dashboard layout shell
  App.css                     # Dark theme styles
  authConfig.js               # MSAL config + scope presets (basic, files, email, full, destructive)
  index.js                    # MSAL provider setup
  components/
    AuthStatus.js             # Multi-account switcher dropdown
    LoginPrompt.js            # Sign-in prompt
    SecurityContextPanel.js   # Role, groups, scopes, expiry countdown
    TokenInspector.js         # JWT decoder display
    ConversationTabs.js       # Multi-tab chat with per-tab scope
    ChatInterface.js          # Chat with denial tagging and latency tracking
    RBACTestMatrix.js         # One-click test grid
    AuditLog.js               # Request history table
    DenialIndicator.js        # Color-coded denial badge
  utils/
    tokenDecoder.js           # JWT base64url decode helper
    denialClassifier.js       # HTTP status + response text → denial tier
    testScenarios.js          # Predefined test prompts with expected outcomes
```

---

## Testing

### Run Tests

```bash
# With services running
uv run pytest tests/test_access_control.py -v
```

### Manual Testing

1. Sign in with a user in the Admin group
2. Test: "What's my email?" → Should work
3. Test: "What time is it in Tokyo?" → Should work (admin only)
4. Test: "List my files" → Should work

5. Sign in with a user in the Viewer group
6. Test: "What's my email?" → Should work
7. Test: "What time is it in Tokyo?" → Should fail (admin only)

### Check Logs

```bash
# All logs in logs/ directory
tail -f logs/a2a_server.log
tail -f logs/adk_agent.log
tail -f logs/mcp_server.log
```

---

## Documentation Links

- [FastMCP Documentation](https://gofastmcp.com)
- [Google ADK Documentation](https://google.github.io/adk-docs/)
- [A2A Protocol Specification](https://github.com/a2aproject/A2A)
- [MSAL.js Documentation](https://learn.microsoft.com/en-us/entra/msal/overview)
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview)

---

## License

MIT
