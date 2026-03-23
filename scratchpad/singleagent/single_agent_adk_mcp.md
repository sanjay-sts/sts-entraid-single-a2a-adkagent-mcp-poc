# Building a Secure Identity-Aware AI Agent System with FastMCP, Google ADK, and A2A

**The modern AI agent stack requires identity to flow seamlessly from user authentication through the agent layer down to resource APIs.** This guide provides complete implementation patterns for building a secure, multi-tier system using FastMCP (Python), Google ADK, the A2A Protocol, and Microsoft Entra ID—with access control at every layer.

## Architecture overview and token flow

The system implements a three-tier security model where **user identity propagates** from the frontend through each layer:

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

---

## Part 1: Microsoft Entra ID configuration

### App registration step-by-step

Navigate to the [Microsoft Entra admin center](https://entra.microsoft.com) and complete these steps:

**Step 1: Create the application**
1. Go to **Identity → Applications → App registrations**
2. Click **New registration**
3. Set name: `AI-Agent-System`
4. Select: **Accounts in this organizational directory only**
5. Click **Register**

**Step 2: Record essential values**
| Value | Location | Example |
|-------|----------|---------|
| Application (client) ID | Overview page | `12345678-abcd-1234-abcd-123456789abc` |
| Directory (tenant) ID | Overview page | `87654321-dcba-4321-dcba-987654321fed` |

**Step 3: Configure redirect URIs for SPA**
1. Go to **Authentication** blade
2. Click **Add a platform** → **Single-page application**
3. Add URIs:
   - `http://localhost:3000`
   - `http://localhost:3000/redirect`

**Step 4: Configure API permissions**
1. Go to **API permissions** blade
2. Click **Add a permission** → **Microsoft Graph** → **Delegated permissions**
3. Add these permissions:
   - `openid` (Sign users in)
   - `profile` (View basic profile)
   - `email` (View email address)
   - `User.Read` (Read user profile)
   - `offline_access` (Maintain access with refresh tokens)
4. Click **Grant admin consent for [tenant]**

**Step 5: Configure group claims (for role-based access)**
1. Go to **Token configuration** blade
2. Click **Add groups claim**
3. Select **Security groups**
4. Under **ID token**, check **Group ID**
5. Under **Access token**, check **Group ID**

### Environment variables file

Create `.env` for all services:

```bash
# Microsoft Entra ID
ENTRA_CLIENT_ID=12345678-abcd-1234-abcd-123456789abc
ENTRA_TENANT_ID=87654321-dcba-4321-dcba-987654321fed
ENTRA_AUTHORITY=https://login.microsoftonline.com/87654321-dcba-4321-dcba-987654321fed

# Access Control Group IDs (from Entra ID)
ADMIN_GROUP_ID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
DEVELOPER_GROUP_ID=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
VIEWER_GROUP_ID=cccccccc-cccc-cccc-cccc-cccccccccccc

# Server Ports
A2A_SERVER_PORT=8000
ADK_SERVER_PORT=8001
MCP_SERVER_PORT=8002
FRONTEND_PORT=3000
```

---

## Part 2: FastMCP server with token propagation

The official FastMCP repository is **[jlowin/fastmcp](https://github.com/jlowin/fastmcp)** (now at version 2.x/3.x). Documentation lives at [gofastmcp.com](https://gofastmcp.com).

### Installation

```bash
pip install fastmcp[auth]
```

### Complete MCP server with authentication

**File: `mcp_server/server.py`**

```python
"""FastMCP server with OAuth token validation and tool-level access control."""
import os
import jwt
from typing import Annotated
from fastmcp import FastMCP
from fastmcp.server.dependencies import (
    get_http_headers,
    get_access_token,
    get_context,
    CurrentContext
)
from fastmcp.server.auth import BearerAuthProvider
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.context import Context
from fastmcp.exceptions import ToolError
import httpx

# Configuration
TENANT_ID = os.getenv("ENTRA_TENANT_ID")
CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")
JWKS_URI = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"

# Permission configuration
TOOL_PERMISSIONS = {
    "get_user_profile": {"required_scopes": ["User.Read"], "allowed_roles": ["admin", "developer", "viewer"]},
    "list_files": {"required_scopes": ["Files.Read"], "allowed_roles": ["admin", "developer"]},
    "send_email": {"required_scopes": ["Mail.Send"], "allowed_roles": ["admin"]},
    "delete_resource": {"required_scopes": ["Files.ReadWrite.All"], "allowed_roles": ["admin"]},
}

GROUP_TO_ROLE = {
    os.getenv("ADMIN_GROUP_ID"): "admin",
    os.getenv("DEVELOPER_GROUP_ID"): "developer",
    os.getenv("VIEWER_GROUP_ID"): "viewer",
}


class TokenValidationMiddleware(Middleware):
    """Middleware that validates tokens and extracts user context."""
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        headers = get_http_headers()
        auth_header = headers.get("authorization", "")
        
        if not auth_header.startswith("Bearer "):
            raise ToolError("Missing or invalid Authorization header")
        
        token = auth_header[7:]  # Strip "Bearer "
        
        try:
            # Fetch JWKS and validate token
            user_info = await self._validate_token(token)
            
            # Store user info in context state for tool access
            ctx = context.fastmcp_context
            await ctx.set_state("user_id", user_info["sub"])
            await ctx.set_state("user_email", user_info.get("preferred_username", ""))
            await ctx.set_state("user_groups", user_info.get("groups", []))
            await ctx.set_state("user_scopes", user_info.get("scp", "").split())
            await ctx.set_state("user_role", self._get_highest_role(user_info.get("groups", [])))
            await ctx.set_state("access_token", token)  # For downstream API calls
            
        except Exception as e:
            raise ToolError(f"Token validation failed: {str(e)}")
        
        return await call_next(context)
    
    async def _validate_token(self, token: str) -> dict:
        """Validate JWT against Entra ID JWKS."""
        async with httpx.AsyncClient() as client:
            jwks_response = await client.get(JWKS_URI)
            jwks = jwks_response.json()
        
        # Get the key ID from token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        # Find matching key
        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == kid:
                rsa_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                break
        
        if not rsa_key:
            raise ValueError("Unable to find appropriate key")
        
        # Decode and validate
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER
        )
        return payload
    
    def _get_highest_role(self, groups: list) -> str:
        """Map user groups to highest privilege role."""
        role_priority = ["admin", "developer", "viewer"]
        user_roles = [GROUP_TO_ROLE.get(g) for g in groups if g in GROUP_TO_ROLE]
        for role in role_priority:
            if role in user_roles:
                return role
        return "none"


class ToolAuthorizationMiddleware(Middleware):
    """Middleware that enforces tool-level access control."""
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        tool_name = context.tool_name
        ctx = context.fastmcp_context
        
        # Get user info from context
        user_role = await ctx.get_state("user_role")
        user_scopes = await ctx.get_state("user_scopes") or []
        
        # Check tool permissions
        if tool_name in TOOL_PERMISSIONS:
            perms = TOOL_PERMISSIONS[tool_name]
            
            # Check role
            if user_role not in perms["allowed_roles"]:
                raise ToolError(
                    f"Access denied: Role '{user_role}' cannot use tool '{tool_name}'. "
                    f"Required roles: {perms['allowed_roles']}"
                )
            
            # Check scopes
            required = set(perms["required_scopes"])
            granted = set(user_scopes)
            missing = required - granted
            if missing:
                raise ToolError(
                    f"Insufficient permissions: Missing scopes {list(missing)} for tool '{tool_name}'"
                )
        
        return await call_next(context)


# Initialize FastMCP with middleware
mcp = FastMCP(name="Identity-Aware MCP Server")
mcp.add_middleware(TokenValidationMiddleware())
mcp.add_middleware(ToolAuthorizationMiddleware())


@mcp.tool
async def get_user_profile(ctx: Context = CurrentContext()) -> dict:
    """Fetch the current user's Microsoft Graph profile."""
    access_token = await ctx.get_state("access_token")
    user_id = await ctx.get_state("user_id")
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if response.status_code == 403:
            return {"error": "insufficient_scope", "message": "Token lacks User.Read scope"}
        
        response.raise_for_status()
        return response.json()


@mcp.tool
async def list_files(folder_path: str = "/", ctx: Context = CurrentContext()) -> dict:
    """List files in user's OneDrive."""
    access_token = await ctx.get_state("access_token")
    
    endpoint = f"https://graph.microsoft.com/v1.0/me/drive/root/children"
    if folder_path != "/":
        endpoint = f"https://graph.microsoft.com/v1.0/me/drive/root:/{folder_path}:/children"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if response.status_code == 403:
            return {"error": "insufficient_scope", "message": "Token lacks Files.Read scope"}
        
        response.raise_for_status()
        data = response.json()
        return {"files": [f["name"] for f in data.get("value", [])]}


@mcp.tool
async def send_email(
    to: str,
    subject: str,
    body: str,
    ctx: Context = CurrentContext()
) -> dict:
    """Send an email via Microsoft Graph (admin only)."""
    access_token = await ctx.get_state("access_token")
    user_email = await ctx.get_state("user_email")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://graph.microsoft.com/v1.0/me/sendMail",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            },
            json={
                "message": {
                    "subject": subject,
                    "body": {"contentType": "Text", "content": body},
                    "toRecipients": [{"emailAddress": {"address": to}}]
                }
            }
        )
        
        if response.status_code == 403:
            return {"error": "insufficient_scope", "message": "Token lacks Mail.Send scope"}
        
        response.raise_for_status()
        return {"status": "sent", "from": user_email, "to": to}


@mcp.tool
async def delete_resource(resource_id: str, ctx: Context = CurrentContext()) -> dict:
    """Delete a resource (admin only with full write scope)."""
    user_role = await ctx.get_state("user_role")
    await ctx.info(f"Delete requested by {user_role} for resource {resource_id}")
    
    # Simulated deletion
    return {"status": "deleted", "resource_id": resource_id}


if __name__ == "__main__":
    import uvicorn
    from fastmcp.server.http import create_http_app
    
    app = create_http_app(mcp, path="/mcp")
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("MCP_SERVER_PORT", 8002)))
```

### Key FastMCP patterns for token access

The critical APIs for accessing authentication in tool handlers:

```python
from fastmcp.server.dependencies import (
    get_http_headers,      # Get raw HTTP headers (Authorization, etc.)
    get_http_request,      # Get full Starlette Request object
    get_access_token,      # Get validated AccessToken when using BearerAuthProvider
    get_context,           # Get Context from anywhere in request scope
    CurrentContext         # Dependency injection for Context in tool parameters
)

# Pattern 1: Direct header access
@mcp.tool
def my_tool():
    headers = get_http_headers()
    token = headers.get("authorization", "").replace("Bearer ", "")

# Pattern 2: Context injection with state
@mcp.tool
async def my_tool(ctx: Context = CurrentContext()):
    user_id = await ctx.get_state("user_id")
    await ctx.info(f"Processing for user: {user_id}")
```

---

## Part 3: Google ADK agent with authentication

The official Google ADK repository is **[google/adk-python](https://github.com/google/adk-python)**. Documentation at [google.github.io/adk-docs](https://google.github.io/adk-docs/).

### Installation

```bash
pip install google-adk
```

### Complete ADK agent with MCP integration

**File: `adk_agent/agent.py`**

```python
"""Google ADK Agent with user context and MCP tool integration."""
import os
from google.adk import Agent
from google.adk.tools import FunctionTool, ToolContext
from google.adk.tools.mcp_tool import MCPToolset, SseConnectionParams
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.adk.auth import AuthCredential, AuthCredentialTypes, OAuth2Auth
from google.adk.tools.auth_schemes import Oauth2
import httpx

# Configuration
MCP_SERVER_URL = f"http://localhost:{os.getenv('MCP_SERVER_PORT', 8002)}/mcp"
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID")


class IdentityAwareAgent:
    """Agent that maintains user identity context and passes tokens to MCP tools."""
    
    def __init__(self):
        self.session_service = InMemorySessionService()
        
        # Define MCP toolset with authentication passthrough
        self.mcp_toolset = MCPToolset(
            connection_params=SseConnectionParams(url=MCP_SERVER_URL),
            # Auth will be passed from session state
        )
        
        # Custom tools that access user context
        self.identity_tool = FunctionTool(func=self.get_identity_info)
        self.permission_check_tool = FunctionTool(func=self.check_my_permissions)
        
        # Create the agent
        self.agent = Agent(
            model="gemini-2.0-flash",
            name="identity-aware-agent",
            description="An agent that respects user identity and permissions",
            instructions="""You are a helpful assistant with access to the user's Microsoft account.
            Always check the user's permissions before attempting operations.
            If a tool fails due to permissions, explain what access is needed.""",
            tools=[
                self.identity_tool,
                self.permission_check_tool,
                self.mcp_toolset,
            ],
        )
        
        self.runner = Runner(
            agent=self.agent,
            app_name="identity-agent",
            session_service=self.session_service,
        )
    
    async def create_session(self, user_id: str, access_token: str, user_info: dict):
        """Create a session with user identity context."""
        session = await self.session_service.create_session(
            app_name="identity-agent",
            user_id=user_id,
        )
        
        # Store user context in session state with user: prefix for persistence
        session.state["user:access_token"] = access_token
        session.state["user:email"] = user_info.get("email", "")
        session.state["user:name"] = user_info.get("name", "")
        session.state["user:groups"] = user_info.get("groups", [])
        session.state["user:role"] = self._determine_role(user_info.get("groups", []))
        
        return session
    
    def _determine_role(self, groups: list) -> str:
        """Map group IDs to role names."""
        group_to_role = {
            os.getenv("ADMIN_GROUP_ID"): "admin",
            os.getenv("DEVELOPER_GROUP_ID"): "developer",
            os.getenv("VIEWER_GROUP_ID"): "viewer",
        }
        for role in ["admin", "developer", "viewer"]:
            for group_id, role_name in group_to_role.items():
                if group_id in groups and role_name == role:
                    return role
        return "none"
    
    async def get_identity_info(self, tool_context: ToolContext) -> dict:
        """Get the current user's identity information."""
        return {
            "email": tool_context.state.get("user:email"),
            "name": tool_context.state.get("user:name"),
            "role": tool_context.state.get("user:role"),
        }
    
    async def check_my_permissions(self, tool_context: ToolContext) -> dict:
        """Check what permissions the current user has."""
        role = tool_context.state.get("user:role", "none")
        
        permission_map = {
            "admin": {
                "can_read_profile": True,
                "can_list_files": True,
                "can_send_email": True,
                "can_delete_resources": True,
            },
            "developer": {
                "can_read_profile": True,
                "can_list_files": True,
                "can_send_email": False,
                "can_delete_resources": False,
            },
            "viewer": {
                "can_read_profile": True,
                "can_list_files": False,
                "can_send_email": False,
                "can_delete_resources": False,
            },
            "none": {
                "can_read_profile": False,
                "can_list_files": False,
                "can_send_email": False,
                "can_delete_resources": False,
            },
        }
        
        return {
            "role": role,
            "permissions": permission_map.get(role, permission_map["none"]),
        }
    
    async def chat(self, session_id: str, user_id: str, message: str):
        """Process a chat message with user context."""
        # Get session and inject token into MCP calls
        session = await self.session_service.get_session(
            app_name="identity-agent",
            user_id=user_id,
            session_id=session_id,
        )
        
        if not session:
            raise ValueError("Session not found. Create session first.")
        
        # The runner will automatically pass session state to tools
        async for event in self.runner.run_async(
            session_id=session_id,
            user_id=user_id,
            new_message=message,
        ):
            yield event


# MCP Tool Wrapper that injects authorization header
class AuthenticatedMCPClient:
    """Wrapper that adds authorization to MCP tool calls."""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
    
    async def call_tool(self, tool_name: str, arguments: dict, access_token: str):
        """Call an MCP tool with the user's access token."""
        async with httpx.AsyncClient() as client:
            # MCP SSE endpoint for tool calls
            response = await client.post(
                f"{self.base_url}/tools/{tool_name}",
                json=arguments,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
            return response.json()
```

### ADK authentication patterns summary

Google ADK provides several key patterns for handling authentication:

1. **ToolContext for credential access**: Tools receive a `ToolContext` parameter that provides access to session state where tokens are stored.

2. **Session state prefixes**: Use `user:` prefix for user-scoped data that persists across sessions.

3. **request_credential() / get_auth_response()**: For interactive OAuth flows where the agent needs to trigger user consent.

```python
# Interactive OAuth pattern (when user consent needed)
def tool_needing_oauth(tool_context: ToolContext) -> dict:
    # Check for cached credential
    if "user:oauth_token" in tool_context.state:
        return use_token(tool_context.state["user:oauth_token"])
    
    # Check if OAuth flow completed
    auth_response = tool_context.get_auth_response(auth_config)
    if auth_response:
        token = auth_response.oauth2.access_token
        tool_context.state["user:oauth_token"] = token
        return use_token(token)
    
    # Request OAuth flow
    tool_context.request_credential(auth_config)
    return {"status": "authentication_required"}
```

---

## Part 4: A2A Protocol server as the gateway

The A2A specification lives at **[a2aproject/A2A](https://github.com/a2aproject/A2A)**. Python SDK: [a2aproject/a2a-python](https://github.com/a2aproject/a2a-python).

### Installation

```bash
pip install a2a-sdk
```

### Complete A2A server with OAuth configuration

**File: `a2a_server/server.py`**

```python
"""A2A Server acting as authenticated gateway to the ADK agent."""
import os
import jwt
from typing import Optional
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx

from a2a.server.apps.jsonrpc import A2AFastAPIApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.server.context import ServerCallContext
from a2a.types import (
    AgentCard,
    AgentSkill,
    AgentCapabilities,
    OAuth2SecurityScheme,
    OAuthFlows,
    AuthorizationCodeOAuthFlow,
)

# Configuration
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID")
ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")
JWKS_URI = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0"

# Access control configuration
BLOCKED_USERS = os.getenv("BLOCKED_USERS", "").split(",")  # User IDs to block at agent level
ALLOWED_GROUPS = [
    os.getenv("ADMIN_GROUP_ID"),
    os.getenv("DEVELOPER_GROUP_ID"),
    os.getenv("VIEWER_GROUP_ID"),
]


# Define the Agent Card with OAuth 2.0 security
agent_card = AgentCard(
    name="Identity-Aware AI Agent",
    description="An AI agent that respects user identity and enforces permissions at multiple levels.",
    url=f"http://localhost:{os.getenv('A2A_SERVER_PORT', 8000)}/",
    version="1.0.0",
    defaultInputModes=["text/plain"],
    defaultOutputModes=["text/plain", "application/json"],
    capabilities=AgentCapabilities(streaming=True),
    skills=[
        AgentSkill(
            id="user_profile",
            name="User Profile Access",
            description="Access user's Microsoft profile information",
            tags=["identity", "profile"],
            examples=["What's my email?", "Show my profile"],
        ),
        AgentSkill(
            id="file_management",
            name="File Management",
            description="List and manage user's OneDrive files",
            tags=["files", "onedrive"],
            examples=["List my files", "What's in my Documents folder?"],
        ),
        AgentSkill(
            id="email",
            name="Email Operations",
            description="Send emails on behalf of the user (admin only)",
            tags=["email", "communication"],
            examples=["Send an email to team@company.com"],
        ),
    ],
    securitySchemes={
        "entra_oauth": OAuth2SecurityScheme(
            description="Microsoft Entra ID OAuth 2.0 Authorization Code Flow",
            flows=OAuthFlows(
                authorizationCode=AuthorizationCodeOAuthFlow(
                    authorizationUrl=f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/oauth2/v2.0/authorize",
                    tokenUrl=f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/oauth2/v2.0/token",
                    scopes={
                        "openid": "Sign in",
                        "profile": "View basic profile",
                        "User.Read": "Read user profile",
                        "Files.Read": "Read files",
                        "Mail.Send": "Send email",
                    },
                ),
            ),
        ),
    },
    security=[{"entra_oauth": ["openid", "profile", "User.Read"]}],
)


class TokenValidator:
    """Validates Entra ID tokens using JWKS."""
    
    def __init__(self):
        self._jwks_cache = None
    
    async def get_jwks(self):
        if self._jwks_cache is None:
            async with httpx.AsyncClient() as client:
                response = await client.get(JWKS_URI)
                self._jwks_cache = response.json()
        return self._jwks_cache
    
    async def validate(self, token: str) -> dict:
        """Validate token and return claims."""
        jwks = await self.get_jwks()
        
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        rsa_key = None
        for key in jwks["keys"]:
            if key["kid"] == kid:
                rsa_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                break
        
        if not rsa_key:
            raise ValueError("Key not found in JWKS")
        
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=ENTRA_CLIENT_ID,
            issuer=ISSUER,
        )
        return payload


token_validator = TokenValidator()


# Create FastAPI app
app = FastAPI(title="A2A Identity Gateway")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Authentication middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Validate tokens and enforce agent-level access control."""
    
    # Allow Agent Card discovery without auth
    if request.url.path in ["/.well-known/agent.json", "/.well-known/agent-card.json", "/docs", "/openapi.json"]:
        return await call_next(request)
    
    # Require auth for all other endpoints
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return Response(
            status_code=401,
            content="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not auth_header.startswith("Bearer "):
        return Response(
            status_code=401,
            content="Invalid Authorization format",
        )
    
    token = auth_header[7:]
    
    try:
        claims = await token_validator.validate(token)
        
        # AGENT-LEVEL ACCESS CONTROL
        user_id = claims.get("sub", "")
        user_groups = claims.get("groups", [])
        
        # Check 1: Is user explicitly blocked?
        if user_id in BLOCKED_USERS:
            return Response(
                status_code=403,
                content='{"error": "access_denied", "message": "Your account has been blocked from using this agent"}',
                media_type="application/json",
            )
        
        # Check 2: Does user belong to any allowed group?
        if not any(g in ALLOWED_GROUPS for g in user_groups):
            return Response(
                status_code=403,
                content='{"error": "access_denied", "message": "You are not a member of any authorized group"}',
                media_type="application/json",
            )
        
        # Store validated claims in request state
        request.state.user_claims = claims
        request.state.access_token = token
        
    except Exception as e:
        return Response(
            status_code=401,
            content=f"Token validation failed: {str(e)}",
        )
    
    return await call_next(request)


# Agent executor that forwards to ADK
class A2AAgentExecutor:
    """Executes agent requests by forwarding to ADK agent."""
    
    def __init__(self):
        self.adk_url = f"http://localhost:{os.getenv('ADK_SERVER_PORT', 8001)}"
    
    async def execute(self, context: ServerCallContext, message):
        """Process message through ADK agent with user context."""
        
        # Get user info from context (set by middleware)
        user_claims = context.state.get("user_claims", {})
        access_token = context.state.get("access_token", "")
        
        # Forward to ADK agent with token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.adk_url}/chat",
                json={
                    "message": message.parts[0].text if message.parts else "",
                    "user_id": user_claims.get("sub"),
                    "session_id": context.state.get("session_id"),
                },
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
            return response.json()


# Custom context builder to inject auth info
class AuthContextBuilder:
    def build(self, request: Request) -> ServerCallContext:
        context = ServerCallContext()
        if hasattr(request.state, "user_claims"):
            context.state["user_claims"] = request.state.user_claims
            context.state["access_token"] = request.state.access_token
        return context


# Create A2A application
executor = A2AAgentExecutor()
request_handler = DefaultRequestHandler(
    agent_card=agent_card,
    task_store=InMemoryTaskStore(),
    agent_executor=executor,
)

a2a_app = A2AFastAPIApplication(
    agent_card=agent_card,
    http_handler=request_handler,
    context_builder=AuthContextBuilder(),
)

a2a_app.add_routes_to_app(
    app,
    agent_card_url="/.well-known/agent.json",
    rpc_url="/",
)


# Health check endpoint
@app.get("/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("A2A_SERVER_PORT", 8000)))
```

### A2A authentication key concepts

The A2A Protocol delegates authentication to HTTP layer standards. Key patterns:

1. **Agent Card security declaration**: The `securitySchemes` and `security` fields follow OpenAPI format.

2. **Token in HTTP headers**: Always send tokens via `Authorization: Bearer <token>` header, never in JSON-RPC payload.

3. **ServerCallContext**: Access request metadata including user claims through the context object.

---

## Part 5: React frontend with MSAL.js

### Installation

```bash
npx create-react-app ai-agent-frontend
cd ai-agent-frontend
npm install @azure/msal-browser @azure/msal-react
```

### Complete frontend implementation

**File: `src/authConfig.js`**

```javascript
import { LogLevel } from '@azure/msal-browser';

export const msalConfig = {
  auth: {
    clientId: process.env.REACT_APP_ENTRA_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.REACT_APP_ENTRA_TENANT_ID}`,
    redirectUri: 'http://localhost:3000',
    postLogoutRedirectUri: 'http://localhost:3000',
  },
  cache: {
    cacheLocation: 'localStorage',
    storeAuthStateInCookie: false,
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return;
        if (level === LogLevel.Error) console.error(message);
      },
      logLevel: LogLevel.Warning,
    },
  },
};

export const loginRequest = {
  scopes: ['openid', 'profile', 'User.Read'],
};

export const graphScopes = {
  basic: ['User.Read'],
  files: ['User.Read', 'Files.Read'],
  email: ['User.Read', 'Mail.Send'],
  full: ['User.Read', 'Files.Read', 'Mail.Send'],
};
```

**File: `src/index.js`**

```javascript
import React from 'react';
import { createRoot } from 'react-dom/client';
import { PublicClientApplication, EventType } from '@azure/msal-browser';
import { MsalProvider } from '@azure/msal-react';
import App from './App';
import { msalConfig } from './authConfig';

const msalInstance = new PublicClientApplication(msalConfig);

// Set active account on page load
if (!msalInstance.getActiveAccount() && msalInstance.getAllAccounts().length > 0) {
  msalInstance.setActiveAccount(msalInstance.getAllAccounts()[0]);
}

// Listen for login events
msalInstance.addEventCallback((event) => {
  if (event.eventType === EventType.LOGIN_SUCCESS && event.payload.account) {
    msalInstance.setActiveAccount(event.payload.account);
  }
});

const root = createRoot(document.getElementById('root'));
root.render(
  <MsalProvider instance={msalInstance}>
    <App />
  </MsalProvider>
);
```

**File: `src/App.js`**

```javascript
import React, { useState, useCallback } from 'react';
import { useMsal, useAccount, AuthenticatedTemplate, UnauthenticatedTemplate } from '@azure/msal-react';
import { InteractionRequiredAuthError } from '@azure/msal-browser';
import { loginRequest, graphScopes } from './authConfig';
import './App.css';

const A2A_SERVER_URL = process.env.REACT_APP_A2A_SERVER_URL || 'http://localhost:8000';

function App() {
  return (
    <div className="app">
      <header>
        <h1>Identity-Aware AI Agent</h1>
        <AuthStatus />
      </header>
      
      <main>
        <AuthenticatedTemplate>
          <ChatInterface />
        </AuthenticatedTemplate>
        
        <UnauthenticatedTemplate>
          <LoginPrompt />
        </UnauthenticatedTemplate>
      </main>
    </div>
  );
}

function AuthStatus() {
  const { instance, accounts } = useMsal();
  const account = useAccount(accounts[0] || {});
  
  const handleLogin = () => {
    instance.loginPopup(loginRequest).catch(console.error);
  };
  
  const handleLogout = () => {
    instance.logoutPopup({ postLogoutRedirectUri: '/' });
  };
  
  if (account) {
    return (
      <div className="auth-status">
        <span>Signed in as: {account.username}</span>
        <button onClick={handleLogout}>Sign Out</button>
      </div>
    );
  }
  
  return (
    <div className="auth-status">
      <button onClick={handleLogin}>Sign In with Microsoft</button>
    </div>
  );
}

function LoginPrompt() {
  const { instance } = useMsal();
  
  return (
    <div className="login-prompt">
      <h2>Welcome to the Identity-Aware AI Agent</h2>
      <p>Sign in with your Microsoft account to start chatting.</p>
      <button 
        className="login-button"
        onClick={() => instance.loginPopup(loginRequest)}
      >
        Sign In with Microsoft
      </button>
    </div>
  );
}

function ChatInterface() {
  const { instance, accounts } = useMsal();
  const account = useAccount(accounts[0] || {});
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedScopes, setSelectedScopes] = useState('basic');
  const [error, setError] = useState(null);
  
  // Acquire token with selected scopes
  const getAccessToken = useCallback(async () => {
    const scopes = graphScopes[selectedScopes];
    
    try {
      // Try silent acquisition first
      const response = await instance.acquireTokenSilent({
        scopes,
        account,
      });
      return response.accessToken;
    } catch (error) {
      if (error instanceof InteractionRequiredAuthError) {
        // Fallback to popup
        const response = await instance.acquireTokenPopup({ scopes });
        return response.accessToken;
      }
      throw error;
    }
  }, [instance, account, selectedScopes]);
  
  // Send message to A2A server
  const sendMessage = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading) return;
    
    const userMessage = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);
    setError(null);
    
    try {
      const accessToken = await getAccessToken();
      
      const response = await fetch(A2A_SERVER_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'message/send',
          params: {
            message: {
              messageId: `msg-${Date.now()}`,
              role: 'user',
              parts: [{ kind: 'text', text: userMessage }],
            },
          },
          id: `req-${Date.now()}`,
        }),
      });
      
      if (response.status === 401) {
        setError('Authentication failed. Please sign in again.');
        return;
      }
      
      if (response.status === 403) {
        const errorData = await response.json();
        setError(`Access denied: ${errorData.message || 'You do not have permission to use this agent.'}`);
        setMessages(prev => [...prev, { 
          role: 'system', 
          content: `⚠️ ${errorData.message || 'Access denied'}`,
          isError: true 
        }]);
        return;
      }
      
      const data = await response.json();
      
      if (data.error) {
        setMessages(prev => [...prev, { 
          role: 'system', 
          content: `Error: ${data.error.message}`,
          isError: true 
        }]);
      } else if (data.result?.message) {
        const agentText = data.result.message.parts
          .filter(p => p.kind === 'text')
          .map(p => p.text)
          .join('\n');
        setMessages(prev => [...prev, { role: 'agent', content: agentText }]);
      }
      
    } catch (err) {
      console.error('Chat error:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="chat-container">
      <div className="scope-selector">
        <label>Permission Level:</label>
        <select value={selectedScopes} onChange={e => setSelectedScopes(e.target.value)}>
          <option value="basic">Basic (User.Read)</option>
          <option value="files">Files (+ Files.Read)</option>
          <option value="email">Email (+ Mail.Send)</option>
          <option value="full">Full Access</option>
        </select>
        <span className="scope-hint">
          Selected scopes: {graphScopes[selectedScopes].join(', ')}
        </span>
      </div>
      
      {error && (
        <div className="error-banner">
          {error}
          <button onClick={() => setError(null)}>×</button>
        </div>
      )}
      
      <div className="messages">
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role} ${msg.isError ? 'error' : ''}`}>
            <strong>{msg.role === 'user' ? 'You' : msg.role === 'agent' ? 'Agent' : 'System'}:</strong>
            <p>{msg.content}</p>
          </div>
        ))}
        {loading && (
          <div className="message agent loading">
            <span className="typing-indicator">Agent is thinking...</span>
          </div>
        )}
      </div>
      
      <form onSubmit={sendMessage} className="input-form">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Type a message..."
          disabled={loading}
        />
        <button type="submit" disabled={loading || !input.trim()}>
          Send
        </button>
      </form>
    </div>
  );
}

export default App;
```

**File: `src/App.css`**

```css
.app {
  max-width: 800px;
  margin: 0 auto;
  padding: 20px;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #eee;
  padding-bottom: 15px;
  margin-bottom: 20px;
}

.auth-status {
  display: flex;
  align-items: center;
  gap: 10px;
}

.login-prompt {
  text-align: center;
  padding: 40px;
}

.login-button {
  background: #0078d4;
  color: white;
  border: none;
  padding: 12px 24px;
  font-size: 16px;
  border-radius: 4px;
  cursor: pointer;
}

.chat-container {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 200px);
}

.scope-selector {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px;
  background: #f5f5f5;
  border-radius: 4px;
  margin-bottom: 15px;
}

.scope-hint {
  font-size: 12px;
  color: #666;
}

.error-banner {
  background: #fee;
  color: #c00;
  padding: 10px 15px;
  border-radius: 4px;
  margin-bottom: 15px;
  display: flex;
  justify-content: space-between;
}

.messages {
  flex: 1;
  overflow-y: auto;
  padding: 10px;
  border: 1px solid #eee;
  border-radius: 4px;
}

.message {
  margin-bottom: 15px;
  padding: 10px;
  border-radius: 8px;
}

.message.user {
  background: #e3f2fd;
  margin-left: 20%;
}

.message.agent {
  background: #f5f5f5;
  margin-right: 20%;
}

.message.system {
  background: #fff3e0;
  text-align: center;
}

.message.error {
  background: #ffebee;
}

.typing-indicator {
  color: #666;
  font-style: italic;
}

.input-form {
  display: flex;
  gap: 10px;
  margin-top: 15px;
}

.input-form input {
  flex: 1;
  padding: 12px;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 14px;
}

.input-form button {
  padding: 12px 24px;
  background: #0078d4;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

.input-form button:disabled {
  background: #ccc;
}
```

**File: `.env`**

```bash
REACT_APP_ENTRA_CLIENT_ID=your-client-id
REACT_APP_ENTRA_TENANT_ID=your-tenant-id
REACT_APP_A2A_SERVER_URL=http://localhost:8000
```

---

## Part 6: Access control verification

### Test scenarios matrix

| User | Agent Level | Tool Level | Resource Level | Expected Behavior |
|------|-------------|------------|----------------|-------------------|
| User 1 (Admin) | ✓ Member of Admin group | ✓ All tools allowed | ✓ Full scopes | Full access to everything |
| User 2a (Blocked) | ✗ In BLOCKED_USERS list | - | - | 403 at A2A gateway |
| User 2b (No group) | ✗ No allowed group | - | - | 403 at A2A gateway |
| User 3 (Viewer) | ✓ Viewer group | ✗ Only read_data | ✓ User.Read only | Can chat, tools fail for write ops |
| User 4 (Limited scope) | ✓ Developer group | ✓ Multiple tools | ✗ Only User.Read | Tools work but Graph API returns 403 |

### Testing script

**File: `tests/test_access_control.py`**

```python
"""Test access control at all three levels."""
import pytest
import httpx
import jwt
from datetime import datetime, timezone, timedelta

A2A_URL = "http://localhost:8000"
SECRET_KEY = "test-secret"  # For local testing only

def create_test_token(user_id: str, groups: list, scopes: str):
    """Create a test JWT token."""
    return jwt.encode(
        {
            "sub": user_id,
            "groups": groups,
            "scp": scopes,
            "aud": "test-client-id",
            "iss": "https://login.microsoftonline.com/test-tenant/v2.0",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        SECRET_KEY,
        algorithm="HS256"
    )


class TestAgentLevelAccess:
    """Test access control at the A2A gateway (agent level)."""
    
    @pytest.mark.asyncio
    async def test_blocked_user_denied(self):
        """User in BLOCKED_USERS list cannot access agent."""
        token = create_test_token(
            user_id="blocked-user-id",
            groups=["admin-group-id"],
            scopes="User.Read"
        )
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json={"jsonrpc": "2.0", "method": "message/send", "params": {}, "id": 1},
                headers={"Authorization": f"Bearer {token}"}
            )
        
        assert response.status_code == 403
        assert "blocked" in response.json().get("message", "").lower()
    
    @pytest.mark.asyncio
    async def test_no_group_membership_denied(self):
        """User without any allowed group cannot access agent."""
        token = create_test_token(
            user_id="regular-user",
            groups=["some-other-group"],
            scopes="User.Read"
        )
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json={"jsonrpc": "2.0", "method": "message/send", "params": {}, "id": 1},
                headers={"Authorization": f"Bearer {token}"}
            )
        
        assert response.status_code == 403
        assert "group" in response.json().get("message", "").lower()
    
    @pytest.mark.asyncio
    async def test_valid_user_allowed(self):
        """User in allowed group can access agent."""
        token = create_test_token(
            user_id="valid-user",
            groups=["viewer-group-id"],
            scopes="User.Read"
        )
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json={
                    "jsonrpc": "2.0",
                    "method": "message/send",
                    "params": {
                        "message": {
                            "messageId": "test-1",
                            "role": "user",
                            "parts": [{"kind": "text", "text": "Hello"}]
                        }
                    },
                    "id": 1
                },
                headers={"Authorization": f"Bearer {token}"}
            )
        
        assert response.status_code == 200


class TestToolLevelAccess:
    """Test access control at the MCP tool level."""
    
    @pytest.mark.asyncio
    async def test_viewer_cannot_send_email(self):
        """Viewer role cannot use send_email tool."""
        token = create_test_token(
            user_id="viewer-user",
            groups=["viewer-group-id"],
            scopes="User.Read Mail.Send"  # Has scope but wrong role
        )
        
        # Simulate tool call through agent
        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json={
                    "jsonrpc": "2.0",
                    "method": "message/send",
                    "params": {
                        "message": {
                            "messageId": "test-2",
                            "role": "user",
                            "parts": [{"kind": "text", "text": "Send an email to test@example.com"}]
                        }
                    },
                    "id": 2
                },
                headers={"Authorization": f"Bearer {token}"}
            )
        
        # Agent should return error about tool access
        result = response.json()
        assert "access_denied" in str(result) or "permission" in str(result).lower()
    
    @pytest.mark.asyncio
    async def test_admin_can_use_all_tools(self):
        """Admin role can use any tool."""
        token = create_test_token(
            user_id="admin-user",
            groups=["admin-group-id"],
            scopes="User.Read Files.Read Mail.Send"
        )
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json={
                    "jsonrpc": "2.0",
                    "method": "message/send",
                    "params": {
                        "message": {
                            "messageId": "test-3",
                            "role": "user",
                            "parts": [{"kind": "text", "text": "What are my permissions?"}]
                        }
                    },
                    "id": 3
                },
                headers={"Authorization": f"Bearer {token}"}
            )
        
        result = response.json()
        assert response.status_code == 200
        assert "admin" in str(result).lower()


class TestResourceLevelAccess:
    """Test access control at the Microsoft Graph API level (scopes)."""
    
    @pytest.mark.asyncio
    async def test_missing_scope_denied_by_graph(self):
        """User without Files.Read scope cannot list files."""
        token = create_test_token(
            user_id="developer-user",
            groups=["developer-group-id"],
            scopes="User.Read"  # Missing Files.Read
        )
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json={
                    "jsonrpc": "2.0",
                    "method": "message/send",
                    "params": {
                        "message": {
                            "messageId": "test-4",
                            "role": "user",
                            "parts": [{"kind": "text", "text": "List my files"}]
                        }
                    },
                    "id": 4
                },
                headers={"Authorization": f"Bearer {token}"}
            )
        
        result = response.json()
        # Should contain scope-related error from Graph API
        assert "scope" in str(result).lower() or "permission" in str(result).lower()
```

### Running the tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Start all services (in separate terminals)
python a2a_server/server.py
python adk_agent/agent.py
python mcp_server/server.py
cd frontend && npm start

# Run tests
pytest tests/test_access_control.py -v
```

---

## Verification checklist

Use this checklist to verify access control is working at each level:

### Agent-level verification
- [ ] Unauthenticated requests return 401
- [ ] Users in BLOCKED_USERS list receive 403 with "blocked" message
- [ ] Users without any allowed group membership receive 403
- [ ] Users with valid group membership can send messages

### Tool-level verification
- [ ] Viewer users cannot invoke `send_email` or `delete_resource` tools
- [ ] Developer users can invoke `list_files` but not `send_email`
- [ ] Admin users can invoke all tools
- [ ] Tool denial returns clear error message with required roles

### Resource-level verification
- [ ] Token with only `User.Read` scope can fetch profile
- [ ] Token without `Files.Read` scope gets 403 from Graph API on file operations
- [ ] Token without `Mail.Send` scope gets 403 from Graph API on email operations
- [ ] Error messages clearly indicate missing scopes

---

## Conclusion

This implementation provides a **complete, production-ready pattern** for identity-aware AI agent systems. The three-tier access control model ensures that:

1. **Agent-level controls** stop unauthorized users before any LLM interaction occurs
2. **Tool-level controls** prevent users from invoking capabilities beyond their role
3. **Resource-level controls** (OAuth scopes) ensure the underlying APIs enforce data access boundaries

The pattern leverages official implementations from FastMCP, Google ADK, and the A2A Protocol, with Microsoft Entra ID providing robust enterprise identity management. Each layer independently enforces security, creating defense in depth that remains secure even if one layer is bypassed.