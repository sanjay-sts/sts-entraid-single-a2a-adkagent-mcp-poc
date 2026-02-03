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
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.context import Context
from fastmcp.exceptions import ToolError
import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

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

# JWKS cache
_jwks_cache = None


async def get_jwks():
    """Fetch and cache JWKS from Entra ID."""
    global _jwks_cache
    if _jwks_cache is None:
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URI)
            _jwks_cache = response.json()
    return _jwks_cache


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
        jwks = await get_jwks()

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

    endpoint = "https://graph.microsoft.com/v1.0/me/drive/root/children"
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
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=int(os.getenv("MCP_SERVER_PORT", 10002)),
        path="/mcp"  # Endpoint: http://localhost:10002/mcp
    )
