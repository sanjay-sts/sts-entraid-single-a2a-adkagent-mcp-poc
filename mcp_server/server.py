"""FastMCP server with OAuth token validation and tool-level access control."""
import os
import jwt
import logging
from pathlib import Path
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

# Configure logging
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "mcp_server.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("mcp_server")

# Configuration
TENANT_ID = os.getenv("ENTRA_TENANT_ID")
CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")

# Support both v1.0 and v2.0 tokens (Graph API uses v1.0 tokens)
JWKS_URIS = [
    f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys",  # v2.0
    f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys",  # v1.0
    "https://login.microsoftonline.com/common/discovery/keys",  # common
]
VALID_ISSUERS = [
    f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",  # v2.0 issuer
    f"https://sts.windows.net/{TENANT_ID}/",  # v1.0 issuer (Graph tokens)
]

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

# JWKS cache (per URI)
_jwks_cache = {}


async def get_jwks(uri: str):
    """Fetch and cache JWKS from a specific URI."""
    global _jwks_cache
    if uri not in _jwks_cache:
        logger.debug(f"Fetching JWKS from {uri}")
        async with httpx.AsyncClient() as client:
            response = await client.get(uri)
            _jwks_cache[uri] = response.json()
        logger.debug(f"JWKS fetched from {uri}, {len(_jwks_cache[uri].get('keys', []))} keys found")
    return _jwks_cache[uri]


async def find_key(kid: str):
    """Find the RSA key matching the kid from any JWKS endpoint."""
    for uri in JWKS_URIS:
        try:
            jwks = await get_jwks(uri)
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    logger.debug(f"Found key {kid} in {uri}")
                    return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        except Exception as e:
            logger.debug(f"Failed to fetch/parse JWKS from {uri}: {e}")
            continue
    return None


class TokenValidationMiddleware(Middleware):
    """Middleware that validates tokens and extracts user context."""

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        logger.debug(f"TokenValidationMiddleware: Processing tool call")
        headers = get_http_headers()
        auth_header = headers.get("authorization", "")

        if not auth_header.startswith("Bearer "):
            logger.warning("Missing or invalid Authorization header in MCP request")
            raise ToolError("Missing or invalid Authorization header")

        token = auth_header[7:]  # Strip "Bearer "
        logger.debug(f"Bearer token received (length: {len(token)})")

        try:
            # Fetch JWKS and validate token
            user_info = await self._validate_token(token)
            logger.info(f"Token validated for user: {user_info.get('preferred_username', user_info.get('unique_name', user_info.get('sub')))}")

            # Store user info in context state for tool access
            ctx = context.fastmcp_context
            await ctx.set_state("user_id", user_info.get("sub") or user_info.get("oid"))
            await ctx.set_state("user_email", user_info.get("preferred_username", user_info.get("unique_name", "")))
            await ctx.set_state("user_groups", user_info.get("groups", []))
            await ctx.set_state("user_scopes", user_info.get("scp", "").split())
            user_role = self._get_highest_role(user_info.get("groups", []))
            await ctx.set_state("user_role", user_role)
            await ctx.set_state("access_token", token)  # For downstream API calls

            logger.debug(f"User context stored - role: {user_role}, groups: {user_info.get('groups', [])}")

        except Exception as e:
            logger.error(f"Token validation failed: {type(e).__name__}: {str(e)}")
            raise ToolError(f"Token validation failed: {str(e)}")

        return await call_next(context)

    async def _validate_token(self, token: str) -> dict:
        """Validate JWT against Entra ID JWKS (supports v1.0 and v2.0 tokens)."""
        # Decode without verification to inspect claims
        unverified = jwt.decode(token, options={"verify_signature": False})
        token_iss = unverified.get("iss", "")
        token_aud = unverified.get("aud", "")
        logger.debug(f"Token claims (unverified): iss={token_iss}, aud={token_aud}")

        # Get the key ID from token header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        logger.debug(f"Token kid: {kid}")

        # Find matching key from any JWKS endpoint
        rsa_key = await find_key(kid)
        if not rsa_key:
            # Clear cache and retry
            global _jwks_cache
            _jwks_cache = {}
            rsa_key = await find_key(kid)

        if not rsa_key:
            logger.error(f"Key {kid} not found in any JWKS endpoint")
            raise ValueError("Unable to find appropriate key")

        # Decode and validate
        # Accept both app's client ID and Microsoft Graph as valid audiences
        valid_audiences = [
            CLIENT_ID,
            "https://graph.microsoft.com",
            "00000003-0000-0000-c000-000000000000",  # Graph API's app ID
        ]
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience=valid_audiences,
            issuer=VALID_ISSUERS,  # Accept both v1.0 and v2.0 issuers
        )
        logger.debug(f"Token decoded successfully - aud: {payload.get('aud')}, iss: {payload.get('iss')}")
        return payload

    def _get_highest_role(self, groups: list) -> str:
        """Map user groups to highest privilege role."""
        role_priority = ["admin", "developer", "viewer"]
        user_roles = [GROUP_TO_ROLE.get(g) for g in groups if g in GROUP_TO_ROLE]
        logger.debug(f"Group to role mapping: groups={groups}, mapped_roles={user_roles}")
        for role in role_priority:
            if role in user_roles:
                return role
        return "none"


class ToolAuthorizationMiddleware(Middleware):
    """Middleware that enforces tool-level access control."""

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        tool_name = context.tool_name
        logger.debug(f"ToolAuthorizationMiddleware: Checking access for tool '{tool_name}'")
        ctx = context.fastmcp_context

        # Get user info from context
        user_role = await ctx.get_state("user_role")
        user_scopes = await ctx.get_state("user_scopes") or []
        logger.debug(f"User role: {user_role}, scopes: {user_scopes}")

        # Check tool permissions
        if tool_name in TOOL_PERMISSIONS:
            perms = TOOL_PERMISSIONS[tool_name]
            logger.debug(f"Tool permissions: {perms}")

            # Check role
            if user_role not in perms["allowed_roles"]:
                logger.warning(f"Access denied: Role '{user_role}' cannot use tool '{tool_name}'")
                raise ToolError(
                    f"Access denied: Role '{user_role}' cannot use tool '{tool_name}'. "
                    f"Required roles: {perms['allowed_roles']}"
                )

            # Check scopes
            required = set(perms["required_scopes"])
            granted = set(user_scopes)
            missing = required - granted
            if missing:
                logger.warning(f"Insufficient scopes for tool '{tool_name}': missing {list(missing)}")
                raise ToolError(
                    f"Insufficient permissions: Missing scopes {list(missing)} for tool '{tool_name}'"
                )

        logger.info(f"Access granted for tool '{tool_name}' to role '{user_role}'")
        return await call_next(context)


# Initialize FastMCP with middleware
mcp = FastMCP(name="Identity-Aware MCP Server")
mcp.add_middleware(TokenValidationMiddleware())
mcp.add_middleware(ToolAuthorizationMiddleware())


@mcp.tool
async def get_user_profile(ctx: Context = CurrentContext()) -> dict:
    """Fetch the current user's Microsoft Graph profile."""
    logger.info("Executing tool: get_user_profile")
    access_token = await ctx.get_state("access_token")
    user_id = await ctx.get_state("user_id")
    logger.debug(f"Calling Graph API /me for user: {user_id}")

    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if response.status_code == 403:
            logger.warning(f"Graph API returned 403 - insufficient scope")
            return {"error": "insufficient_scope", "message": "Token lacks User.Read scope"}

        response.raise_for_status()
        result = response.json()
        logger.debug(f"Graph API response: {result.get('displayName', 'N/A')}")
        return result


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
