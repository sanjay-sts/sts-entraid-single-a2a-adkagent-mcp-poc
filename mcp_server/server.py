"""FastMCP server with OAuth token validation and tool-level access control."""
import os
import asyncio
import jwt
import logging
from datetime import datetime, timezone as tz
from zoneinfo import ZoneInfo
from pathlib import Path
from typing import Annotated, Optional
from contextvars import ContextVar
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
from fastmcp.server.auth import AuthContext
import sys
import httpx
from dotenv import load_dotenv

# Add project root to path for shared dev_config module
sys.path.insert(0, str(Path(__file__).parent.parent))
from dev_config import is_auth_disabled, get_section

# Context variables for passing auth info from middleware to tools (works in stateless mode)
current_user_token: ContextVar[str] = ContextVar("current_user_token", default="")
current_user_role: ContextVar[str] = ContextVar("current_user_role", default="none")
current_user_email: ContextVar[str] = ContextVar("current_user_email", default="")
current_user_scopes: ContextVar[list] = ContextVar("current_user_scopes", default=[])

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


async def get_all_keys(kid: str):
    """Get all RSA keys matching the kid from all JWKS endpoints."""
    keys = []
    for uri in JWKS_URIS:
        try:
            jwks = await get_jwks(uri)
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    logger.debug(f"Found key {kid} in {uri}")
                    keys.append((uri, jwt.algorithms.RSAAlgorithm.from_jwk(key)))
        except Exception as e:
            logger.debug(f"Failed to fetch/parse JWKS from {uri}: {e}")
            continue
    return keys


class TokenValidationMiddleware(Middleware):
    """Middleware that validates tokens and extracts user context."""

    def _set_bypass_context(self):
        """Set ContextVars to dev bypass defaults from config."""
        dev_cfg = get_section("mcp")
        current_user_token.set("dev-bypass-token")
        current_user_role.set(dev_cfg.get("default_role", "admin"))
        current_user_email.set(dev_cfg.get("default_email", "dev@localhost"))
        current_user_scopes.set(dev_cfg.get("default_scopes", [
            "User.Read", "Files.Read", "Mail.Send", "Files.ReadWrite.All"
        ]))
        logger.warning("AUTH BYPASSED - role: %s", dev_cfg.get("default_role", "admin"))

    async def _validate_and_set_context(self, raise_on_error: bool = True):
        """Validate Bearer token from headers and set ContextVars.

        Args:
            raise_on_error: If True, raise ToolError on failure. If False, silently
                leave ContextVars at defaults (role="none"), which causes auth=
                callables to hide tools during listing.
        """
        headers = get_http_headers()
        auth_header = headers.get("authorization", "")

        if not auth_header.startswith("Bearer "):
            if raise_on_error:
                logger.warning("Missing or invalid Authorization header in MCP request")
                raise ToolError("Missing or invalid Authorization header")
            return

        token = auth_header[7:]
        logger.debug(f"Bearer token received (length: {len(token)})")

        try:
            user_info = await self._validate_token(token)
            logger.info(f"Token validated for user: {user_info.get('preferred_username', user_info.get('unique_name', user_info.get('sub')))}")

            user_role = self._get_highest_role(user_info.get("groups", []))
            user_email = user_info.get("preferred_username", user_info.get("unique_name", ""))
            user_scopes = user_info.get("scp", "").split()

            current_user_token.set(token)
            current_user_role.set(user_role)
            current_user_email.set(user_email)
            current_user_scopes.set(user_scopes)

            logger.debug(f"User context stored - role: {user_role}, email: {user_email}")

        except Exception as e:
            logger.error(f"Token validation failed: {type(e).__name__}: {str(e)}")
            if raise_on_error:
                raise ToolError(f"Token validation failed: {str(e)}")

    async def on_list_tools(self, context, call_next):
        if is_auth_disabled("mcp"):
            self._set_bypass_context()
        else:
            # Validate token so auth= callables see correct role during tool listing.
            # If no token or invalid token, role stays "none" and tools are hidden.
            await self._validate_and_set_context(raise_on_error=False)
        return await call_next(context)

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        if is_auth_disabled("mcp"):
            self._set_bypass_context()
            return await call_next(context)

        # Validate token — raise on failure (tool calls require valid auth)
        await self._validate_and_set_context(raise_on_error=True)

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

        # Get all matching keys from all endpoints
        keys = await get_all_keys(kid)
        if not keys:
            # Clear cache and retry
            global _jwks_cache
            _jwks_cache = {}
            keys = await get_all_keys(kid)

        if not keys:
            logger.error(f"Key {kid} not found in any JWKS endpoint")
            raise ValueError("Unable to find appropriate key")

        # Accept your custom API audience (tokens with api://{client-id}/access_as_user scope)
        valid_audiences = [
            CLIENT_ID,
            f"api://{CLIENT_ID}",  # Custom API scope audience
        ]

        # Try each key until one works
        last_error = None
        for uri, rsa_key in keys:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=["RS256"],
                    audience=valid_audiences,
                    issuer=VALID_ISSUERS,  # Accept both v1.0 and v2.0 issuers
                )
                logger.info(f"Token decoded successfully using key from {uri}")
                return payload
            except jwt.InvalidSignatureError as e:
                logger.debug(f"Signature verification failed with key from {uri}, trying next...")
                last_error = e
                continue
            except Exception as e:
                logger.debug(f"Validation failed with key from {uri}: {type(e).__name__}: {e}")
                last_error = e
                continue

        # All keys failed
        logger.error(f"Token validation failed with all {len(keys)} keys: {last_error}")
        raise last_error or ValueError("Token validation failed")

    def _get_highest_role(self, groups: list) -> str:
        """Map user groups to highest privilege role."""
        role_priority = ["admin", "developer", "viewer"]
        user_roles = [GROUP_TO_ROLE.get(g) for g in groups if g in GROUP_TO_ROLE]
        logger.debug(f"Group to role mapping: groups={groups}, mapped_roles={user_roles}")
        for role in role_priority:
            if role in user_roles:
                return role
        return "none"


# Auth helpers for per-tool authorization (replaces ToolAuthorizationMiddleware)
# These custom callables read from ContextVars set by TokenValidationMiddleware.
# Execution order: middleware on_call_tool → auth= callables → tool function.
# If auth= callables run before middleware (ContextVars not set), fall back to
# re-adding ToolAuthorizationMiddleware.
def require_role(*allowed_roles: str):
    """Require user to have one of the specified roles."""
    def check(ctx: AuthContext) -> bool:
        user_role = current_user_role.get()
        if user_role not in allowed_roles:
            raise ToolError(
                f"[TOOL_DENIAL] Access denied: Role '{user_role}' cannot use this tool. "
                f"Required roles: {list(allowed_roles)}"
            )
        return True
    return check


def require_scopes_from_token(*required_scopes: str):
    """Require user token to have the specified OAuth scopes."""
    def check(ctx: AuthContext) -> bool:
        user_scopes = set(current_user_scopes.get())
        missing = set(required_scopes) - user_scopes
        if missing:
            raise ToolError(
                f"[SCOPE_DENIAL] Insufficient permissions: Missing scopes {list(missing)}"
            )
        return True
    return check


# Initialize FastMCP with middleware
mcp = FastMCP(name="Identity-Aware MCP Server")
mcp.add_middleware(TokenValidationMiddleware())


@mcp.tool(auth=[require_role("admin", "developer", "viewer"), require_scopes_from_token("User.Read")])
async def get_user_profile() -> dict:
    """Fetch the current user's Microsoft Graph profile."""
    logger.info("Executing tool: get_user_profile")
    access_token = current_user_token.get()
    user_email = current_user_email.get()
    user_role = current_user_role.get()
    logger.debug(f"Getting profile for user: {user_email}")

    # Try Graph API first
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if response.status_code == 200:
            result = response.json()
            logger.debug(f"Graph API response: {result.get('displayName', 'N/A')}")
            return result

        # If Graph fails (401/403), return profile from token claims
        logger.warning(f"Graph API returned {response.status_code}, using token claims instead")
        return {
            "source": "token_claims",
            "email": user_email,
            "role": user_role,
            "note": "Graph API requires OBO flow for delegated access. Showing token claims."
        }


@mcp.tool(auth=[require_role("admin", "developer"), require_scopes_from_token("Files.Read")])
async def list_files(folder_path: str = "/") -> dict:
    """List files in user's OneDrive."""
    access_token = current_user_token.get()
    user_role = current_user_role.get()

    endpoint = "https://graph.microsoft.com/v1.0/me/drive/root/children"
    if folder_path != "/":
        endpoint = f"https://graph.microsoft.com/v1.0/me/drive/root:/{folder_path}:/children"

    async with httpx.AsyncClient() as client:
        response = await client.get(
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if response.status_code == 200:
            data = response.json()
            return {"files": [f["name"] for f in data.get("value", [])]}

        # If Graph fails, return informative message
        logger.warning(f"Graph API returned {response.status_code} for list_files")
        return {
            "error": "graph_api_unavailable",
            "status_code": response.status_code,
            "role": user_role,
            "note": "Graph API requires OBO flow. Token validated but cannot access OneDrive."
        }


@mcp.tool(auth=[require_role("admin"), require_scopes_from_token("Mail.Send")])
async def send_email(
    to: str,
    subject: str,
    body: str,
) -> dict:
    """Send an email via Microsoft Graph (admin only)."""
    access_token = current_user_token.get()
    user_email = current_user_email.get()

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


@mcp.tool(auth=[require_role("admin"), require_scopes_from_token("Files.ReadWrite.All")])
async def delete_resource(resource_id: str) -> dict:
    """Delete a resource (admin only with full write scope)."""
    user_role = current_user_role.get()
    logger.info(f"Delete requested by {user_role} for resource {resource_id}")

    # Simulated deletion
    return {"status": "deleted", "resource_id": resource_id}


# ============================================================================
# TIME TOOLS - Admin Only
# These tools demonstrate admin-restricted functionality without Graph API calls
# ============================================================================

# Common timezone mappings for user-friendly input
TIMEZONE_ALIASES = {
    "EST": "America/New_York",
    "EDT": "America/New_York",
    "CST": "America/Chicago",
    "CDT": "America/Chicago",
    "MST": "America/Denver",
    "MDT": "America/Denver",
    "PST": "America/Los_Angeles",
    "PDT": "America/Los_Angeles",
    "GMT": "Europe/London",
    "BST": "Europe/London",
    "CET": "Europe/Paris",
    "CEST": "Europe/Paris",
    "JST": "Asia/Tokyo",
    "IST": "Asia/Kolkata",
    "AEST": "Australia/Sydney",
    "AEDT": "Australia/Sydney",
    "UTC": "UTC",
}


def resolve_timezone(tz_input: str) -> ZoneInfo:
    """Resolve timezone from alias or IANA name."""
    # Check if it's an alias
    resolved = TIMEZONE_ALIASES.get(tz_input.upper(), tz_input)
    try:
        return ZoneInfo(resolved)
    except Exception:
        raise ValueError(f"Unknown timezone: {tz_input}. Use IANA names (e.g., 'America/New_York') or common aliases (e.g., 'EST', 'PST', 'UTC').")


@mcp.tool(auth=require_role("admin"))
async def get_current_time(timezone: str = "UTC") -> dict:
    """Get the current time in a specified timezone (admin only).

    Args:
        timezone: Timezone name (IANA format like 'America/New_York' or alias like 'EST', 'PST', 'UTC')

    Returns:
        Current time information including ISO format, Unix timestamp, and formatted string
    """
    user_role = current_user_role.get()
    user_email = current_user_email.get()
    logger.info(f"get_current_time called by {user_email} (role: {user_role}) for timezone: {timezone}")

    try:
        tz_info = resolve_timezone(timezone)
        now = datetime.now(tz_info)

        return {
            "timezone": str(tz_info),
            "iso_format": now.isoformat(),
            "unix_timestamp": int(now.timestamp()),
            "formatted": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "date": now.strftime("%Y-%m-%d"),
            "time": now.strftime("%H:%M:%S"),
            "day_of_week": now.strftime("%A"),
            "utc_offset": now.strftime("%z"),
            "requested_by": user_email,
        }
    except ValueError as e:
        logger.warning(f"Invalid timezone requested: {timezone}")
        return {"error": str(e)}


@mcp.tool(auth=require_role("admin"))
async def convert_timezone(
    time_str: str,
    from_timezone: str,
    to_timezone: str
) -> dict:
    """Convert a time from one timezone to another (admin only).

    Args:
        time_str: Time to convert in ISO format (e.g., '2024-01-15T14:30:00') or common formats
        from_timezone: Source timezone (IANA name or alias like 'EST', 'PST')
        to_timezone: Target timezone (IANA name or alias like 'EST', 'PST')

    Returns:
        Converted time information in both timezones
    """
    user_role = current_user_role.get()
    user_email = current_user_email.get()
    logger.info(f"convert_timezone called by {user_email} (role: {user_role}): {time_str} from {from_timezone} to {to_timezone}")

    try:
        from_tz = resolve_timezone(from_timezone)
        to_tz = resolve_timezone(to_timezone)

        # Parse the input time - try multiple formats
        parsed_time = None
        formats_to_try = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M",
            "%m/%d/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M",
            "%H:%M:%S",
            "%H:%M",
        ]

        for fmt in formats_to_try:
            try:
                parsed_time = datetime.strptime(time_str, fmt)
                break
            except ValueError:
                continue

        if parsed_time is None:
            return {"error": f"Could not parse time: {time_str}. Use ISO format (YYYY-MM-DDTHH:MM:SS) or common formats."}

        # If only time was provided (no date), use today's date
        if parsed_time.year == 1900:
            today = datetime.now(from_tz).date()
            parsed_time = parsed_time.replace(year=today.year, month=today.month, day=today.day)

        # Localize to source timezone and convert to target
        source_time = parsed_time.replace(tzinfo=from_tz)
        target_time = source_time.astimezone(to_tz)

        return {
            "original": {
                "time": source_time.strftime("%Y-%m-%d %H:%M:%S"),
                "timezone": str(from_tz),
                "iso_format": source_time.isoformat(),
            },
            "converted": {
                "time": target_time.strftime("%Y-%m-%d %H:%M:%S"),
                "timezone": str(to_tz),
                "iso_format": target_time.isoformat(),
            },
            "offset_difference": f"{(target_time.utcoffset().total_seconds() - source_time.utcoffset().total_seconds()) / 3600:+.1f} hours",
            "requested_by": user_email,
        }
    except ValueError as e:
        logger.warning(f"Timezone conversion error: {e}")
        return {"error": str(e)}


@mcp.tool(auth=require_role("admin"))
async def get_time_difference(
    timezone1: str,
    timezone2: str
) -> dict:
    """Get the current time difference between two timezones (admin only).

    Args:
        timezone1: First timezone (IANA name or alias)
        timezone2: Second timezone (IANA name or alias)

    Returns:
        Time difference information and current times in both zones
    """
    user_role = current_user_role.get()
    user_email = current_user_email.get()
    logger.info(f"get_time_difference called by {user_email} (role: {user_role}): {timezone1} vs {timezone2}")

    try:
        tz1 = resolve_timezone(timezone1)
        tz2 = resolve_timezone(timezone2)

        now_utc = datetime.now(tz.utc)
        time1 = now_utc.astimezone(tz1)
        time2 = now_utc.astimezone(tz2)

        # Calculate the difference in hours
        offset1 = time1.utcoffset().total_seconds() / 3600
        offset2 = time2.utcoffset().total_seconds() / 3600
        diff_hours = offset2 - offset1

        # Format the difference nicely
        if diff_hours == 0:
            diff_str = "same time"
        elif diff_hours > 0:
            diff_str = f"{timezone2} is {abs(diff_hours):.1f} hours ahead of {timezone1}"
        else:
            diff_str = f"{timezone2} is {abs(diff_hours):.1f} hours behind {timezone1}"

        return {
            "timezone1": {
                "name": str(tz1),
                "current_time": time1.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "utc_offset": f"UTC{offset1:+.1f}",
            },
            "timezone2": {
                "name": str(tz2),
                "current_time": time2.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "utc_offset": f"UTC{offset2:+.1f}",
            },
            "difference_hours": diff_hours,
            "description": diff_str,
            "requested_by": user_email,
        }
    except ValueError as e:
        logger.warning(f"Time difference error: {e}")
        return {"error": str(e)}


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=int(os.getenv("MCP_SERVER_PORT", 10002)),
        path="/mcp",  # Endpoint: http://localhost:10002/mcp
        stateless_http=True,  # Enable stateless mode - no session required
    )
