"""FastMCP server with built-in auth providers and policy-based access control.

Uses FastMCP's AzureJWTVerifier / JWTVerifier for trusted provider verification
(JWKS, issuer, audience) and a lightweight UserContextMiddleware for role resolution
via the agent-owned permissions.toml policy store.
"""

import os
import logging
from datetime import datetime, timezone as tz
from zoneinfo import ZoneInfo
from pathlib import Path
from contextvars import ContextVar
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers, get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.auth import AuthContext, RemoteAuthProvider, MultiAuth
from fastmcp.server.auth.providers.azure import AzureJWTVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.exceptions import ToolError
from pydantic import AnyHttpUrl
import sys
import httpx
from dotenv import load_dotenv

# Add project root and mcp_server/ to path for sibling module imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))
from dev_config import is_auth_disabled, get_section
from policy import TomlPolicyEvaluator

# Context variables for passing auth info from middleware to tools (works in stateless mode)
# Removed current_user_scopes — IdP scopes are no longer checked at tool level.
current_user_token: ContextVar[str] = ContextVar("current_user_token", default="")
current_user_role: ContextVar[str] = ContextVar("current_user_role", default="none")
current_user_email: ContextVar[str] = ContextVar("current_user_email", default="")

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

# Provider-specific email claim mapping
EMAIL_CLAIMS = {
    "entra": ["preferred_username", "unique_name", "upn", "email"],
    "cognito": ["email"],
    "auth0": ["email"],
    "default": ["email", "preferred_username", "sub"],
}


def _detect_provider(claims: dict) -> str:
    """Detect IdP from token issuer claim."""
    iss = claims.get("iss", "")
    if "login.microsoftonline.com" in iss or "sts.windows.net" in iss:
        return "entra"
    if "cognito-idp" in iss:
        return "cognito"
    if "auth0.com" in iss:
        return "auth0"
    return "default"


def _extract_email(claims: dict, provider: str) -> str:
    """Extract email from claims using provider-specific claim names."""
    for claim_name in EMAIL_CLAIMS.get(provider, EMAIL_CLAIMS["default"]):
        if claim_name in claims:
            return claims[claim_name]
    return claims.get("sub", "")


def _extract_groups(claims: dict) -> list[str]:
    """Extract groups from claims, handling Entra ID group overage.

    Entra ID limits groups in tokens to ~150. When exceeded, the token
    contains an overage indicator (_claim_names.groups) instead of groups.
    In that case, groups must be fetched via Graph API /me/memberOf.
    For POC, we log a warning. Production: call Graph API.
    """
    if "groups" in claims:
        return claims["groups"]

    # Entra ID group overage detection
    claim_names = claims.get("_claim_names", {})
    if isinstance(claim_names, dict) and "groups" in claim_names:
        logger.warning(
            "Group overage detected — token has too many groups. "
            "Groups must be fetched via Graph API /me/memberOf. "
            "Falling back to user-level role assignment."
        )
        # TODO: Production — call Graph API to get full group list
        return []

    return []


# --- Auth setup: trusted provider verification ---

def _build_auth():
    """Configure trusted IdP verifiers. Only tokens from these providers are accepted.

    Trust model:
      Token arrives → FastMCP auth system
        1. Fetch JWKS from CONFIGURED provider endpoint (cached, auto-rotated)
        2. Validate JWT SIGNATURE against provider's public keys
        3. Check ISSUER matches configured trusted issuer
        4. Check AUDIENCE matches configured expected audience
        5. Check EXPIRY (not expired)
        → Only tokens signed by keys from trusted providers pass
    """
    if is_auth_disabled("mcp"):
        return None  # No auth in dev bypass mode

    verifiers = []

    # Entra ID verifier — auto-configures JWKS, issuer, audience from Azure config
    if TENANT_ID and CLIENT_ID:
        verifiers.append(AzureJWTVerifier(
            client_id=CLIENT_ID,
            tenant_id=TENANT_ID,
            required_scopes=["access_as_user"],
        ))

        # v1.0 token fallback — Graph API can return v1.0 tokens with
        # sts.windows.net issuer even when using v2.0 endpoints.
        verifiers.append(JWTVerifier(
            jwks_uri=f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys",
            issuer=f"https://sts.windows.net/{TENANT_ID}/",
            audience=[CLIENT_ID, f"api://{CLIENT_ID}"],
            algorithm="RS256",
            required_scopes=["access_as_user"],
        ))

    # Add more verifiers here for other IdPs:
    # verifiers.append(JWTVerifier(
    #     jwks_uri="https://cognito-idp.us-east-1.amazonaws.com/{pool_id}/.well-known/jwks.json",
    #     issuer="https://cognito-idp.us-east-1.amazonaws.com/{pool_id}",
    #     audience="your-cognito-client-id",
    # ))

    if not verifiers:
        logger.warning("No auth providers configured — all requests will be unauthenticated!")
        return None

    if len(verifiers) == 1:
        return RemoteAuthProvider(
            token_verifier=verifiers[0],
            authorization_servers=[
                AnyHttpUrl(f"https://login.microsoftonline.com/{TENANT_ID}/v2.0")
            ],
            base_url=f"http://localhost:{os.getenv('MCP_SERVER_PORT', 10002)}",
        )

    return MultiAuth(
        verifiers=verifiers,
        base_url=f"http://localhost:{os.getenv('MCP_SERVER_PORT', 10002)}",
    )


# --- Policy evaluator ---

policy_evaluator = TomlPolicyEvaluator(
    Path(__file__).parent.parent / "permissions.toml"
)


# --- Middleware: role resolution + ContextVar setup ---

class UserContextMiddleware(Middleware):
    """Reads validated token claims, resolves available roles, enforces role selection.

    FastMCP's built-in auth validates the token (signature, issuer, audience, expiry).
    This middleware then:
      - Detects the provider (from issuer claim)
      - Extracts email (provider-specific claim name)
      - Resolves available roles from group claims via policy evaluator
      - Handles group overage (Entra ID >150 groups)
      - Checks X-Assume-Role header for explicit role selection (tool calls)
      - Falls back to highest-priority role when header is absent (tool listing)
      - Sets ContextVars for auth= callables and tool functions
    """

    def __init__(self, evaluator: TomlPolicyEvaluator):
        self.policy_evaluator = evaluator

    def _set_bypass_context(self) -> None:
        """Dev bypass — sets mock auth context from dev_config.toml.

        Respects X-Assume-Role header if present, otherwise uses default_role.
        """
        dev_cfg = get_section("mcp")
        current_user_token.set("dev-bypass-token")
        current_user_email.set(dev_cfg.get("default_email", "dev@localhost"))
        # Respect X-Assume-Role header from upstream (ADK agent)
        try:
            headers = get_http_headers()
            assumed_role = headers.get("x-assume-role", "")
        except Exception:
            assumed_role = ""
        role = assumed_role or dev_cfg.get("default_role", "admin")
        current_user_role.set(role)
        logger.warning("AUTH BYPASSED - role: %s", role)

    def _resolve_context(self, raise_on_error: bool = True) -> None:
        """Extract claims from validated token and resolve role.

        Args:
            raise_on_error: If True (tool calls), raise ToolError on missing role
                selection. If False (tool listing), use highest available role.
        """
        token = get_access_token()
        if not token or not token.claims:
            if raise_on_error:
                raise ToolError("No valid authentication token available")
            return  # ContextVars stay at defaults → tools hidden during listing

        provider = _detect_provider(token.claims)
        email = _extract_email(token.claims, provider)
        groups = _extract_groups(token.claims)

        # Resolve ALL roles the user qualifies for
        available_roles = self.policy_evaluator.get_available_roles(
            email, provider, groups
        )

        # Check X-Assume-Role header for explicit role selection
        headers = get_http_headers()
        assumed_role = headers.get("x-assume-role", "")

        if assumed_role:
            # Validate the assumed role is available to this user
            if assumed_role not in available_roles:
                raise ToolError(
                    f"[TOOL_DENIAL] Cannot assume role '{assumed_role}'. "
                    f"Available roles: {available_roles}"
                )
        elif raise_on_error:
            # Tool calls require explicit role selection
            if not available_roles:
                raise ToolError(
                    f"[TOOL_DENIAL] No roles available for {email}. "
                    f"Contact admin to assign group membership."
                )
            raise ToolError(
                f"[ROLE_SELECTION] Role selection required. "
                f"Set X-Assume-Role header to one of: {available_roles}"
            )
        else:
            # Tool listing — use highest-priority role for visibility
            assumed_role = available_roles[0] if available_roles else "none"

        current_user_token.set(token.token)
        current_user_email.set(email)
        current_user_role.set(assumed_role)

        logger.info(
            "User %s assumed role '%s' (available: %s)",
            email, assumed_role, available_roles,
        )

    async def on_list_tools(self, context, call_next):
        if is_auth_disabled("mcp"):
            self._set_bypass_context()
        else:
            # Lenient: use highest available role so tools are visible
            self._resolve_context(raise_on_error=False)
        return await call_next(context)

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        if is_auth_disabled("mcp"):
            self._set_bypass_context()
            return await call_next(context)

        # Strict: require explicit role selection via X-Assume-Role
        self._resolve_context(raise_on_error=True)

        return await call_next(context)


# --- Auth callables for per-tool authorization ---

def require_role(*allowed_roles: str):
    """Require user to have one of the specified roles.

    Reads from current_user_role ContextVar set by UserContextMiddleware.
    Used as auth= callable on @mcp.tool() decorators to control tool visibility
    and access.
    """
    def check(ctx: AuthContext) -> bool:
        user_role = current_user_role.get()
        if user_role not in allowed_roles:
            raise ToolError(
                f"[TOOL_DENIAL] Access denied: Role '{user_role}' cannot use this tool. "
                f"Required roles: {list(allowed_roles)}"
            )
        return True
    return check


# --- Initialize FastMCP with built-in auth + middleware ---

mcp = FastMCP(name="Identity-Aware MCP Server", auth=_build_auth())
mcp.add_middleware(UserContextMiddleware(policy_evaluator))


# ============================================================================
# TOOLS
# ============================================================================

@mcp.tool(auth=require_role("admin", "developer", "viewer"))
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


@mcp.tool(auth=require_role("admin", "developer"))
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


@mcp.tool(auth=require_role("admin"))
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


@mcp.tool(auth=require_role("admin"))
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
