"""FastMCP server with Cedar ABAC policy evaluation.

Uses FastMCP's AzureJWTVerifier / JWTVerifier for trusted provider verification
(JWKS, issuer, audience) and a lightweight UserContextMiddleware for role resolution.
Tool authorization is handled by Cedar policies via CedarPolicyEvaluator — replacing
the previous require_role() auth callables with Cedar's permit/forbid policies.
"""

import asyncio
import os
import sys
import logging
from datetime import datetime, timezone as tz
from zoneinfo import ZoneInfo
from pathlib import Path
from contextvars import ContextVar

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers, get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.auth import AuthContext, MultiAuth
from fastmcp.server.auth.providers.azure import AzureJWTVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.exceptions import ToolError

# Add project root and mcp_server/ to path for sibling module imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))
from dev_config import is_auth_disabled, get_section, DEV_BYPASS_TOKEN, detect_provider
from policy import AccessRequest, AccessDecision, TomlPolicyEvaluator, CedarPolicyEvaluator
from graph_obo import init_obo_exchanger, get_obo_exchanger

# Context variables for passing auth info from middleware to tools (works in stateless mode)
current_user_token: ContextVar[str] = ContextVar("current_user_token", default="")
current_user_role: ContextVar[str] = ContextVar("current_user_role", default="none")
current_user_email: ContextVar[str] = ContextVar("current_user_email", default="")
current_user_provider: ContextVar[str] = ContextVar("current_user_provider", default="")
current_user_groups: ContextVar[list] = ContextVar("current_user_groups", default=[])
current_user_claims: ContextVar[dict] = ContextVar("current_user_claims", default={})

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

COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_REGION = os.getenv("COGNITO_REGION", "us-east-1")

# Provider-specific email claim mapping
EMAIL_CLAIMS = {
    "entra": ["preferred_username", "unique_name", "upn", "email"],
    "cognito": ["email"],
    "auth0": ["email"],
    "default": ["email", "preferred_username", "sub"],
}


# _detect_provider removed — using shared detect_provider() from dev_config


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
    # Cognito uses cognito:groups claim
    if "cognito:groups" in claims:
        return claims["cognito:groups"]

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

    # Cognito verifier — User Pool JWT validation
    # NOTE: audience is intentionally omitted. Cognito access tokens use
    # "client_id" instead of "aud". We validate client_id in UserContextMiddleware.
    if COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID:
        cognito_iss = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
        verifiers.append(JWTVerifier(
            jwks_uri=f"{cognito_iss}/.well-known/jwks.json",
            issuer=cognito_iss,
            required_scopes=["ai-agent-api/access_as_user"],
        ))

    if not verifiers:
        logger.warning("No auth providers configured — all requests will be unauthenticated!")
        return None

    return MultiAuth(
        verifiers=verifiers,
        base_url=f"http://localhost:{os.getenv('MCP_SERVER_PORT', 10002)}",
    )


# --- Policy evaluator ---

_toml_evaluator = TomlPolicyEvaluator(
    Path(__file__).parent.parent / "permissions.toml"
)
policy_evaluator = CedarPolicyEvaluator(
    Path(__file__).parent.parent / "cedar",
    _toml_evaluator,
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

    def __init__(self, evaluator):  # PolicyEvaluator (TomlPolicyEvaluator or CedarPolicyEvaluator)
        self.policy_evaluator = evaluator

    def _set_bypass_context(self) -> None:
        """Dev bypass — sets mock auth context from dev_config.toml.

        Respects X-Assume-Role header if present, otherwise uses default_role.
        """
        dev_cfg = get_section("mcp")
        current_user_token.set(DEV_BYPASS_TOKEN)
        current_user_email.set(dev_cfg.get("default_email", "dev@localhost"))
        current_user_provider.set(dev_cfg.get("default_provider", "entra"))
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

        provider = detect_provider(token.claims)

        # Cognito access tokens use client_id instead of aud — validate manually
        if provider == "cognito" and COGNITO_CLIENT_ID:
            token_client_id = token.claims.get("client_id", "")
            if token_client_id != COGNITO_CLIENT_ID:
                raise ToolError(
                    f"[TOOL_DENIAL] Invalid Cognito client_id: {token_client_id}"
                )

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
        current_user_provider.set(provider)
        current_user_groups.set(groups)
        current_user_claims.set(token.claims)

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
        else:
            # Strict: require explicit role selection via X-Assume-Role
            self._resolve_context(raise_on_error=True)
        return await call_next(context)


# --- Cedar auth callables for per-tool authorization ---

def require_cedar(tool_name: str):
    """Cedar-based auth callable for @mcp.tool() decorators.

    Phase 1 RBAC check — evaluates Cedar policies without context.
    For ABAC tools (e.g., delete_s3_object), a Phase 2 check with context
    happens inside the tool function via cedar_check_with_context().
    """
    def check(ctx: AuthContext) -> bool:
        request = AccessRequest(
            email=current_user_email.get(),
            provider=current_user_provider.get(),
            groups=current_user_groups.get(),
            tool_name=tool_name,
            claims=current_user_claims.get(),
            assumed_role=current_user_role.get(),
        )
        decision = policy_evaluator.check_access(request, [])
        if not decision.allowed:
            raise ToolError(
                f"[TOOL_DENIAL] Access denied: {decision.reason}"
            )
        return True
    return check


def cedar_check_with_context(tool_name: str, context: dict) -> AccessDecision:
    """Phase 2 ABAC check — evaluates Cedar policies with runtime context.

    Call inside tool functions that need path-based or attribute-based checks
    beyond simple RBAC. Returns AccessDecision; caller handles denial.
    """
    request = AccessRequest(
        email=current_user_email.get(),
        provider=current_user_provider.get(),
        groups=current_user_groups.get(),
        tool_name=tool_name,
        claims=current_user_claims.get(),
        assumed_role=current_user_role.get(),
        context=context,
    )
    return policy_evaluator.check_access(request, [])


async def _get_graph_token(scopes: list[str] | None = None) -> str | None:
    """Get a Graph API token via OBO exchange.

    Returns None (preserving existing fallback behavior) when:
      - Dev bypass mode (no real token to exchange)
      - Non-Entra provider (OBO is Entra-only)
      - ENTRA_CLIENT_SECRET not configured (exchanger not initialized)
      - OBO exchange fails (logged, not raised)
    """
    provider = current_user_provider.get()
    if provider != "entra":
        return None

    exchanger = get_obo_exchanger()
    if not exchanger:
        return None

    user_token = current_user_token.get()
    if not user_token or user_token == DEV_BYPASS_TOKEN:
        return None

    return await exchanger.get_graph_token(user_token, scopes)


# Graph API base URL
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"


def _require_entra_provider() -> dict | None:
    """Return a provider_not_supported error dict if the user is not Entra, else None."""
    provider = current_user_provider.get()
    if provider and provider != "entra":
        return {
            "error": "provider_not_supported",
            "provider": provider,
            "note": f"Graph API is not available for {provider} users. Use Entra ID for Graph access.",
        }
    return None


async def _get_effective_graph_token(scope: str) -> tuple[str, bool]:
    """Get the best available token for Graph API calls.

    Returns (token, obo_used) tuple.
    """
    graph_token = await _get_graph_token([f"https://graph.microsoft.com/{scope}"])
    effective_token = graph_token or current_user_token.get()
    return effective_token, graph_token is not None


# --- Initialize FastMCP with built-in auth + middleware ---

mcp = FastMCP(name="Identity-Aware MCP Server", auth=_build_auth())
mcp.add_middleware(UserContextMiddleware(policy_evaluator))
init_obo_exchanger()


# ============================================================================
# TOOLS
# ============================================================================

@mcp.tool(auth=require_cedar("get_user_profile"))
async def get_user_profile() -> dict:
    """Fetch the current user's Microsoft Graph profile."""
    logger.info("Executing tool: get_user_profile")
    user_email = current_user_email.get()
    user_role = current_user_role.get()

    provider_error = _require_entra_provider()
    if provider_error:
        provider_error.update(email=user_email, role=user_role)
        return provider_error

    effective_token, obo_used = await _get_effective_graph_token("User.Read")

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{GRAPH_API_BASE}/me",
            headers={"Authorization": f"Bearer {effective_token}"}
        )

        if response.status_code == 200:
            result = response.json()
            result["_obo_used"] = obo_used
            return result

        logger.warning("Graph API returned %d, using token claims instead", response.status_code)
        return {
            "source": "token_claims",
            "email": user_email,
            "role": user_role,
            "_obo_used": obo_used,
            "note": "Graph API returned error. Showing token claims as fallback.",
        }


@mcp.tool(auth=require_cedar("list_files"))
async def list_files(folder_path: str = "/") -> dict:
    """List files in user's OneDrive."""
    provider_error = _require_entra_provider()
    if provider_error:
        return provider_error

    effective_token, obo_used = await _get_effective_graph_token("Files.Read")

    if folder_path == "/":
        endpoint = f"{GRAPH_API_BASE}/me/drive/root/children"
    else:
        endpoint = f"{GRAPH_API_BASE}/me/drive/root:/{folder_path}:/children"

    async with httpx.AsyncClient() as client:
        response = await client.get(
            endpoint,
            headers={"Authorization": f"Bearer {effective_token}"}
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "files": [f["name"] for f in data.get("value", [])],
                "_obo_used": obo_used,
            }

        logger.warning("Graph API returned %d for list_files", response.status_code)
        return {
            "error": "graph_api_unavailable",
            "status_code": response.status_code,
            "role": current_user_role.get(),
            "_obo_used": obo_used,
            "note": "Graph API returned error. Ensure ENTRA_CLIENT_SECRET is set for OBO flow.",
        }


@mcp.tool(auth=require_cedar("send_email"))
async def send_email(
    to: str,
    subject: str,
    body: str,
) -> dict:
    """Send an email via Microsoft Graph (admin only)."""
    provider_error = _require_entra_provider()
    if provider_error:
        return provider_error

    effective_token, obo_used = await _get_effective_graph_token("Mail.Send")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{GRAPH_API_BASE}/me/sendMail",
            headers={
                "Authorization": f"Bearer {effective_token}",
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
        return {"status": "sent", "from": current_user_email.get(), "to": to, "_obo_used": obo_used}


@mcp.tool(auth=require_cedar("delete_resource"))
async def delete_resource(resource_id: str) -> dict:
    """Delete a resource (admin only, simulated)."""
    user_role = current_user_role.get()
    logger.info("Delete requested by %s for resource %s", user_role, resource_id)

    # Simulated deletion
    return {"status": "deleted", "resource_id": resource_id}


# ============================================================================
# S3 TOOLS - Multi-cloud storage (any authenticated user, server-side AWS creds)
# ============================================================================

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")


async def _run_s3_operation(operation, error_map: dict | None = None) -> dict:
    """Run a boto3 S3 operation with standardized error handling.

    Args:
        operation: Callable that receives a boto3 S3 client and returns a dict.
        error_map: Optional mapping of ClientError codes to error dicts.
    """
    try:
        import boto3
        from botocore.exceptions import NoCredentialsError, ClientError
    except ImportError:
        return {"error": "boto3_not_installed", "message": "boto3 package not available"}

    try:
        def _run():
            s3 = boto3.client("s3", region_name=AWS_REGION)
            return operation(s3)

        return await asyncio.to_thread(_run)
    except NoCredentialsError:
        return {"error": "aws_not_configured", "message": "AWS credentials not configured on server"}
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_map and error_code in error_map:
            return error_map[error_code]
        return {"error": "s3_access_denied", "code": error_code, "message": str(e)}


@mcp.tool(auth=require_cedar("list_s3_buckets"))
async def list_s3_buckets() -> dict:
    """List all S3 buckets accessible with server-side AWS credentials (admin/developer only)."""
    logger.info("Executing tool: list_s3_buckets")

    def _operation(s3):
        response = s3.list_buckets()
        buckets = [
            {"name": b["Name"], "created": b["CreationDate"].isoformat()}
            for b in response.get("Buckets", [])
        ]
        return {
            "buckets": buckets,
            "count": len(buckets),
            "requested_by": current_user_email.get(),
            "role": current_user_role.get(),
        }

    return await _run_s3_operation(_operation)


@mcp.tool(auth=require_cedar("list_s3_objects"))
async def list_s3_objects(bucket: str, prefix: str = "", max_keys: int = 20) -> dict:
    """List objects in an S3 bucket (admin/developer only).

    Args:
        bucket: S3 bucket name
        prefix: Key prefix to filter objects (e.g., 'documents/')
        max_keys: Maximum number of objects to return (default 20, max 100)
    """
    logger.info("Executing tool: list_s3_objects (bucket=%s, prefix=%s)", bucket, prefix)
    max_keys = min(max_keys, 100)

    def _operation(s3):
        params = {"Bucket": bucket, "MaxKeys": max_keys}
        if prefix:
            params["Prefix"] = prefix
        response = s3.list_objects_v2(**params)
        objects = [
            {
                "key": obj["Key"],
                "size": obj["Size"],
                "last_modified": obj["LastModified"].isoformat(),
            }
            for obj in response.get("Contents", [])
        ]
        return {
            "bucket": bucket,
            "prefix": prefix,
            "objects": objects,
            "count": len(objects),
            "requested_by": current_user_email.get(),
            "role": current_user_role.get(),
        }

    return await _run_s3_operation(
        _operation,
        error_map={
            "NoSuchBucket": {
                "error": "bucket_not_found",
                "bucket": bucket,
                "message": f"Bucket '{bucket}' does not exist",
            },
        },
    )


@mcp.tool(auth=require_cedar("get_s3_object_info"))
async def get_s3_object_info(bucket: str, key: str) -> dict:
    """Get metadata about a specific S3 object (all roles).

    Args:
        bucket: S3 bucket name
        key: Object key (full path in the bucket)
    """
    logger.info("Executing tool: get_s3_object_info (bucket=%s, key=%s)", bucket, key)

    def _operation(s3):
        response = s3.head_object(Bucket=bucket, Key=key)
        return {
            "bucket": bucket,
            "key": key,
            "size": response["ContentLength"],
            "content_type": response.get("ContentType", "unknown"),
            "last_modified": response["LastModified"].isoformat(),
            "etag": response.get("ETag", ""),
            "metadata": dict(response.get("Metadata", {})),
            "requested_by": current_user_email.get(),
            "role": current_user_role.get(),
        }

    not_found_error = {
        "error": "object_not_found",
        "bucket": bucket,
        "key": key,
        "message": f"Object '{key}' not found in bucket '{bucket}'",
    }
    return await _run_s3_operation(
        _operation,
        error_map={"404": not_found_error, "NoSuchKey": not_found_error},
    )


@mcp.tool(auth=require_cedar("delete_s3_object"))
async def delete_s3_object(bucket: str, key: str) -> dict:
    """Delete an S3 object. Requires admin role, or developer role with archiver
    attribute and object must be under archive/ prefix.

    This tool demonstrates ABAC (Attribute-Based Access Control) via Cedar policies:
    - Phase 1 (auth callable): Cedar RBAC check — can this role call this tool?
    - Phase 2 (below): Cedar ABAC check — can this user delete at this path?

    Args:
        bucket: S3 bucket name
        key: Object key (full path in the bucket)
    """
    logger.info("Executing tool: delete_s3_object (bucket=%s, key=%s)", bucket, key)

    # Phase 2: ABAC check with resource path context
    decision = cedar_check_with_context(
        "delete_s3_object", {"resource_path": key}
    )
    if not decision.allowed:
        logger.warning(
            "ABAC denied delete_s3_object: %s key=%s reason=%s",
            current_user_email.get(), key, decision.reason,
        )
        return {
            "error": "abac_denied",
            "message": f"[TOOL_DENIAL] {decision.reason}",
            "bucket": bucket,
            "key": key,
        }

    def _operation(s3):
        s3.delete_object(Bucket=bucket, Key=key)
        return {
            "status": "deleted",
            "bucket": bucket,
            "key": key,
            "deleted_by": current_user_email.get(),
            "role": current_user_role.get(),
        }

    return await _run_s3_operation(
        _operation,
        error_map={
            "NoSuchBucket": {
                "error": "bucket_not_found",
                "bucket": bucket,
                "message": f"Bucket '{bucket}' does not exist",
            },
        },
    )


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


@mcp.tool(auth=require_cedar("get_current_time"))
async def get_current_time(timezone: str = "UTC") -> dict:
    """Get the current time in a specified timezone (admin only).

    Args:
        timezone: Timezone name (IANA format like 'America/New_York' or alias like 'EST', 'PST', 'UTC')

    Returns:
        Current time information including ISO format, Unix timestamp, and formatted string
    """
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
            "requested_by": current_user_email.get(),
        }
    except ValueError as e:
        return {"error": str(e)}


TIME_PARSE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%H:%M:%S",
    "%H:%M",
]


def _parse_time_string(time_str: str) -> datetime | None:
    """Try parsing a time string against common formats. Returns None on failure."""
    for fmt in TIME_PARSE_FORMATS:
        try:
            return datetime.strptime(time_str, fmt)
        except ValueError:
            continue
    return None


@mcp.tool(auth=require_cedar("convert_timezone"))
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
    try:
        from_tz = resolve_timezone(from_timezone)
        to_tz = resolve_timezone(to_timezone)

        parsed_time = _parse_time_string(time_str)
        if parsed_time is None:
            return {"error": f"Could not parse time: {time_str}. Use ISO format (YYYY-MM-DDTHH:MM:SS) or common formats."}

        # If only time was provided (no date), use today's date
        if parsed_time.year == 1900:
            today = datetime.now(from_tz).date()
            parsed_time = parsed_time.replace(year=today.year, month=today.month, day=today.day)

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
            "requested_by": current_user_email.get(),
        }
    except ValueError as e:
        return {"error": str(e)}


@mcp.tool(auth=require_cedar("get_time_difference"))
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
    try:
        tz1 = resolve_timezone(timezone1)
        tz2 = resolve_timezone(timezone2)

        now_utc = datetime.now(tz.utc)
        time1 = now_utc.astimezone(tz1)
        time2 = now_utc.astimezone(tz2)

        offset1 = time1.utcoffset().total_seconds() / 3600
        offset2 = time2.utcoffset().total_seconds() / 3600
        diff_hours = offset2 - offset1

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
            "requested_by": current_user_email.get(),
        }
    except ValueError as e:
        return {"error": str(e)}


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=int(os.getenv("MCP_SERVER_PORT", 10002)),
        path="/mcp",  # Endpoint: http://localhost:10002/mcp
        stateless_http=True,  # Enable stateless mode - no session required
    )
