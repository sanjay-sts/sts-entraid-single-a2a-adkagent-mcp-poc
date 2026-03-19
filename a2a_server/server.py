"""A2A Server with streaming support using official a2a-sdk.

Implements the A2A Protocol with proper SSE streaming.
"""
import os
import json
import jwt
import asyncio
import logging
import uuid
from contextvars import ContextVar
from pathlib import Path
from typing import AsyncIterable
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
import sys
import httpx
from dotenv import load_dotenv

# Add project root to path for shared dev_config module
sys.path.insert(0, str(Path(__file__).parent.parent))
from dev_config import is_auth_disabled, get_section

# Context variables for passing auth data to agent executor
current_user_claims: ContextVar[dict] = ContextVar("current_user_claims", default={})
current_access_token: ContextVar[str] = ContextVar("current_access_token", default="")
current_assumed_role: ContextVar[str] = ContextVar("current_assumed_role", default="")

# Configure logging
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "a2a_server.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("a2a_server")

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCard,
    AgentSkill,
    AgentCapabilities,
    Message,
    Part,
    TextPart,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
    TaskArtifactUpdateEvent,
    Artifact,
    SecurityScheme,
    HTTPAuthSecurityScheme,
)

# Load environment variables
load_dotenv()

# Configuration
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID")
ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")

# Support both v1.0 and v2.0 tokens (Graph API uses v1.0 tokens)
JWKS_URIS = [
    f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/v2.0/keys",  # v2.0
    f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/keys",  # v1.0
    "https://login.microsoftonline.com/common/discovery/keys",  # common
]
VALID_ISSUERS = [
    f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0",  # v2.0 issuer
    f"https://sts.windows.net/{ENTRA_TENANT_ID}/",  # v1.0 issuer (Graph tokens)
]
A2A_SERVER_PORT = int(os.getenv("A2A_SERVER_PORT", 10000))
ADK_SERVER_URL = f"http://localhost:{os.getenv('ADK_SERVER_PORT', 10001)}"
FRONTEND_PORT = os.getenv("FRONTEND_PORT", 10003)

# Access control configuration
BLOCKED_USERS = [u.strip() for u in os.getenv("BLOCKED_USERS", "").split(",") if u.strip()]
ALLOWED_GROUPS = [
    os.getenv("ADMIN_GROUP_ID"),
    os.getenv("DEVELOPER_GROUP_ID"),
    os.getenv("VIEWER_GROUP_ID"),
]
ALLOWED_GROUPS = [g for g in ALLOWED_GROUPS if g]


class TokenValidator:
    """Validates Entra ID tokens using JWKS (supports both v1.0 and v2.0 tokens)."""

    def __init__(self):
        self._jwks_cache = {}  # Cache per URI

    async def get_jwks(self, uri: str):
        """Fetch and cache JWKS from a specific URI."""
        if uri not in self._jwks_cache:
            logger.debug(f"Fetching JWKS from {uri}")
            async with httpx.AsyncClient() as client:
                response = await client.get(uri)
                self._jwks_cache[uri] = response.json()
            logger.debug(f"JWKS fetched from {uri}, {len(self._jwks_cache[uri].get('keys', []))} keys found")
        return self._jwks_cache[uri]

    def clear_cache(self):
        logger.debug("Clearing JWKS cache")
        self._jwks_cache = {}

    async def _get_all_keys(self, kid: str):
        """Get all RSA keys matching the kid from all JWKS endpoints."""
        keys = []
        for uri in JWKS_URIS:
            try:
                jwks = await self.get_jwks(uri)
                for key in jwks.get("keys", []):
                    if key.get("kid") == kid:
                        logger.debug(f"Found key {kid} in {uri}")
                        keys.append((uri, jwt.algorithms.RSAAlgorithm.from_jwk(key)))
            except Exception as e:
                logger.debug(f"Failed to fetch/parse JWKS from {uri}: {e}")
                continue
        return keys

    async def validate(self, token: str) -> dict:
        """Validate token and return claims."""
        logger.debug(f"Validating token (first 50 chars): {token[:50]}...")

        # Decode without verification to inspect claims
        unverified = jwt.decode(token, options={"verify_signature": False})
        token_iss = unverified.get("iss", "")
        token_aud = unverified.get("aud", "")
        logger.debug(f"Token claims (unverified): iss={token_iss}, aud={token_aud}")
        logger.debug(f"Valid issuers: {VALID_ISSUERS}")

        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        logger.debug(f"Token kid: {kid}")

        # Get all matching keys from all endpoints
        keys = await self._get_all_keys(kid)
        if not keys:
            # Clear cache and retry
            logger.debug("Key not found, clearing cache and retrying")
            self.clear_cache()
            keys = await self._get_all_keys(kid)

        if not keys:
            logger.error(f"Key {kid} not found in any JWKS endpoint")
            raise ValueError("Key not found in JWKS")

        # Accept your custom API audience (tokens with api://{client-id}/access_as_user scope)
        valid_audiences = [
            ENTRA_CLIENT_ID,
            f"api://{ENTRA_CLIENT_ID}",  # Custom API scope audience
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
                    issuer=VALID_ISSUERS,  # Accept multiple issuers
                )
                logger.info(f"Token validated successfully using key from {uri}")
                logger.info(f"User: {payload.get('preferred_username', payload.get('unique_name', payload.get('sub')))}")
                # Log all claims to see what's available
                logger.debug(f"All token claims: {list(payload.keys())}")
                logger.debug(f"Token claims details: preferred_username={payload.get('preferred_username')}, unique_name={payload.get('unique_name')}, upn={payload.get('upn')}, name={payload.get('name')}, groups={payload.get('groups', [])}")
                return payload
            except jwt.InvalidSignatureError as e:
                logger.debug(f"Signature verification failed with key from {uri}, trying next...")
                last_error = e
                continue
            except jwt.InvalidAudienceError:
                logger.error(f"Invalid audience: token aud={token_aud}, expected one of {valid_audiences}")
                raise
            except jwt.InvalidIssuerError:
                logger.error(f"Invalid issuer: token iss={token_iss}, expected one of {VALID_ISSUERS}")
                raise
            except Exception as e:
                logger.debug(f"Validation failed with key from {uri}: {type(e).__name__}: {e}")
                last_error = e
                continue

        # All keys failed
        logger.error(f"Token validation failed with all {len(keys)} keys: {last_error}")
        raise last_error or ValueError("Token validation failed")


token_validator = TokenValidator()

# User sessions mapping
user_sessions = {}


class IdentityAwareAgentExecutor(AgentExecutor):
    """Agent executor that forwards requests to the ADK agent with user context."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Execute the agent request with streaming support."""
        try:
            # Get user context from context variables (set by auth middleware)
            user_claims = current_user_claims.get()
            access_token = current_access_token.get()
            logger.debug(f"Agent executor - user_claims: {bool(user_claims)}, access_token length: {len(access_token)}")

            # Update task status to working
            await event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(state=TaskState.working),
                    final=False,
                )
            )

            # Extract message text from the request
            message_text = ""
            if context.message and context.message.parts:
                for part in context.message.parts:
                    if hasattr(part, 'root') and hasattr(part.root, 'text'):
                        message_text += part.root.text + " "
                    elif hasattr(part, 'text'):
                        message_text += part.text + " "

            message_text = message_text.strip()
            logger.debug(f"Message text: {message_text}")

            if not message_text:
                await event_queue.enqueue_event(
                    TaskStatusUpdateEvent(
                        task_id=context.task_id,
                        context_id=context.context_id,
                        status=TaskStatus(
                            state=TaskState.failed,
                            message=Message(
                                messageId=str(uuid.uuid4()),
                                role="agent",
                                parts=[Part(root=TextPart(text="No message text provided"))],
                            ),
                        ),
                        final=True,
                    )
                )
                return

            # Ensure session exists for user
            user_id = user_claims.get("sub", user_claims.get("oid", "anonymous"))
            session_id = await self._ensure_session(user_id, user_claims, access_token)
            logger.debug(f"Session ID: {session_id} for user: {user_id}")

            # Call ADK agent
            logger.debug(f"Calling ADK agent at {ADK_SERVER_URL}/chat")
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{ADK_SERVER_URL}/chat",
                    json={
                        "message": message_text,
                        "user_id": user_id,
                        "session_id": session_id,
                        "role": current_assumed_role.get(),
                    },
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=60.0,
                )
                response.raise_for_status()
                data = response.json()

            # Send the response as a completed task
            response_text = data.get("response", "No response from agent")
            logger.info(f"Agent response received: {response_text[:100]}...")

            await event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(
                        state=TaskState.completed,
                        message=Message(
                            messageId=str(uuid.uuid4()),
                            role="agent",
                            parts=[Part(root=TextPart(text=response_text))],
                        ),
                    ),
                    final=True,
                )
            )

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error calling ADK: {e.response.status_code} - {e.response.text}")
            await event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(
                        state=TaskState.failed,
                        message=Message(
                            messageId=str(uuid.uuid4()),
                            role="agent",
                            parts=[Part(root=TextPart(text=f"Agent error: {e.response.text}"))],
                        ),
                    ),
                    final=True,
                )
            )
        except Exception as e:
            logger.error(f"Error in agent executor: {type(e).__name__}: {str(e)}")
            await event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(
                        state=TaskState.failed,
                        message=Message(
                            messageId=str(uuid.uuid4()),
                            role="agent",
                            parts=[Part(root=TextPart(text=f"Error: {str(e)}"))],
                        ),
                    ),
                    final=True,
                )
            )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Cancel the agent execution."""
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=context.task_id,
                context_id=context.context_id,
                status=TaskStatus(state=TaskState.canceled),
                final=True,
            )
        )

    async def _ensure_session(self, user_id: str, user_claims: dict, access_token: str) -> str:
        """Ensure a session exists for the user."""
        if user_id not in user_sessions:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{ADK_SERVER_URL}/session",
                    json={
                        "user_id": user_id,
                        "user_info": {
                            # Try multiple claim names for email (v2.0: preferred_username, v1.0: unique_name, upn)
                            "email": user_claims.get("preferred_username") or user_claims.get("unique_name") or user_claims.get("upn", ""),
                            # Try multiple claim names for name
                            "name": user_claims.get("name") or user_claims.get("given_name", ""),
                            "groups": user_claims.get("groups", []),
                            "assumed_role": current_assumed_role.get(),
                        },
                    },
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=30.0,
                )
                response.raise_for_status()
                data = response.json()
                user_sessions[user_id] = data["session_id"]

        return user_sessions[user_id]


# Create the Agent Card
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
    skills=[
        AgentSkill(
            id="identity_info",
            name="Identity Information",
            description="Get user's email, name, and role from the authenticated token",
            tags=["identity", "auth"],
            examples=["What's my email?", "Who am I?", "What's my name?"],
        ),
        AgentSkill(
            id="permissions",
            name="Permission Check",
            description="Check what permissions the authenticated user has based on their role",
            tags=["permissions", "rbac"],
            examples=["What are my permissions?", "What can I do?"],
        ),
        AgentSkill(
            id="graph_profile",
            name="Microsoft Graph Profile",
            description="Fetch user profile from Microsoft Graph API via MCP (requires User.Read scope)",
            tags=["graph", "profile", "mcp"],
            examples=["Show my Microsoft profile", "Get my Graph profile"],
        ),
        AgentSkill(
            id="onedrive_files",
            name="OneDrive Files",
            description="List files in user's OneDrive via MCP (admin/developer only, requires Files.Read scope)",
            tags=["files", "onedrive", "mcp"],
            examples=["List my files", "What's in my OneDrive?"],
        ),
        AgentSkill(
            id="time_current",
            name="Current Time",
            description="Get the current time in any timezone (ADMIN ONLY)",
            tags=["time", "timezone", "admin"],
            examples=["What time is it in Tokyo?", "Current time in EST", "What's the time in UTC?"],
        ),
        AgentSkill(
            id="time_convert",
            name="Timezone Converter",
            description="Convert time between different timezones (ADMIN ONLY)",
            tags=["time", "timezone", "convert", "admin"],
            examples=["Convert 3pm EST to PST", "What is 14:00 Tokyo time in London?"],
        ),
        AgentSkill(
            id="time_difference",
            name="Timezone Difference",
            description="Get the time difference between two timezones (ADMIN ONLY)",
            tags=["time", "timezone", "difference", "admin"],
            examples=["Time difference between NYC and London", "How many hours ahead is Tokyo from LA?"],
        ),
    ],
)


# Create FastAPI app with lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="A2A Identity Gateway", lifespan=lifespan)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"http://localhost:{FRONTEND_PORT}", "http://localhost:10003"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _cors_headers(request: Request) -> dict:
    """Build CORS headers for error responses returned before CORSMiddleware can act."""
    origin = request.headers.get("origin", "")
    allowed = [f"http://localhost:{FRONTEND_PORT}", "http://localhost:10003"]
    if origin in allowed:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        }
    return {}


# Authentication middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Validate tokens and enforce agent-level access control."""
    logger.debug(f"Incoming request: {request.method} {request.url.path}")

    # Allow CORS preflight requests without auth
    if request.method == "OPTIONS":
        logger.debug("Allowing OPTIONS preflight request")
        return await call_next(request)

    # Allow Agent Card discovery and health without auth
    if request.url.path in [
        "/.well-known/agent.json",
        "/.well-known/agent-card.json",
        "/health",
        "/docs",
        "/openapi.json",
    ]:
        logger.debug(f"Allowing unauthenticated access to {request.url.path}")
        return await call_next(request)

    # Development auth bypass (dev_config.toml)
    if is_auth_disabled("a2a"):
        mock_claims = {
            "sub": "dev-user",
            "preferred_username": get_section("a2a").get("default_email", "dev@localhost"),
            "name": "Dev User (auth bypassed)",
            "groups": ALLOWED_GROUPS,
            "scp": "User.Read Files.Read Mail.Send Files.ReadWrite.All",
        }
        current_user_claims.set(mock_claims)
        current_access_token.set("dev-bypass-token")
        current_assumed_role.set(request.headers.get("X-Assume-Role", "") or get_section("a2a").get("default_role", "admin"))
        request.state.user_claims = mock_claims
        request.state.access_token = "dev-bypass-token"
        logger.warning("AUTH BYPASSED: %s %s", request.method, request.url.path)
        return await call_next(request)

    # Require auth for all other endpoints
    auth_header = request.headers.get("Authorization")
    logger.debug(f"Authorization header present: {bool(auth_header)}")
    if not auth_header:
        logger.warning("Missing Authorization header")
        return Response(
            status_code=401,
            content='{"error": "unauthorized", "message": "Missing Authorization header", "denial_level": "agent", "denial_reason": "missing_token"}',
            media_type="application/json",
            headers={"WWW-Authenticate": "Bearer", **_cors_headers(request)},
        )

    if not auth_header.startswith("Bearer "):
        logger.warning(f"Invalid Authorization format: {auth_header[:20]}...")
        return Response(
            status_code=401,
            content='{"error": "unauthorized", "message": "Invalid Authorization format", "denial_level": "agent", "denial_reason": "invalid_format"}',
            media_type="application/json",
            headers=_cors_headers(request),
        )

    token = auth_header[7:]
    logger.debug(f"Extracted Bearer token (length: {len(token)})")

    try:
        claims = await token_validator.validate(token)
        user_id = claims.get("sub", "")
        user_groups = claims.get("groups", [])
        logger.info(f"Token validated for user: {claims.get('preferred_username', user_id)}")
        logger.debug(f"User groups: {user_groups}")
        logger.debug(f"Allowed groups: {ALLOWED_GROUPS}")

        # Check if user is blocked
        if user_id in BLOCKED_USERS:
            logger.warning(f"Blocked user attempted access: {user_id}")
            return Response(
                status_code=403,
                content='{"error": "access_denied", "message": "Your account has been blocked", "denial_level": "agent", "denial_reason": "blocked_user"}',
                media_type="application/json",
                headers=_cors_headers(request),
            )

        # Check group membership
        if ALLOWED_GROUPS and not any(g in ALLOWED_GROUPS for g in user_groups):
            logger.warning(f"User {user_id} not in allowed groups. Has: {user_groups}, Allowed: {ALLOWED_GROUPS}")
            return Response(
                status_code=403,
                content='{"error": "access_denied", "message": "Not a member of any authorized group", "denial_level": "agent", "denial_reason": "no_group_membership"}',
                media_type="application/json",
                headers=_cors_headers(request),
            )

        logger.debug("Access control passed, storing claims in request state")
        # Store claims in request state for the agent executor
        request.state.user_claims = claims
        request.state.access_token = token

        # Also set context variables for the agent executor
        current_user_claims.set(claims)
        current_access_token.set(token)
        current_assumed_role.set(request.headers.get("X-Assume-Role", ""))

    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return Response(
            status_code=401,
            content='{"error": "token_expired", "message": "Token has expired", "denial_level": "agent", "denial_reason": "token_expired"}',
            media_type="application/json",
            headers=_cors_headers(request),
        )
    except Exception as e:
        logger.error(f"Auth failed: {type(e).__name__}: {str(e)}")
        return Response(
            status_code=401,
            content=json.dumps({"error": "auth_failed", "message": str(e), "denial_level": "agent", "denial_reason": "validation_failed"}),
            media_type="application/json",
            headers=_cors_headers(request),
        )

    logger.debug("Auth middleware complete, passing to next handler")
    return await call_next(request)


# Create A2A request handler and application
agent_executor = IdentityAwareAgentExecutor()
task_store = InMemoryTaskStore()
request_handler = DefaultRequestHandler(
    agent_executor=agent_executor,
    task_store=task_store,
)

a2a_app = A2AStarletteApplication(
    agent_card=agent_card,
    http_handler=request_handler,
)

# Add A2A routes to the FastAPI app
a2a_app.add_routes_to_app(app)


# Group-to-role mapping (same as mcp_server and adk_agent)
GROUP_TO_ROLE = {
    os.getenv("ADMIN_GROUP_ID"): "admin",
    os.getenv("DEVELOPER_GROUP_ID"): "developer",
    os.getenv("VIEWER_GROUP_ID"): "viewer",
}

# Tool permission matrix (matches auth= decorators on MCP tools)
TOOL_ROLES = {
    "get_user_profile": ["admin", "developer", "viewer"],
    "list_files": ["admin", "developer"],
    "send_email": ["admin"],
    "delete_resource": ["admin"],
    "get_current_time": ["admin"],
    "convert_timezone": ["admin"],
    "get_time_difference": ["admin"],
}

TOOL_SCOPES = {
    "get_user_profile": ["User.Read"],
    "list_files": ["Files.Read"],
    "send_email": ["Mail.Send"],
    "delete_resource": ["Files.ReadWrite.All"],
    "get_current_time": [],
    "convert_timezone": [],
    "get_time_difference": [],
}


def _determine_role(groups: list) -> str:
    """Map user groups to highest privilege role."""
    role_priority = ["admin", "developer", "viewer"]
    user_roles = [GROUP_TO_ROLE.get(g) for g in groups if g in GROUP_TO_ROLE]
    for role in role_priority:
        if role in user_roles:
            return role
    return "none"


def _get_available_roles(groups: list) -> list:
    """Return all roles the user qualifies for, ordered by priority."""
    role_priority = ["admin", "developer", "viewer"]
    user_roles = {GROUP_TO_ROLE.get(g) for g in groups if g in GROUP_TO_ROLE}
    return [r for r in role_priority if r in user_roles]


# Health check endpoint
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "a2a-gateway"}


@app.get("/me")
async def get_me(request: Request):
    """Return the authenticated user's security context."""
    # Auth middleware has already validated the token and set context vars
    claims = current_user_claims.get()
    if not claims:
        return Response(
            status_code=401,
            content='{"error": "unauthorized", "message": "No authenticated user"}',
            media_type="application/json",
        )

    user_groups = claims.get("groups", [])
    available_roles = _get_available_roles(user_groups)
    token_scopes = claims.get("scp", "").split()

    # In dev bypass mode with no group IDs configured, grant all roles
    if is_auth_disabled("a2a") and not available_roles:
        available_roles = ["admin", "developer", "viewer"]

    # Use assumed role if valid, otherwise highest from groups or dev bypass default
    assumed_role = request.headers.get("X-Assume-Role", "") or current_assumed_role.get()
    if assumed_role and assumed_role in available_roles:
        active_role = assumed_role
    elif available_roles:
        active_role = available_roles[0]
    else:
        active_role = _determine_role(user_groups)

    # Build group names mapping
    group_names = {}
    for gid in user_groups:
        if gid in GROUP_TO_ROLE:
            group_names[gid] = GROUP_TO_ROLE[gid]

    # Build permission matrix based on active role
    permissions = {}
    for tool, allowed_roles in TOOL_ROLES.items():
        permissions[tool] = active_role in allowed_roles

    return {
        "user": {
            "email": claims.get("preferred_username") or claims.get("unique_name") or claims.get("upn", ""),
            "name": claims.get("name") or claims.get("given_name", ""),
            "oid": claims.get("oid", ""),
        },
        "security": {
            "role": active_role,
            "available_roles": available_roles,
            "groups": user_groups,
            "group_names": group_names,
            "token_scopes": token_scopes,
            "token_expiry": claims.get("exp"),
            "issuer": claims.get("iss", ""),
        },
        "permissions": permissions,
        "tool_scopes": TOOL_SCOPES,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=A2A_SERVER_PORT)
