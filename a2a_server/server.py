"""A2A Server with streaming support using official a2a-sdk.

Implements the A2A Protocol with proper SSE streaming.
"""
import asyncio
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass
from contextvars import ContextVar
from pathlib import Path
from contextlib import asynccontextmanager

import httpx
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

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
    SecurityScheme,
    HTTPAuthSecurityScheme,
)

# Load environment variables
load_dotenv()

# Configuration
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID")
ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")

COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_REGION = os.getenv("COGNITO_REGION", "us-east-1")

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

# Cognito group names for agent-level access control
COGNITO_ALLOWED_GROUPS = [
    os.getenv("COGNITO_ADMIN_GROUP", "platform-admins"),
    os.getenv("COGNITO_DEVELOPER_GROUP", "platform-developers"),
    os.getenv("COGNITO_VIEWER_GROUP", "platform-viewers"),
]
COGNITO_ALLOWED_GROUPS = [g for g in COGNITO_ALLOWED_GROUPS if g]


@dataclass
class IdPConfig:
    """Configuration for an Identity Provider."""
    name: str
    jwks_uris: list[str]
    valid_issuers: list[str]
    valid_audiences: list[str]
    algorithms: list[str] = None
    audience_claim: str = "aud"  # "aud" for standard, "client_id" for Cognito

    def __post_init__(self):
        if self.algorithms is None:
            self.algorithms = ["RS256"]


def _build_idp_configs() -> list[IdPConfig]:
    """Build IdP configurations from environment variables."""
    configs = []

    # Entra ID
    if ENTRA_TENANT_ID and ENTRA_CLIENT_ID:
        configs.append(IdPConfig(
            name="entra",
            jwks_uris=[
                f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/v2.0/keys",
                f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/keys",
                "https://login.microsoftonline.com/common/discovery/keys",
            ],
            valid_issuers=[
                f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0",
                f"https://sts.windows.net/{ENTRA_TENANT_ID}/",
            ],
            valid_audiences=[
                ENTRA_CLIENT_ID,
                f"api://{ENTRA_CLIENT_ID}",
            ],
        ))

    # Cognito
    if COGNITO_USER_POOL_ID and COGNITO_CLIENT_ID:
        cognito_iss = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
        configs.append(IdPConfig(
            name="cognito",
            jwks_uris=[f"{cognito_iss}/.well-known/jwks.json"],
            valid_issuers=[cognito_iss],
            valid_audiences=[COGNITO_CLIENT_ID],
            audience_claim="client_id",  # Cognito access tokens use client_id, not aud
        ))

    return configs

IDP_CONFIGS = _build_idp_configs()


class TokenValidator:
    """Validates JWT tokens from multiple IdPs using JWKS."""

    def __init__(self):
        self._jwks_cache = {}

    async def get_jwks(self, uri: str):
        """Fetch and cache JWKS from a specific URI."""
        if uri not in self._jwks_cache:
            logger.debug("Fetching JWKS from %s", uri)
            async with httpx.AsyncClient() as client:
                response = await client.get(uri)
                self._jwks_cache[uri] = response.json()
            logger.debug("JWKS fetched from %s, %d keys found", uri, len(self._jwks_cache[uri].get('keys', [])))
        return self._jwks_cache[uri]

    def clear_cache(self):
        logger.debug("Clearing JWKS cache")
        self._jwks_cache = {}

    def _detect_idp(self, token: str) -> IdPConfig | None:
        """Detect which IdP issued the token by peeking at the iss claim."""
        unverified = jwt.decode(token, options={"verify_signature": False})
        token_iss = unverified.get("iss", "")
        for config in IDP_CONFIGS:
            if token_iss in config.valid_issuers:
                return config
        # Fallback: try substring matching for partial issuer matches
        for config in IDP_CONFIGS:
            for valid_iss in config.valid_issuers:
                if valid_iss in token_iss or token_iss in valid_iss:
                    return config
        return None

    async def _get_keys_for_idp(self, kid: str, idp: IdPConfig):
        """Get RSA keys matching kid from an IdP's JWKS endpoints."""
        keys = []
        for uri in idp.jwks_uris:
            try:
                jwks = await self.get_jwks(uri)
                for key in jwks.get("keys", []):
                    if key.get("kid") == kid:
                        logger.debug("Found key %s in %s", kid, uri)
                        keys.append((uri, jwt.algorithms.RSAAlgorithm.from_jwk(key)))
            except Exception as e:
                logger.debug("Failed to fetch/parse JWKS from %s: %s", uri, e)
        return keys

    async def validate(self, token: str) -> dict:
        """Validate token against the matching IdP and return claims."""
        logger.debug("Validating token (first 50 chars): %s...", token[:50])

        # Detect which IdP issued this token
        idp = self._detect_idp(token)
        if not idp:
            unverified = jwt.decode(token, options={"verify_signature": False})
            logger.error("No IdP config found for issuer: %s", unverified.get('iss', 'unknown'))
            raise ValueError(f"Unknown token issuer: {unverified.get('iss', 'unknown')}")

        logger.debug("Token matched IdP: %s", idp.name)

        unverified = jwt.decode(token, options={"verify_signature": False})
        token_iss = unverified.get("iss", "")
        token_aud = unverified.get("aud", "")
        logger.debug("Token claims (unverified): iss=%s, aud=%s", token_iss, token_aud)

        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        logger.debug("Token kid: %s", kid)

        # Get keys from the matching IdP's endpoints
        keys = await self._get_keys_for_idp(kid, idp)
        if not keys:
            logger.debug("Key not found, clearing cache and retrying")
            self.clear_cache()
            keys = await self._get_keys_for_idp(kid, idp)

        if not keys:
            logger.error("Key %s not found in %s JWKS endpoints", kid, idp.name)
            raise ValueError(f"Key not found in {idp.name} JWKS")

        # Try each key
        # Cognito access tokens use "client_id" instead of "aud", so we skip
        # PyJWT's audience check and validate the audience claim manually.
        skip_aud = idp.audience_claim != "aud"
        decode_options = {"verify_aud": False} if skip_aud else {}

        last_error = None
        for uri, rsa_key in keys:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=idp.algorithms,
                    audience=None if skip_aud else idp.valid_audiences,
                    issuer=idp.valid_issuers,
                    options=decode_options,
                )

                # Manual audience check for non-standard audience claims (e.g., Cognito client_id)
                if skip_aud:
                    actual = payload.get(idp.audience_claim, "")
                    if actual not in idp.valid_audiences:
                        raise jwt.InvalidAudienceError(
                            f"Invalid {idp.audience_claim}: {actual}, expected one of {idp.valid_audiences}"
                        )

                logger.info("Token validated successfully via %s using key from %s", idp.name, uri)
                email = payload.get("preferred_username") or payload.get("email") or payload.get("cognito:username") or payload.get("sub", "")
                logger.info("User: %s", email)
                logger.debug("All token claims: %s", list(payload.keys()))
                return payload
            except jwt.InvalidSignatureError as e:
                logger.debug("Signature verification failed with key from %s", uri)
                last_error = e
            except jwt.InvalidAudienceError:
                logger.error("Invalid audience: token %s=%s, expected one of %s", idp.audience_claim, token_aud, idp.valid_audiences)
                raise
            except jwt.InvalidIssuerError:
                logger.error("Invalid issuer: token iss=%s, expected one of %s", token_iss, idp.valid_issuers)
                raise
            except Exception as e:
                logger.debug("Validation failed with key from %s: %s: %s", uri, type(e).__name__, e)
                last_error = e

        logger.error("Token validation failed with all %d keys for %s: %s", len(keys), idp.name, last_error)
        raise last_error or ValueError("Token validation failed")


token_validator = TokenValidator()

# User sessions mapping
user_sessions = {}
_session_lock = asyncio.Lock()


def _make_task_event(
    context: RequestContext, state: TaskState, text: str | None = None, final: bool = True
) -> TaskStatusUpdateEvent:
    """Build a TaskStatusUpdateEvent, optionally with a text message."""
    status_kwargs = {"state": state}
    if text is not None:
        status_kwargs["message"] = Message(
            messageId=str(uuid.uuid4()),
            role="agent",
            parts=[Part(root=TextPart(text=text))],
        )
    return TaskStatusUpdateEvent(
        task_id=context.task_id,
        context_id=context.context_id,
        status=TaskStatus(**status_kwargs),
        final=final,
    )


def _extract_message_text(message) -> str:
    """Extract plain text from an A2A message's parts."""
    if not message or not message.parts:
        return ""
    texts = []
    for part in message.parts:
        if hasattr(part, 'root') and hasattr(part.root, 'text'):
            texts.append(part.root.text)
        elif hasattr(part, 'text'):
            texts.append(part.text)
    return " ".join(texts).strip()


class IdentityAwareAgentExecutor(AgentExecutor):
    """Agent executor that forwards requests to the ADK agent with user context."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Execute the agent request with streaming support."""
        try:
            user_claims = current_user_claims.get()
            access_token = current_access_token.get()

            await event_queue.enqueue_event(
                _make_task_event(context, TaskState.working, final=False)
            )

            message_text = _extract_message_text(context.message)
            if not message_text:
                await event_queue.enqueue_event(
                    _make_task_event(context, TaskState.failed, "No message text provided")
                )
                return

            user_id = user_claims.get("sub", user_claims.get("oid", "anonymous"))
            session_id = await self._ensure_session(user_id, user_claims, access_token)

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

            response_text = data.get("response", "No response from agent")
            logger.info("Agent response received (length: %d)", len(response_text))

            await event_queue.enqueue_event(
                _make_task_event(context, TaskState.completed, response_text)
            )

        except httpx.HTTPStatusError as e:
            logger.error("HTTP error calling ADK: %d - %s", e.response.status_code, e.response.text)
            await event_queue.enqueue_event(
                _make_task_event(context, TaskState.failed, f"Agent error: {e.response.text}")
            )
        except Exception as e:
            logger.error("Error in agent executor: %s: %s", type(e).__name__, e)
            await event_queue.enqueue_event(
                _make_task_event(context, TaskState.failed, f"Error: {e}")
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
        if user_id in user_sessions:
            return user_sessions[user_id]

        async with _session_lock:
            # Re-check after acquiring lock (another coroutine may have created it)
            if user_id in user_sessions:
                return user_sessions[user_id]

            provider = _detect_provider(user_claims)
            email, name, groups = _extract_user_info(user_claims, provider)

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{ADK_SERVER_URL}/session",
                    json={
                        "user_id": user_id,
                        "user_info": {
                            "email": email,
                            "name": name,
                            "groups": groups,
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
    description="A multi-IdP AI agent with Entra ID and Cognito authentication that enforces role-based access control via MCP tools.",
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
        AgentSkill(
            id="s3_buckets",
            name="S3 Bucket List",
            description="List S3 buckets accessible with server-side AWS credentials (admin/developer only)",
            tags=["s3", "aws", "storage"],
            examples=["List my S3 buckets", "What S3 buckets are available?"],
        ),
        AgentSkill(
            id="s3_objects",
            name="S3 Object Browser",
            description="Browse objects in an S3 bucket (admin/developer only)",
            tags=["s3", "aws", "storage", "files"],
            examples=["List objects in my-bucket", "Show files in bucket test-data"],
        ),
        AgentSkill(
            id="s3_info",
            name="S3 Object Info",
            description="Get metadata about a specific S3 object (all authenticated users)",
            tags=["s3", "aws", "storage", "metadata"],
            examples=["Get info about file.txt in my-bucket"],
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
    logger.debug("Incoming request: %s %s", request.method, request.url.path)

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
        logger.debug("Allowing unauthenticated access to %s", request.url.path)
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
    logger.debug("Authorization header present: %s", bool(auth_header))
    if not auth_header:
        logger.warning("Missing Authorization header")
        return Response(
            status_code=401,
            content='{"error": "unauthorized", "message": "Missing Authorization header", "denial_level": "agent", "denial_reason": "missing_token"}',
            media_type="application/json",
            headers={"WWW-Authenticate": "Bearer", **_cors_headers(request)},
        )

    if not auth_header.startswith("Bearer "):
        logger.warning("Invalid Authorization format: %.20s...", auth_header)
        return Response(
            status_code=401,
            content='{"error": "unauthorized", "message": "Invalid Authorization format", "denial_level": "agent", "denial_reason": "invalid_format"}',
            media_type="application/json",
            headers=_cors_headers(request),
        )

    token = auth_header[7:]
    logger.debug("Extracted Bearer token (length: %d)", len(token))

    try:
        claims = await token_validator.validate(token)
        user_id = claims.get("sub", "")
        user_groups = claims.get("groups", [])
        logger.info("Token validated for user: %s", claims.get('preferred_username', user_id))
        logger.debug("User groups: %s", user_groups)

        # Check if user is blocked
        if user_id in BLOCKED_USERS:
            logger.warning("Blocked user attempted access: %s", user_id)
            return Response(
                status_code=403,
                content='{"error": "access_denied", "message": "Your account has been blocked", "denial_level": "agent", "denial_reason": "blocked_user"}',
                media_type="application/json",
                headers=_cors_headers(request),
            )

        # Check group membership (provider-aware)
        provider = _detect_provider(claims)
        if provider == "cognito":
            user_groups = claims.get("cognito:groups", [])
            allowed = COGNITO_ALLOWED_GROUPS
        else:
            allowed = ALLOWED_GROUPS

        if allowed and not any(g in allowed for g in user_groups):
            logger.warning("User %s not in allowed groups. Has: %s, Allowed: %s", user_id, user_groups, allowed)
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
        logger.error("Auth failed: %s: %s", type(e).__name__, e)
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
    # Cognito group names
    os.getenv("COGNITO_ADMIN_GROUP", "platform-admins"): "admin",
    os.getenv("COGNITO_DEVELOPER_GROUP", "platform-developers"): "developer",
    os.getenv("COGNITO_VIEWER_GROUP", "platform-viewers"): "viewer",
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
    "list_s3_buckets": ["admin", "developer"],
    "list_s3_objects": ["admin", "developer"],
    "get_s3_object_info": ["admin", "developer", "viewer"],
}

TOOL_SCOPES = {
    "get_user_profile": ["User.Read"],
    "list_files": ["Files.Read"],
    "send_email": ["Mail.Send"],
    "delete_resource": ["Files.ReadWrite.All"],
    "get_current_time": [],
    "convert_timezone": [],
    "get_time_difference": [],
    "list_s3_buckets": [],
    "list_s3_objects": [],
    "get_s3_object_info": [],
}


def _detect_provider(claims: dict) -> str:
    """Detect IdP from token issuer claim."""
    iss = claims.get("iss", "")
    if "login.microsoftonline.com" in iss or "sts.windows.net" in iss:
        return "entra"
    if "cognito-idp" in iss:
        return "cognito"
    return "unknown"


def _extract_user_info(claims: dict, provider: str) -> tuple[str, str, list]:
    """Extract (email, name, groups) from claims based on provider.

    Returns a tuple of (email, display_name, group_list).
    """
    if provider == "cognito":
        email = claims.get("email") or claims.get("cognito:username", "")
        name = claims.get("name") or claims.get("email", "")
        groups = claims.get("cognito:groups", [])
    else:
        email = (
            claims.get("preferred_username")
            or claims.get("unique_name")
            or claims.get("upn")
            or claims.get("email", "")
        )
        name = claims.get("name") or claims.get("given_name", "")
        groups = claims.get("groups", [])
    return email, name, groups


ROLE_PRIORITY = ["admin", "developer", "viewer"]


def _determine_role(groups: list) -> str:
    """Map user groups to highest privilege role."""
    user_roles = {GROUP_TO_ROLE[g] for g in groups if g in GROUP_TO_ROLE}
    for role in ROLE_PRIORITY:
        if role in user_roles:
            return role
    return "none"


def _get_available_roles(groups: list) -> list:
    """Return all roles the user qualifies for, ordered by priority."""
    user_roles = {GROUP_TO_ROLE[g] for g in groups if g in GROUP_TO_ROLE}
    return [r for r in ROLE_PRIORITY if r in user_roles]


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

    provider = _detect_provider(claims)
    user_email, user_name, user_groups = _extract_user_info(claims, provider)

    available_roles = _get_available_roles(user_groups)

    # Extract scopes from the token -- Entra uses "scp", Cognito/Auth0 use "scope"
    raw_scopes = claims.get("scp", "") or claims.get("scope", "")
    token_scopes = raw_scopes.split() if isinstance(raw_scopes, str) else []

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

    group_names = {gid: GROUP_TO_ROLE[gid] for gid in user_groups if gid in GROUP_TO_ROLE}
    permissions = {tool: active_role in roles for tool, roles in TOOL_ROLES.items()}

    return {
        "user": {
            "email": user_email,
            "name": user_name,
            "oid": claims.get("oid") or claims.get("sub", ""),
        },
        "security": {
            "provider": provider,
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
