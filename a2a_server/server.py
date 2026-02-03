"""A2A Server with streaming support using official a2a-sdk.

Implements the A2A Protocol with proper SSE streaming.
"""
import os
import jwt
import asyncio
from typing import AsyncIterable
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
import httpx
from dotenv import load_dotenv

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
)

# Load environment variables
load_dotenv()

# Configuration
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID")
ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")
JWKS_URI = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0"
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
    """Validates Entra ID tokens using JWKS."""

    def __init__(self):
        self._jwks_cache = None

    async def get_jwks(self):
        if self._jwks_cache is None:
            async with httpx.AsyncClient() as client:
                response = await client.get(JWKS_URI)
                self._jwks_cache = response.json()
        return self._jwks_cache

    def clear_cache(self):
        self._jwks_cache = None

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
            self.clear_cache()
            jwks = await self.get_jwks()
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

# User sessions mapping
user_sessions = {}


class IdentityAwareAgentExecutor(AgentExecutor):
    """Agent executor that forwards requests to the ADK agent with user context."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Execute the agent request with streaming support."""
        try:
            # Get user context from metadata (set by auth middleware)
            user_claims = context.metadata.get("user_claims", {})
            access_token = context.metadata.get("access_token", "")

            # Update task status to working
            event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(state=TaskState.working),
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

            if not message_text:
                event_queue.enqueue_event(
                    TaskStatusUpdateEvent(
                        task_id=context.task_id,
                        context_id=context.context_id,
                        status=TaskStatus(
                            state=TaskState.failed,
                            message=Message(
                                role="agent",
                                parts=[Part(root=TextPart(text="No message text provided"))],
                            ),
                        ),
                    )
                )
                return

            # Ensure session exists for user
            user_id = user_claims.get("sub", "anonymous")
            session_id = await self._ensure_session(user_id, user_claims, access_token)

            # Call ADK agent
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{ADK_SERVER_URL}/chat",
                    json={
                        "message": message_text,
                        "user_id": user_id,
                        "session_id": session_id,
                    },
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=60.0,
                )
                response.raise_for_status()
                data = response.json()

            # Send the response as a completed task
            response_text = data.get("response", "No response from agent")

            event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(
                        state=TaskState.completed,
                        message=Message(
                            role="agent",
                            parts=[Part(root=TextPart(text=response_text))],
                        ),
                    ),
                )
            )

        except httpx.HTTPStatusError as e:
            event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(
                        state=TaskState.failed,
                        message=Message(
                            role="agent",
                            parts=[Part(root=TextPart(text=f"Agent error: {e.response.text}"))],
                        ),
                    ),
                )
            )
        except Exception as e:
            event_queue.enqueue_event(
                TaskStatusUpdateEvent(
                    task_id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(
                        state=TaskState.failed,
                        message=Message(
                            role="agent",
                            parts=[Part(root=TextPart(text=f"Error: {str(e)}"))],
                        ),
                    ),
                )
            )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        """Cancel the agent execution."""
        event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                task_id=context.task_id,
                context_id=context.context_id,
                status=TaskStatus(state=TaskState.canceled),
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
                            "email": user_claims.get("preferred_username", ""),
                            "name": user_claims.get("name", ""),
                            "groups": user_claims.get("groups", []),
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
    description="An AI agent that respects user identity and enforces permissions at multiple levels.",
    url=f"http://localhost:{A2A_SERVER_PORT}/",
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


# Authentication middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Validate tokens and enforce agent-level access control."""

    # Allow Agent Card discovery and health without auth
    if request.url.path in [
        "/.well-known/agent.json",
        "/health",
        "/docs",
        "/openapi.json",
    ]:
        return await call_next(request)

    # Require auth for all other endpoints
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return Response(
            status_code=401,
            content='{"error": "unauthorized", "message": "Missing Authorization header"}',
            media_type="application/json",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not auth_header.startswith("Bearer "):
        return Response(
            status_code=401,
            content='{"error": "unauthorized", "message": "Invalid Authorization format"}',
            media_type="application/json",
        )

    token = auth_header[7:]

    try:
        claims = await token_validator.validate(token)
        user_id = claims.get("sub", "")
        user_groups = claims.get("groups", [])

        # Check if user is blocked
        if user_id in BLOCKED_USERS:
            return Response(
                status_code=403,
                content='{"error": "access_denied", "message": "Your account has been blocked"}',
                media_type="application/json",
            )

        # Check group membership
        if ALLOWED_GROUPS and not any(g in ALLOWED_GROUPS for g in user_groups):
            return Response(
                status_code=403,
                content='{"error": "access_denied", "message": "Not a member of any authorized group"}',
                media_type="application/json",
            )

        # Store claims in request state for the agent executor
        request.state.user_claims = claims
        request.state.access_token = token

    except jwt.ExpiredSignatureError:
        return Response(
            status_code=401,
            content='{"error": "token_expired", "message": "Token has expired"}',
            media_type="application/json",
        )
    except Exception as e:
        return Response(
            status_code=401,
            content=f'{{"error": "auth_failed", "message": "{str(e)}"}}',
            media_type="application/json",
        )

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


# Health check endpoint
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "a2a-gateway"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=A2A_SERVER_PORT)
