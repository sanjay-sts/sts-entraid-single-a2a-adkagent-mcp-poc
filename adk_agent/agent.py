"""Google ADK Agent with user context and MCP tool integration using McpToolset."""
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import AsyncGenerator

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from google.adk.agents import LlmAgent
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.models.lite_llm import LiteLlm
from google.adk.runners import Runner, RunConfig
from google.adk.sessions import InMemorySessionService
from google.adk.tools import FunctionTool, ToolContext
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset, StreamableHTTPConnectionParams
from google.genai import types
from litellm.exceptions import RateLimitError

# Add project root to path for shared dev_config module
sys.path.insert(0, str(Path(__file__).parent.parent))
from dev_config import is_auth_disabled, DEV_BYPASS_TOKEN

# Load environment variables
load_dotenv()

# Configure logging
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "adk_agent.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("adk_agent")

# Configuration
MCP_SERVER_URL = f"http://localhost:{os.getenv('MCP_SERVER_PORT', 10002)}/mcp"
ADK_SERVER_PORT = int(os.getenv("ADK_SERVER_PORT", 10001))

# Group-to-role mapping from env vars
GROUP_TO_ROLE = {
    os.getenv("ADMIN_GROUP_ID"): "admin",
    os.getenv("DEVELOPER_GROUP_ID"): "developer",
    os.getenv("VIEWER_GROUP_ID"): "viewer",
}

ROLE_PRIORITY = ["admin", "developer", "viewer"]

# Permission matrix per role (static, matches MCP tool auth= decorators)
PERMISSION_MAP = {
    "admin": {
        "can_read_profile": True,
        "can_list_files": True,
        "can_send_email": True,
        "can_delete_resources": True,
        "can_use_time_tools": True,
        "can_list_s3": True,
        "can_view_s3_object": True,
    },
    "developer": {
        "can_read_profile": True,
        "can_list_files": True,
        "can_send_email": False,
        "can_delete_resources": False,
        "can_use_time_tools": False,
        "can_list_s3": True,
        "can_view_s3_object": True,
    },
    "viewer": {
        "can_read_profile": True,
        "can_list_files": False,
        "can_send_email": False,
        "can_delete_resources": False,
        "can_use_time_tools": False,
        "can_list_s3": False,
        "can_view_s3_object": True,
    },
    "none": {
        "can_read_profile": False,
        "can_list_files": False,
        "can_send_email": False,
        "can_delete_resources": False,
        "can_use_time_tools": False,
        "can_list_s3": False,
        "can_view_s3_object": False,
    },
}


def mcp_header_provider(readonly_context: ReadonlyContext) -> dict[str, str]:
    """Provides Authorization and X-Assume-Role headers for MCP calls from session state.

    This is called by McpToolset to get dynamic headers for each request.
    The access token and role are stored in session state with 'user:' prefix.
    """
    headers = {}
    if readonly_context and readonly_context.state:
        access_token = readonly_context.state.get("user:access_token", "")
        role = readonly_context.state.get("user:role", "")
        abac_attrs = readonly_context.state.get("user:abac_attrs", "")
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        if role:
            headers["X-Assume-Role"] = role
        if abac_attrs:
            headers["X-Abac-Attrs"] = abac_attrs
    if not headers:
        logger.warning("MCP header_provider: No access token found in session state")
    return headers


class IdentityAwareAgent:
    """Agent that maintains user identity context and uses McpToolset for MCP tools."""

    def __init__(self):
        self.session_service = InMemorySessionService()
        self.sessions = {}  # Track active sessions

        # Identity tools (local - no MCP)
        self.identity_tool = FunctionTool(func=self.get_identity_info)
        self.permission_check_tool = FunctionTool(func=self.check_my_permissions)

        # MCP Toolset - connects to FastMCP server with dynamic auth
        # Uses header_provider to inject Authorization header from session state
        self.mcp_toolset = McpToolset(
            connection_params=StreamableHTTPConnectionParams(
                url=MCP_SERVER_URL,
                timeout=30.0,
                sse_read_timeout=60.0,
            ),
            # Filter tools: only expose these MCP tools to the agent
            # Admin-only tools (time tools) are enforced by MCP middleware
            tool_filter=[
                "get_user_profile",
                "list_files",
                "send_email",
                "delete_resource",
                "get_current_time",
                "convert_timezone",
                "get_time_difference",
                "list_s3_buckets",
                "list_s3_objects",
                "get_s3_object_info",
                "delete_s3_object",
            ],
            # Dynamic header provider for per-request auth
            header_provider=mcp_header_provider,
        )

        # Create the agent with both local tools and MCP toolset
        # Using LlmAgent (recommended for LiteLLM) with Claude Haiku 4.5 on Bedrock
        self.agent = LlmAgent(
            model=LiteLlm(model="bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0"),
            name="identity_aware_agent",
            description="An agent that provides user identity information and time utilities",
            instruction="""You are a helpful assistant for identity, time, and cloud storage queries.

When a user asks a question:
1. Call the appropriate tool to get the information
2. Once you receive the tool result, format it nicely and respond to the user
3. Do not call unnecessary tools - only call what's needed to answer the question

Available tools:
- get_identity_info: Get user's email, name, role from their token
- check_my_permissions: Check what actions the user can perform
- get_user_profile: Get Microsoft profile via Graph API
- list_files: List OneDrive files (admin/developer only)
- get_current_time: Get current time in a timezone (ADMIN ONLY)
- convert_timezone: Convert time between timezones (ADMIN ONLY)
- get_time_difference: Get difference between timezones (ADMIN ONLY)
- list_s3_buckets: List all S3 buckets (admin/developer only)
- list_s3_objects: List objects in an S3 bucket (admin/developer only)
- get_s3_object_info: Get metadata about a specific S3 object (all roles)
- delete_s3_object: Delete an S3 object (admin any path except protected/; developer with archiver attribute in archive/ only)

For timezone queries, use IANA timezone names like "UTC", "Europe/Belgrade", "Asia/Tokyo", "America/New_York".""",
            tools=[
                self.identity_tool,
                self.permission_check_tool,
                self.mcp_toolset,  # McpToolset provides all MCP tools
            ],
        )

        # Limit LLM calls: user message → tool call → final response
        # Keep low to prevent infinite loops with ADK's "Handle the requests" injection
        self.run_config = RunConfig(max_llm_calls=4)

        self.runner = Runner(
            agent=self.agent,
            app_name="identity-agent",
            session_service=self.session_service,
        )

    async def create_session(self, user_id: str, access_token: str, user_info: dict) -> str:
        """Create a session with user identity context."""
        logger.info("Creating session for user: %s", user_id)

        # Use assumed_role if provided, otherwise determine from groups
        assumed_role = user_info.get("assumed_role", "")
        role = assumed_role if assumed_role else self._determine_role(user_info.get("groups", []))

        # Pass initial state at creation time - this ensures it's stored properly
        # Using user: prefix for persistence across sessions
        # Serialize ABAC attrs as JSON string for session state storage
        abac_attrs = user_info.get("abac_attrs", {})

        initial_state = {
            "user:access_token": access_token,
            "user:email": user_info.get("email", user_info.get("preferred_username", "")),
            "user:name": user_info.get("name", user_info.get("displayName", "")),
            "user:groups": user_info.get("groups", []),
            "user:role": role,
            "user:abac_attrs": json.dumps(abac_attrs) if abac_attrs else "",
        }

        session = await self.session_service.create_session(
            app_name="identity-agent",
            user_id=user_id,
            state=initial_state,
        )

        logger.debug("Session created with id: %s, role: %s", session.id, role)

        # Track session
        self.sessions[session.id] = {
            "user_id": user_id,
            "session": session
        }

        return session.id

    def _determine_role(self, groups: list) -> str:
        """Map group IDs to highest-priority role."""
        user_roles = {GROUP_TO_ROLE[g] for g in groups if g in GROUP_TO_ROLE}
        for role in ROLE_PRIORITY:
            if role in user_roles:
                return role
        return "none"

    async def get_identity_info(self, tool_context: ToolContext) -> dict:
        """Get the current user's identity information."""
        # Access session state via tool_context
        state = tool_context.state if tool_context else {}
        email = state.get("user:email", "")
        name = state.get("user:name", "")
        role = state.get("user:role", "none")

        logger.debug("get_identity_info called - email: %s, role: %s", email, role)

        return {
            "email": email,
            "name": name,
            "role": role,
        }

    async def check_my_permissions(self, tool_context: ToolContext) -> dict:
        """Check what permissions the current user has."""
        state = tool_context.state if tool_context else {}
        role = state.get("user:role", "none")

        logger.debug("check_my_permissions called - role: %s", role)

        return {
            "role": role,
            "permissions": PERMISSION_MAP.get(role, PERMISSION_MAP["none"]),
        }

    async def chat(self, session_id: str, user_id: str, message: str, access_token: str) -> AsyncGenerator[dict, None]:
        """Process a chat message with user context, with retry logic for rate limits."""
        logger.info("Chat request - session: %s, user: %s", session_id, user_id)

        session_info = self.sessions.get(session_id)
        if not session_info:
            logger.error("Session not found: %s", session_id)
            yield {"error": "Session not found. Create session first."}
            return

        # Update access token in storage — user: prefix must match mcp_header_provider keys
        self.session_service.user_state.setdefault("identity-agent", {}).setdefault(user_id, {})["user:access_token"] = access_token

        max_retries = 3
        base_delay = 30  # seconds -- rate limits reset per minute

        for attempt in range(max_retries):
            try:
                async for event in self.runner.run_async(
                    session_id=session_id,
                    user_id=user_id,
                    new_message=types.Content(
                        role="user",
                        parts=[types.Part(text=message)]
                    ),
                    run_config=self.run_config,
                ):
                    yield event
                return  # Success

            except RateLimitError as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (attempt + 1)  # 30s, 60s, 90s
                    logger.warning("Rate limited, waiting %ds before retry %d/%d", delay, attempt + 2, max_retries)
                    await asyncio.sleep(delay)
                else:
                    logger.error("Rate limit exceeded after %d retries", max_retries)
                    yield {"error": f"Rate limit exceeded. Please wait a minute and try again. Details: {e}"}
                    return
            except Exception as e:
                logger.error("Agent error: %s: %s", type(e).__name__, e)
                yield {"error": f"Agent error: {e}"}
                return


# Create FastAPI app
app = FastAPI(title="Identity-Aware ADK Agent")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"http://localhost:{os.getenv('FRONTEND_PORT', 10003)}"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global agent instance
agent = IdentityAwareAgent()


def _extract_bearer_token(request: Request, endpoint: str) -> str:
    """Extract Bearer token from request, with dev bypass fallback.

    Raises HTTPException(401) if no token and auth is not bypassed.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    if is_auth_disabled("adk"):
        logger.warning("AUTH BYPASSED: %s", endpoint)
        return DEV_BYPASS_TOKEN
    raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")


def _validate_user_id(access_token: str, user_id: str) -> None:
    """Verify user_id matches the token's sub claim to prevent impersonation.

    Skips validation in dev bypass mode. Raises HTTPException(403) on mismatch.
    """
    if access_token == DEV_BYPASS_TOKEN:
        return
    try:
        import jwt
        claims = jwt.decode(access_token, options={"verify_signature": False})
        token_sub = claims.get("sub")
        if token_sub and token_sub != user_id:
            logger.warning("user_id mismatch: body=%s, token sub=%s", user_id, token_sub)
            raise HTTPException(status_code=403, detail="user_id does not match authenticated token")
    except HTTPException:
        raise
    except Exception:
        pass  # Token decode failed — A2A gateway already validated


@app.post("/session")
async def create_session(request: Request):
    """Create a new session for a user."""
    access_token = _extract_bearer_token(request, "POST /session")

    body = await request.json()
    user_id = body.get("user_id")
    user_info = body.get("user_info", {})

    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    _validate_user_id(access_token, user_id)
    session_id = await agent.create_session(user_id, access_token, user_info)
    logger.info("Session created: %s for user: %s", session_id, user_id)
    return {"session_id": session_id}


async def _parse_chat_request(request: Request, endpoint: str) -> tuple[str, str, str, str, str, dict]:
    """Parse and validate a chat request body.

    Returns (access_token, message, user_id, session_id, role, abac_attrs).
    Raises HTTPException(400) if required fields are missing.
    """
    access_token = _extract_bearer_token(request, endpoint)
    body = await request.json()
    message = body.get("message", "")
    user_id = body.get("user_id")
    session_id = body.get("session_id")
    role = body.get("role", "")
    abac_attrs = body.get("abac_attrs", {})
    if not all([message, user_id, session_id]):
        raise HTTPException(status_code=400, detail="message, user_id, and session_id are required")
    _validate_user_id(access_token, user_id)
    return access_token, message, user_id, session_id, role, abac_attrs


@app.post("/chat")
async def chat(request: Request):
    """Process a chat message."""
    access_token, message, user_id, session_id, role, abac_attrs = await _parse_chat_request(request, "POST /chat")
    logger.info("Chat request - user: %s, session: %s, role: %s", user_id, session_id, role)

    # Update role and ABAC attrs in session state — must use user: prefix to match
    # mcp_header_provider which reads user:role, user:abac_attrs, user:access_token
    user_state = agent.session_service.user_state.setdefault("identity-agent", {}).setdefault(user_id, {})
    if role:
        user_state["user:role"] = role
    if abac_attrs:
        user_state["user:abac_attrs"] = json.dumps(abac_attrs)

    # Collect events and extract the final text response (last text after tool calls)
    response_text = "No response generated"

    async for event in agent.chat(session_id, user_id, message, access_token):
        if isinstance(event, dict) and "error" in event:
            response_text = event["error"]
            break

        if hasattr(event, "content") and event.content:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    text = part.text.strip()
                    if text:
                        response_text = text

    logger.info("Chat response generated (length: %d)", len(response_text))
    return {"response": response_text, "session_id": session_id}


@app.post("/chat/stream")
async def chat_stream(request: Request):
    """Process a chat message with streaming response."""
    access_token, message, user_id, session_id, role, abac_attrs = await _parse_chat_request(request, "POST /chat/stream")

    # Update role and ABAC attrs in session state (same as /chat)
    user_state = agent.session_service.user_state.setdefault("identity-agent", {}).setdefault(user_id, {})
    if role:
        user_state["user:role"] = role
    if abac_attrs:
        user_state["user:abac_attrs"] = json.dumps(abac_attrs)

    async def generate():
        async for event in agent.chat(session_id, user_id, message, access_token):
            if hasattr(event, "content") and event.content:
                for part in event.content.parts:
                    if hasattr(part, "text") and part.text:
                        yield f"data: {json.dumps({'text': part.text})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "agent": "identity_aware_agent"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=ADK_SERVER_PORT)
