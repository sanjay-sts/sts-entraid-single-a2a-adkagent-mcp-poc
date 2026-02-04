"""Google ADK Agent with user context and MCP tool integration using McpToolset."""
import os
import asyncio
import logging
from pathlib import Path
from typing import Optional, AsyncGenerator, Dict
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool, ToolContext
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset, StreamableHTTPConnectionParams
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner, RunConfig
from google.adk.models.lite_llm import LiteLlm
from google.adk.agents.readonly_context import ReadonlyContext
from google.genai import types
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import json
from dotenv import load_dotenv
from litellm.exceptions import RateLimitError

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
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID")
ADK_SERVER_PORT = int(os.getenv("ADK_SERVER_PORT", 10001))

# Map CLAUDE_API_KEY to ANTHROPIC_API_KEY for LiteLLM compatibility
if os.getenv("CLAUDE_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
    os.environ["ANTHROPIC_API_KEY"] = os.getenv("CLAUDE_API_KEY")


def mcp_header_provider(readonly_context: ReadonlyContext) -> Dict[str, str]:
    """Provides Authorization header for MCP calls from session state.

    This is called by McpToolset to get dynamic headers for each request.
    The access token is stored in session state with 'user:' prefix.
    """
    if readonly_context and readonly_context.state:
        access_token = readonly_context.state.get("user:access_token", "")
        if access_token:
            logger.debug(f"MCP header_provider: Providing auth token (length: {len(access_token)})")
            return {"Authorization": f"Bearer {access_token}"}
    logger.warning("MCP header_provider: No access token found in session state")
    return {}


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
            ],
            # Dynamic header provider for per-request auth
            header_provider=mcp_header_provider,
        )

        # Create the agent with both local tools and MCP toolset
        # Using LlmAgent (recommended for LiteLLM) with Claude Sonnet 4
        self.agent = LlmAgent(
            model=LiteLlm(model="anthropic/claude-sonnet-4-20250514"),
            name="identity_aware_agent",
            description="An agent that provides user identity information and time utilities",
            instruction="""You are a helpful assistant for identity and time queries.

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
        logger.info(f"Creating session for user: {user_id}")
        logger.debug(f"User info: {user_info}")

        # Determine role first
        role = self._determine_role(user_info.get("groups", []))

        # Pass initial state at creation time - this ensures it's stored properly
        # Using user: prefix for persistence across sessions
        initial_state = {
            "user:access_token": access_token,
            "user:email": user_info.get("email", user_info.get("preferred_username", "")),
            "user:name": user_info.get("name", user_info.get("displayName", "")),
            "user:groups": user_info.get("groups", []),
            "user:role": role,
        }

        session = await self.session_service.create_session(
            app_name="identity-agent",
            user_id=user_id,
            state=initial_state,
        )

        logger.debug(f"Session created with id: {session.id}")
        logger.debug(f"User role determined: {role}")

        # Track session
        self.sessions[session.id] = {
            "user_id": user_id,
            "session": session
        }

        return session.id

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
        # Access session state via tool_context
        state = tool_context.state if tool_context else {}
        email = state.get("user:email", "")
        name = state.get("user:name", "")
        role = state.get("user:role", "none")

        logger.debug(f"get_identity_info called - email: {email}, role: {role}")

        return {
            "email": email,
            "name": name,
            "role": role,
        }

    async def check_my_permissions(self, tool_context: ToolContext) -> dict:
        """Check what permissions the current user has."""
        state = tool_context.state if tool_context else {}
        role = state.get("user:role", "none")

        logger.debug(f"check_my_permissions called - role: {role}")

        permission_map = {
            "admin": {
                "can_read_profile": True,
                "can_list_files": True,
                "can_send_email": True,
                "can_delete_resources": True,
                "can_use_time_tools": True,
            },
            "developer": {
                "can_read_profile": True,
                "can_list_files": True,
                "can_send_email": False,
                "can_delete_resources": False,
                "can_use_time_tools": False,
            },
            "viewer": {
                "can_read_profile": True,
                "can_list_files": False,
                "can_send_email": False,
                "can_delete_resources": False,
                "can_use_time_tools": False,
            },
            "none": {
                "can_read_profile": False,
                "can_list_files": False,
                "can_send_email": False,
                "can_delete_resources": False,
                "can_use_time_tools": False,
            },
        }

        return {
            "role": role,
            "permissions": permission_map.get(role, permission_map["none"]),
        }

    async def chat(self, session_id: str, user_id: str, message: str, access_token: str) -> AsyncGenerator[dict, None]:
        """Process a chat message with user context, with retry logic for rate limits."""
        logger.info(f"Chat request - session: {session_id}, user: {user_id}")
        logger.debug(f"Message: {message[:100]}...")

        # Get session
        session_info = self.sessions.get(session_id)
        if not session_info:
            logger.error(f"Session not found: {session_id}")
            yield {"error": "Session not found. Create session first."}
            return

        # Update access token in the storage directly (InMemorySessionService stores user: state separately)
        # This is critical - header_provider reads from session state during MCP calls
        # user: prefixed keys are stored in user_state with prefix stripped
        self.session_service.user_state.setdefault("identity-agent", {}).setdefault(user_id, {})["access_token"] = access_token
        logger.debug(f"Updated access token in user_state (length: {len(access_token)})")

        # Retry configuration
        max_retries = 3
        base_delay = 30  # seconds - Claude rate limits reset per minute

        for attempt in range(max_retries):
            try:
                # Run the agent
                logger.debug(f"Starting agent run (attempt {attempt + 1}/{max_retries})")
                async for event in self.runner.run_async(
                    session_id=session_id,
                    user_id=user_id,
                    new_message=types.Content(
                        role="user",
                        parts=[types.Part(text=message)]
                    ),
                    run_config=self.run_config,
                ):
                    logger.debug(f"Agent event: {type(event).__name__}")
                    yield event
                return  # Success, exit retry loop

            except RateLimitError as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (attempt + 1)  # 30s, 60s, 90s
                    logger.warning(f"Rate limited, waiting {delay}s before retry {attempt + 2}/{max_retries}...")
                    await asyncio.sleep(delay)
                else:
                    logger.error(f"Rate limit exceeded after {max_retries} retries")
                    yield {"error": f"Rate limit exceeded. Please wait a minute and try again. Details: {str(e)}"}
                    return
            except Exception as e:
                logger.error(f"Agent error: {type(e).__name__}: {str(e)}")
                yield {"error": f"Agent error: {str(e)}"}
                return


# Create FastAPI app
app = FastAPI(title="Identity-Aware ADK Agent")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"http://localhost:{os.getenv('FRONTEND_PORT', 3000)}"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global agent instance
agent = IdentityAwareAgent()


@app.post("/session")
async def create_session(request: Request):
    """Create a new session for a user."""
    logger.debug("POST /session request received")
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("Missing or invalid Authorization header in /session")
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    access_token = auth_header[7:]
    logger.debug(f"Access token received (length: {len(access_token)})")

    # Get user info from token (simplified - in production, validate the token)
    body = await request.json()
    user_id = body.get("user_id")
    user_info = body.get("user_info", {})
    logger.debug(f"Creating session for user_id: {user_id}")

    if not user_id:
        logger.error("user_id missing in request body")
        raise HTTPException(status_code=400, detail="user_id is required")

    session_id = await agent.create_session(user_id, access_token, user_info)
    logger.info(f"Session created: {session_id} for user: {user_id}")
    return {"session_id": session_id}


@app.post("/chat")
async def chat(request: Request):
    """Process a chat message."""
    logger.debug("POST /chat request received")
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        logger.warning("Missing or invalid Authorization header in /chat")
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    access_token = auth_header[7:]
    body = await request.json()

    message = body.get("message", "")
    user_id = body.get("user_id")
    session_id = body.get("session_id")
    logger.info(f"Chat request - user: {user_id}, session: {session_id}")
    logger.debug(f"Message: {message}")

    if not all([message, user_id, session_id]):
        logger.error("Missing required fields: message, user_id, or session_id")
        raise HTTPException(status_code=400, detail="message, user_id, and session_id are required")

    # Collect ALL events, then extract the FINAL text response
    # The final response is the last text content after all tool calls complete
    final_response = None
    all_texts = []

    async for event in agent.chat(session_id, user_id, message, access_token):
        logger.debug(f"Event type: {type(event).__name__}")

        # Check for error dict from our error handling
        if isinstance(event, dict) and "error" in event:
            final_response = event["error"]
            break

        if hasattr(event, "content") and event.content:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    text = part.text.strip()
                    if text:
                        all_texts.append(text)
                        logger.debug(f"Collected text (len={len(text)}): {text[:100]}...")
                        # Keep updating final_response - the last one is the actual answer
                        final_response = text

    # Use the last collected text as the final response
    # This is typically the model's final answer after processing tool results
    if final_response:
        response_text = final_response
    elif all_texts:
        # Fallback: join all texts if no clear final response
        response_text = all_texts[-1]  # Take the last one
    else:
        response_text = "No response generated"

    logger.info(f"Chat response generated (length: {len(response_text)})")
    logger.debug(f"Final Response: {response_text[:200]}...")

    return {
        "response": response_text,
        "session_id": session_id
    }


@app.post("/chat/stream")
async def chat_stream(request: Request):
    """Process a chat message with streaming response."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    access_token = auth_header[7:]
    body = await request.json()

    message = body.get("message", "")
    user_id = body.get("user_id")
    session_id = body.get("session_id")

    if not all([message, user_id, session_id]):
        raise HTTPException(status_code=400, detail="message, user_id, and session_id are required")

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
