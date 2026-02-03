"""Google ADK Agent with user context and MCP tool integration."""
import os
import asyncio
import logging
from pathlib import Path
from typing import Optional, AsyncGenerator
from google.adk import Agent
from google.adk.tools import FunctionTool, ToolContext
from google.adk.tools.mcp_tool import MCPToolset, SseConnectionParams
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai import types
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import httpx
import json
from dotenv import load_dotenv

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


class IdentityAwareAgent:
    """Agent that maintains user identity context and passes tokens to MCP tools."""

    def __init__(self):
        self.session_service = InMemorySessionService()
        self.sessions = {}  # Track active sessions

        # Custom tools that access user context
        self.identity_tool = FunctionTool(func=self.get_identity_info)
        self.permission_check_tool = FunctionTool(func=self.check_my_permissions)

        # Create the agent
        self.agent = Agent(
            model="gemini-2.0-flash",
            name="identity_aware_agent",
            description="An agent that respects user identity and permissions",
            instruction="""You are a helpful assistant with access to the user's Microsoft account.
            Always check the user's permissions before attempting operations.
            If a tool fails due to permissions, explain what access is needed.

            Available tools:
            - get_identity_info: Get the current user's identity information
            - check_my_permissions: Check what permissions the current user has
            - get_user_profile: Fetch the user's Microsoft Graph profile
            - list_files: List files in user's OneDrive
            - send_email: Send an email (admin only)
            - delete_resource: Delete a resource (admin only)
            """,
            tools=[
                self.identity_tool,
                self.permission_check_tool,
            ],
        )

        self.runner = Runner(
            agent=self.agent,
            app_name="identity-agent",
            session_service=self.session_service,
        )

    async def create_session(self, user_id: str, access_token: str, user_info: dict) -> str:
        """Create a session with user identity context."""
        logger.info(f"Creating session for user: {user_id}")
        logger.debug(f"User info: {user_info}")

        session = await self.session_service.create_session(
            app_name="identity-agent",
            user_id=user_id,
        )

        # Store user context in session state with user: prefix for persistence
        session.state["user:access_token"] = access_token
        session.state["user:email"] = user_info.get("email", user_info.get("preferred_username", ""))
        session.state["user:name"] = user_info.get("name", user_info.get("displayName", ""))
        session.state["user:groups"] = user_info.get("groups", [])
        session.state["user:role"] = self._determine_role(user_info.get("groups", []))

        logger.debug(f"Session created with id: {session.id}")
        logger.debug(f"User role determined: {session.state['user:role']}")

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
        return {
            "email": tool_context.state.get("user:email"),
            "name": tool_context.state.get("user:name"),
            "role": tool_context.state.get("user:role"),
        }

    async def check_my_permissions(self, tool_context: ToolContext) -> dict:
        """Check what permissions the current user has."""
        role = tool_context.state.get("user:role", "none")

        permission_map = {
            "admin": {
                "can_read_profile": True,
                "can_list_files": True,
                "can_send_email": True,
                "can_delete_resources": True,
            },
            "developer": {
                "can_read_profile": True,
                "can_list_files": True,
                "can_send_email": False,
                "can_delete_resources": False,
            },
            "viewer": {
                "can_read_profile": True,
                "can_list_files": False,
                "can_send_email": False,
                "can_delete_resources": False,
            },
            "none": {
                "can_read_profile": False,
                "can_list_files": False,
                "can_send_email": False,
                "can_delete_resources": False,
            },
        }

        return {
            "role": role,
            "permissions": permission_map.get(role, permission_map["none"]),
        }

    async def chat(self, session_id: str, user_id: str, message: str, access_token: str) -> AsyncGenerator[dict, None]:
        """Process a chat message with user context."""
        logger.info(f"Chat request - session: {session_id}, user: {user_id}")
        logger.debug(f"Message: {message[:100]}...")

        # Get session
        session_info = self.sessions.get(session_id)
        if not session_info:
            logger.error(f"Session not found: {session_id}")
            yield {"error": "Session not found. Create session first."}
            return

        # Update access token in case it was refreshed
        session_info["session"].state["user:access_token"] = access_token
        logger.debug("Updated access token in session state")

        # Run the agent
        logger.debug("Starting agent run")
        async for event in self.runner.run_async(
            session_id=session_id,
            user_id=user_id,
            new_message=types.Content(
                role="user",
                parts=[types.Part(text=message)]
            ),
        ):
            logger.debug(f"Agent event: {type(event).__name__}")
            yield event

    async def call_mcp_tool(self, tool_name: str, arguments: dict, access_token: str) -> dict:
        """Call an MCP tool with the user's access token."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{MCP_SERVER_URL}/tools/{tool_name}",
                json=arguments,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()


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

    # Collect responses
    responses = []
    async for event in agent.chat(session_id, user_id, message, access_token):
        if hasattr(event, "content") and event.content:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    responses.append(part.text)

    response_text = " ".join(responses) if responses else "No response generated"
    logger.info(f"Chat response generated (length: {len(response_text)})")
    logger.debug(f"Response: {response_text[:200]}...")

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
