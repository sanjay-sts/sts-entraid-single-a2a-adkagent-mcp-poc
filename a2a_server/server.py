"""A2A Server acting as authenticated gateway to the ADK agent.

Implements the A2A Protocol (https://github.com/a2aproject/A2A) using plain FastAPI.
"""
import os
import jwt
from typing import Optional
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID")
ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID")
JWKS_URI = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/discovery/v2.0/keys"
ISSUER = f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0"
A2A_SERVER_PORT = int(os.getenv("A2A_SERVER_PORT", 10000))
ADK_SERVER_URL = f"http://localhost:{os.getenv('ADK_SERVER_PORT', 10001)}"
FRONTEND_PORT = os.getenv("FRONTEND_PORT", 3000)

# Access control configuration
BLOCKED_USERS = [u.strip() for u in os.getenv("BLOCKED_USERS", "").split(",") if u.strip()]
ALLOWED_GROUPS = [
    os.getenv("ADMIN_GROUP_ID"),
    os.getenv("DEVELOPER_GROUP_ID"),
    os.getenv("VIEWER_GROUP_ID"),
]
# Filter out None values
ALLOWED_GROUPS = [g for g in ALLOWED_GROUPS if g]


# Define the Agent Card (A2A Protocol standard)
AGENT_CARD = {
    "name": "Identity-Aware AI Agent",
    "description": "An AI agent that respects user identity and enforces permissions at multiple levels.",
    "url": f"http://localhost:{A2A_SERVER_PORT}/",
    "version": "1.0.0",
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain", "application/json"],
    "capabilities": {"streaming": False},
    "skills": [
        {
            "id": "user_profile",
            "name": "User Profile Access",
            "description": "Access user's Microsoft profile information",
            "tags": ["identity", "profile"],
            "examples": ["What's my email?", "Show my profile"],
        },
        {
            "id": "file_management",
            "name": "File Management",
            "description": "List and manage user's OneDrive files",
            "tags": ["files", "onedrive"],
            "examples": ["List my files", "What's in my Documents folder?"],
        },
        {
            "id": "email",
            "name": "Email Operations",
            "description": "Send emails on behalf of the user (admin only)",
            "tags": ["email", "communication"],
            "examples": ["Send an email to team@company.com"],
        },
    ],
    "securitySchemes": {
        "entra_oauth": {
            "type": "oauth2",
            "description": "Microsoft Entra ID OAuth 2.0 Authorization Code Flow",
            "flows": {
                "authorizationCode": {
                    "authorizationUrl": f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/oauth2/v2.0/authorize",
                    "tokenUrl": f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/oauth2/v2.0/token",
                    "scopes": {
                        "openid": "Sign in",
                        "profile": "View basic profile",
                        "User.Read": "Read user profile",
                        "Files.Read": "Read files",
                        "Mail.Send": "Send email",
                    },
                },
            },
        },
    },
    "security": [{"entra_oauth": ["openid", "profile", "User.Read"]}],
}


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
        """Clear JWKS cache to force refresh."""
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
            # Key not found, try refreshing JWKS cache
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


# Create FastAPI app
app = FastAPI(title="A2A Identity Gateway")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"http://localhost:{FRONTEND_PORT}", "http://localhost:10003"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# User sessions mapping (user_id -> session_id)
user_sessions = {}


# Authentication middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Validate tokens and enforce agent-level access control."""

    # Allow Agent Card discovery without auth
    if request.url.path in [
        "/.well-known/agent.json",
        "/.well-known/agent-card.json",
        "/docs",
        "/openapi.json",
        "/health"
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

        # AGENT-LEVEL ACCESS CONTROL
        user_id = claims.get("sub", "")
        user_groups = claims.get("groups", [])

        # Check 1: Is user explicitly blocked?
        if user_id in BLOCKED_USERS:
            return Response(
                status_code=403,
                content='{"error": "access_denied", "message": "Your account has been blocked from using this agent"}',
                media_type="application/json",
            )

        # Check 2: Does user belong to any allowed group?
        if ALLOWED_GROUPS and not any(g in ALLOWED_GROUPS for g in user_groups):
            return Response(
                status_code=403,
                content='{"error": "access_denied", "message": "You are not a member of any authorized group"}',
                media_type="application/json",
            )

        # Store validated claims in request state
        request.state.user_claims = claims
        request.state.access_token = token

    except jwt.ExpiredSignatureError:
        return Response(
            status_code=401,
            content='{"error": "token_expired", "message": "Token has expired"}',
            media_type="application/json",
        )
    except jwt.InvalidTokenError as e:
        return Response(
            status_code=401,
            content=f'{{"error": "invalid_token", "message": "Token validation failed: {str(e)}"}}',
            media_type="application/json",
        )
    except Exception as e:
        return Response(
            status_code=401,
            content=f'{{"error": "authentication_failed", "message": "Authentication failed: {str(e)}"}}',
            media_type="application/json",
        )

    return await call_next(request)


async def ensure_session(user_claims: dict, access_token: str) -> str:
    """Ensure a session exists for the user, creating one if necessary."""
    user_id = user_claims.get("sub")

    if user_id not in user_sessions:
        # Create session in ADK agent
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{ADK_SERVER_URL}/session",
                json={
                    "user_id": user_id,
                    "user_info": {
                        "email": user_claims.get("preferred_username", ""),
                        "name": user_claims.get("name", ""),
                        "groups": user_claims.get("groups", []),
                    }
                },
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
            user_sessions[user_id] = data["session_id"]

    return user_sessions[user_id]


# A2A message handler (JSON-RPC endpoint)
@app.post("/")
async def handle_a2a_request(request: Request):
    """Handle A2A JSON-RPC requests."""
    user_claims = request.state.user_claims
    access_token = request.state.access_token

    body = await request.json()

    # Handle JSON-RPC method
    method = body.get("method", "")
    params = body.get("params", {})
    request_id = body.get("id", 1)

    if method == "message/send":
        try:
            # Ensure session exists
            session_id = await ensure_session(user_claims, access_token)

            # Extract message text
            message = params.get("message", {})
            parts = message.get("parts", [])
            text_parts = [p.get("text", "") for p in parts if p.get("kind") == "text"]
            message_text = " ".join(text_parts)

            if not message_text:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "No text content in message"}
                }

            # Forward to ADK agent
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{ADK_SERVER_URL}/chat",
                    json={
                        "message": message_text,
                        "user_id": user_claims.get("sub"),
                        "session_id": session_id,
                    },
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=60.0
                )
                response.raise_for_status()
                data = response.json()

            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "message": {
                        "messageId": f"resp-{request_id}",
                        "role": "agent",
                        "parts": [{"kind": "text", "text": data.get("response", "")}]
                    }
                }
            }

        except httpx.HTTPStatusError as e:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": f"Agent error: {e.response.text}"}
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": str(e)}
            }

    elif method == "agent/card":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": AGENT_CARD
        }

    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}
        }


# Agent Card endpoint (A2A discovery)
@app.get("/.well-known/agent.json")
async def get_agent_card():
    """Return the Agent Card for A2A discovery."""
    return AGENT_CARD


# Health check endpoint
@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "a2a-gateway"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=A2A_SERVER_PORT)
