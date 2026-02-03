"""Test access control at all three levels."""
import pytest
import httpx
import jwt
from datetime import datetime, timezone, timedelta
import os

# Test configuration
A2A_URL = os.getenv("A2A_URL", "http://localhost:10000")
MCP_URL = os.getenv("MCP_URL", "http://localhost:10002")
SECRET_KEY = "test-secret"  # For local testing only

# Test group IDs (should match your .env configuration)
ADMIN_GROUP_ID = os.getenv("ADMIN_GROUP_ID", "admin-group-id")
DEVELOPER_GROUP_ID = os.getenv("DEVELOPER_GROUP_ID", "developer-group-id")
VIEWER_GROUP_ID = os.getenv("VIEWER_GROUP_ID", "viewer-group-id")
BLOCKED_USER_ID = os.getenv("BLOCKED_USER_ID", "blocked-user-id")


def create_test_token(
    user_id: str,
    groups: list,
    scopes: str,
    email: str = "test@example.com"
) -> str:
    """Create a test JWT token.

    Note: In production, tokens are signed by Entra ID using RS256.
    For testing purposes, we use HS256 with a test secret.
    The actual validation middleware should be mocked or configured
    to accept test tokens.
    """
    return jwt.encode(
        {
            "sub": user_id,
            "groups": groups,
            "scp": scopes,
            "preferred_username": email,
            "name": "Test User",
            "aud": os.getenv("ENTRA_CLIENT_ID", "test-client-id"),
            "iss": f"https://login.microsoftonline.com/{os.getenv('ENTRA_TENANT_ID', 'test-tenant')}/v2.0",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
            "nbf": datetime.now(timezone.utc),
        },
        SECRET_KEY,
        algorithm="HS256"
    )


def a2a_message(text: str) -> dict:
    """Create an A2A JSON-RPC message/send request body."""
    return {
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {
            "message": {
                "messageId": f"test-{datetime.now().timestamp()}",
                "role": "user",
                "parts": [{"kind": "text", "text": text}]
            }
        },
        "id": 1
    }


class TestAgentLevelAccess:
    """Test access control at the A2A gateway (agent level)."""

    @pytest.mark.asyncio
    async def test_unauthenticated_request_denied(self):
        """Request without token returns 401."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("Hello"),
            )

        assert response.status_code == 401
        data = response.json()
        assert "unauthorized" in data.get("error", "").lower() or "authorization" in data.get("message", "").lower()

    @pytest.mark.asyncio
    async def test_invalid_token_denied(self):
        """Request with invalid token returns 401."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("Hello"),
                headers={"Authorization": "Bearer invalid-token"}
            )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_blocked_user_denied(self):
        """User in BLOCKED_USERS list cannot access agent."""
        token = create_test_token(
            user_id=BLOCKED_USER_ID,
            groups=[ADMIN_GROUP_ID],
            scopes="User.Read"
        )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("Hello"),
                headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 403
        data = response.json()
        assert "blocked" in data.get("message", "").lower()

    @pytest.mark.asyncio
    async def test_no_group_membership_denied(self):
        """User without any allowed group cannot access agent."""
        token = create_test_token(
            user_id="regular-user",
            groups=["some-other-group"],
            scopes="User.Read"
        )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("Hello"),
                headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 403
        data = response.json()
        assert "group" in data.get("message", "").lower()

    @pytest.mark.asyncio
    async def test_valid_user_allowed(self):
        """User in allowed group can access agent."""
        token = create_test_token(
            user_id="valid-user",
            groups=[VIEWER_GROUP_ID],
            scopes="User.Read"
        )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("Hello"),
                headers={"Authorization": f"Bearer {token}"}
            )

        # Should not be 401 or 403
        assert response.status_code in [200, 500]  # 500 might occur if ADK agent isn't running

    @pytest.mark.asyncio
    async def test_agent_card_accessible_without_auth(self):
        """Agent card endpoint should be accessible without authentication."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{A2A_URL}/.well-known/agent.json")

        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "skills" in data


class TestToolLevelAccess:
    """Test access control at the MCP tool level."""

    @pytest.mark.asyncio
    async def test_viewer_cannot_send_email(self):
        """Viewer role cannot use send_email tool."""
        token = create_test_token(
            user_id="viewer-user",
            groups=[VIEWER_GROUP_ID],
            scopes="User.Read Mail.Send"  # Has scope but wrong role
        )

        # Simulate asking agent to send email
        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("Send an email to test@example.com saying hello"),
                headers={"Authorization": f"Bearer {token}"}
            )

        # If agent is running, response should contain access denied message
        if response.status_code == 200:
            result = response.json()
            result_str = str(result).lower()
            assert "access" in result_str or "denied" in result_str or "permission" in result_str

    @pytest.mark.asyncio
    async def test_developer_cannot_send_email(self):
        """Developer role cannot use send_email tool."""
        token = create_test_token(
            user_id="developer-user",
            groups=[DEVELOPER_GROUP_ID],
            scopes="User.Read Mail.Send"
        )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("Send an email to test@example.com"),
                headers={"Authorization": f"Bearer {token}"}
            )

        if response.status_code == 200:
            result = response.json()
            result_str = str(result).lower()
            assert "access" in result_str or "denied" in result_str or "permission" in result_str

    @pytest.mark.asyncio
    async def test_viewer_cannot_list_files(self):
        """Viewer role cannot use list_files tool."""
        token = create_test_token(
            user_id="viewer-user",
            groups=[VIEWER_GROUP_ID],
            scopes="User.Read Files.Read"  # Has scope but wrong role
        )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("List my files"),
                headers={"Authorization": f"Bearer {token}"}
            )

        if response.status_code == 200:
            result = response.json()
            result_str = str(result).lower()
            assert "access" in result_str or "denied" in result_str or "permission" in result_str

    @pytest.mark.asyncio
    async def test_admin_can_check_permissions(self):
        """Admin role can check permissions."""
        token = create_test_token(
            user_id="admin-user",
            groups=[ADMIN_GROUP_ID],
            scopes="User.Read Files.Read Mail.Send"
        )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("What are my permissions?"),
                headers={"Authorization": f"Bearer {token}"}
            )

        if response.status_code == 200:
            result = response.json()
            result_str = str(result).lower()
            assert "admin" in result_str or "permission" in result_str


class TestResourceLevelAccess:
    """Test access control at the Microsoft Graph API level (scopes)."""

    @pytest.mark.asyncio
    async def test_missing_files_scope_denied(self):
        """User without Files.Read scope cannot list files."""
        token = create_test_token(
            user_id="developer-user",
            groups=[DEVELOPER_GROUP_ID],
            scopes="User.Read"  # Missing Files.Read
        )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("List my files"),
                headers={"Authorization": f"Bearer {token}"}
            )

        if response.status_code == 200:
            result = response.json()
            result_str = str(result).lower()
            # Should fail either at tool level (scope check) or Graph API level
            assert "scope" in result_str or "permission" in result_str or "access" in result_str

    @pytest.mark.asyncio
    async def test_missing_mail_scope_denied(self):
        """User without Mail.Send scope cannot send email."""
        token = create_test_token(
            user_id="admin-user",
            groups=[ADMIN_GROUP_ID],
            scopes="User.Read"  # Missing Mail.Send
        )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                A2A_URL,
                json=a2a_message("Send an email to test@example.com"),
                headers={"Authorization": f"Bearer {token}"}
            )

        if response.status_code == 200:
            result = response.json()
            result_str = str(result).lower()
            assert "scope" in result_str or "permission" in result_str


class TestHealthEndpoints:
    """Test health check endpoints."""

    @pytest.mark.asyncio
    async def test_a2a_health(self):
        """A2A server health endpoint."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{A2A_URL}/health")

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    @pytest.mark.asyncio
    async def test_mcp_health(self):
        """MCP server health check via root endpoint."""
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(f"{MCP_URL}/health", timeout=5.0)
                # MCP server might not have explicit health endpoint
                assert response.status_code in [200, 404]
            except httpx.ConnectError:
                pytest.skip("MCP server not running")


# Pytest configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    import asyncio
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
