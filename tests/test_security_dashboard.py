"""Security Dashboard tests with real Entra ID tokens.

These tests validate the three-tier access control system (Agent, Tool, Resource)
using pre-acquired Entra ID tokens. Tests skip gracefully when tokens are absent.

Run:
    uv run pytest tests/test_security_dashboard.py -v
    uv run pytest tests/test_security_dashboard.py -m "not slow" -v   # skip LLM tests
"""
import pytest
import httpx
import time
from datetime import datetime, timezone


# =============================================================================
# Class 1: Health & Discovery (no auth needed)
# =============================================================================

@pytest.mark.usefixtures("require_services")
class TestHealthAndDiscovery:
    """Verify health endpoints and agent card discovery."""

    @pytest.mark.asyncio
    async def test_a2a_health_returns_healthy(self, a2a_url):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{a2a_url}/health", timeout=10.0)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "healthy"

    @pytest.mark.asyncio
    async def test_adk_health_returns_healthy(self, adk_url):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{adk_url}/health", timeout=10.0)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "healthy"

    @pytest.mark.asyncio
    async def test_agent_card_new_endpoint(self, a2a_url):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{a2a_url}/.well-known/agent-card.json", timeout=10.0)
        assert resp.status_code == 200
        card = resp.json()
        assert "name" in card
        assert "skills" in card
        assert card.get("capabilities", {}).get("streaming") is True
        assert len(card.get("skills", [])) == 7

    @pytest.mark.asyncio
    async def test_agent_card_legacy_endpoint(self, a2a_url):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{a2a_url}/.well-known/agent.json", timeout=10.0)
        assert resp.status_code == 200
        card = resp.json()
        assert "name" in card

    @pytest.mark.asyncio
    async def test_agent_card_skills_complete(self, a2a_url):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{a2a_url}/.well-known/agent-card.json", timeout=10.0)
        card = resp.json()
        skill_ids = {s["id"] for s in card.get("skills", [])}
        expected = {
            "identity_info", "permissions", "graph_profile",
            "onedrive_files", "time_current", "time_convert", "time_difference",
        }
        assert expected == skill_ids, f"Missing: {expected - skill_ids}, Extra: {skill_ids - expected}"


# =============================================================================
# Class 2: Agent-Level Access Control
# =============================================================================

@pytest.mark.usefixtures("require_services")
class TestAgentLevelAccessControl:
    """Validate agent-level (A2A gateway) auth enforcement with real tokens."""

    @pytest.mark.asyncio
    async def test_no_token_returns_401_with_denial_fields(self, a2a_url, make_a2a_message):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url, json=make_a2a_message("Hello"), timeout=10.0,
            )
        assert resp.status_code == 401
        data = resp.json()
        assert data.get("denial_level") == "agent"
        assert data.get("denial_reason") == "missing_token"

    @pytest.mark.asyncio
    async def test_invalid_format_returns_401(self, a2a_url, make_a2a_message):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("Hello"),
                headers={"Authorization": "Basic abc123"},
                timeout=10.0,
            )
        assert resp.status_code == 401
        data = resp.json()
        assert data.get("denial_reason") == "invalid_format"

    @pytest.mark.asyncio
    async def test_garbage_token_returns_401(self, a2a_url, make_a2a_message):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("Hello"),
                headers={"Authorization": "Bearer not-a-real-jwt-token"},
                timeout=10.0,
            )
        assert resp.status_code == 401
        data = resp.json()
        assert data.get("denial_reason") == "validation_failed"

    @pytest.mark.asyncio
    async def test_nogroup_user_returns_403(self, a2a_url, make_a2a_message, real_nogroup_token):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("Hello"),
                headers={"Authorization": f"Bearer {real_nogroup_token}"},
                timeout=10.0,
            )
        assert resp.status_code == 403
        data = resp.json()
        assert data.get("denial_reason") == "no_group_membership"

    @pytest.mark.asyncio
    async def test_admin_token_accepted(self, a2a_url, real_admin_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=10.0,
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_developer_token_accepted(self, a2a_url, real_developer_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_developer_token}"},
                timeout=10.0,
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_viewer_token_accepted(self, a2a_url, real_viewer_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_viewer_token}"},
                timeout=10.0,
            )
        assert resp.status_code == 200


# =============================================================================
# Class 3: /me Endpoint
# =============================================================================

@pytest.mark.usefixtures("require_services")
class TestMeEndpoint:
    """Validate the GET /me endpoint returns correct security context."""

    @pytest.mark.asyncio
    async def test_me_no_token_returns_401(self, a2a_url):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{a2a_url}/me", timeout=10.0)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_me_admin_role_and_permissions(self, a2a_url, real_admin_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=10.0,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["security"]["role"] == "admin"
        perms = data["permissions"]
        for tool_name in [
            "get_user_profile", "list_files", "send_email", "delete_resource",
            "get_current_time", "convert_timezone", "get_time_difference",
        ]:
            assert perms.get(tool_name) is True, f"Admin should have {tool_name}=true"

    @pytest.mark.asyncio
    async def test_me_developer_role_and_permissions(self, a2a_url, real_developer_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_developer_token}"},
                timeout=10.0,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["security"]["role"] == "developer"
        perms = data["permissions"]
        assert perms["get_user_profile"] is True
        assert perms["list_files"] is True
        assert perms["send_email"] is False
        assert perms["delete_resource"] is False
        assert perms["get_current_time"] is False
        assert perms["convert_timezone"] is False
        assert perms["get_time_difference"] is False

    @pytest.mark.asyncio
    async def test_me_viewer_role_and_permissions(self, a2a_url, real_viewer_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_viewer_token}"},
                timeout=10.0,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["security"]["role"] == "viewer"
        perms = data["permissions"]
        assert perms["get_user_profile"] is True
        assert perms["list_files"] is False
        assert perms["send_email"] is False
        assert perms["delete_resource"] is False
        assert perms["get_current_time"] is False

    @pytest.mark.asyncio
    async def test_me_response_structure_complete(self, a2a_url, real_admin_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=10.0,
            )
        data = resp.json()
        # Top-level sections
        assert "user" in data
        assert "security" in data
        assert "permissions" in data
        assert "tool_scopes" in data
        # user fields
        assert isinstance(data["user"].get("email"), str)
        # security fields
        sec = data["security"]
        assert isinstance(sec.get("role"), str)
        assert isinstance(sec.get("groups"), list)
        assert isinstance(sec.get("token_scopes"), list)
        assert isinstance(sec.get("token_expiry"), (int, float))
        # permissions is dict of bool
        assert all(isinstance(v, bool) for v in data["permissions"].values())
        # tool_scopes is dict of lists
        assert all(isinstance(v, list) for v in data["tool_scopes"].values())

    @pytest.mark.asyncio
    async def test_me_group_names_mapping(self, a2a_url, real_admin_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=10.0,
            )
        data = resp.json()
        group_names = data["security"].get("group_names", {})
        valid_roles = {"admin", "developer", "viewer"}
        for gid, role_name in group_names.items():
            assert role_name in valid_roles, f"Unexpected role name '{role_name}' for group {gid}"

    @pytest.mark.asyncio
    async def test_me_token_expiry_in_future(self, a2a_url, real_admin_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=10.0,
            )
        data = resp.json()
        expiry = data["security"].get("token_expiry", 0)
        now = datetime.now(timezone.utc).timestamp()
        assert expiry > now, (
            f"Token expired! expiry={expiry}, now={now:.0f}. "
            "Re-acquire tokens via Token Inspector."
        )


# =============================================================================
# Class 4: Tool-Level Access Control (LLM pipeline – slow)
# =============================================================================

def _assert_denial(text: str, context: str):
    """Assert that the response text contains denial indicators."""
    lower = text.lower()
    denial_indicators = [
        "[tool_denial]", "[scope_denial]",
        "access denied", "cannot use", "not authorized", "denied",
        "don't have permission", "do not have permission",
        "not have the required", "insufficient",
        "not allowed", "permission denied", "lack",
    ]
    assert any(ind in lower for ind in denial_indicators), (
        f"Expected denial in {context} response but got: {text[:300]}"
    )


def _assert_success(text: str, context: str):
    """Assert that the response text does NOT contain denial indicators."""
    lower = text.lower()
    hard_denials = ["[tool_denial]", "[scope_denial]"]
    assert not any(d in lower for d in hard_denials), (
        f"Unexpected denial tag in {context} response: {text[:300]}"
    )


@pytest.mark.usefixtures("require_services")
@pytest.mark.slow
class TestToolLevelAccessControl:
    """Full pipeline tests: A2A -> ADK -> MCP -> tool execution.

    Each test sends a prompt through the LLM and takes 10-30s.
    """

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_admin_get_user_profile(
        self, a2a_url, real_admin_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("What is my email address?"),
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        _assert_success(text, "admin get_user_profile")

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_admin_get_current_time(
        self, a2a_url, real_admin_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("What time is it right now?"),
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        _assert_success(text, "admin get_current_time")

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_developer_get_user_profile(
        self, a2a_url, real_developer_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("What is my email address?"),
                headers={"Authorization": f"Bearer {real_developer_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        _assert_success(text, "developer get_user_profile")

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_developer_time_tool_denied(
        self, a2a_url, real_developer_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("What time is it in Tokyo right now? Use the time tool."),
                headers={"Authorization": f"Bearer {real_developer_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        _assert_denial(text, "developer time tool")

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_viewer_get_user_profile(
        self, a2a_url, real_viewer_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("What is my email address?"),
                headers={"Authorization": f"Bearer {real_viewer_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        _assert_success(text, "viewer get_user_profile")

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_viewer_list_files_denied(
        self, a2a_url, real_viewer_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("List my OneDrive files using the list_files tool."),
                headers={"Authorization": f"Bearer {real_viewer_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        _assert_denial(text, "viewer list_files")

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_viewer_send_email_denied(
        self, a2a_url, real_viewer_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message(
                    "Send an email to test@example.com with subject 'Test' and body 'Hello'."
                ),
                headers={"Authorization": f"Bearer {real_viewer_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        _assert_denial(text, "viewer send_email")

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_developer_send_email_denied(
        self, a2a_url, real_developer_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message(
                    "Send an email to test@example.com with subject 'Test' and body 'Hello'."
                ),
                headers={"Authorization": f"Bearer {real_developer_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        _assert_denial(text, "developer send_email")


# =============================================================================
# Class 5: Denial Classification
# =============================================================================

@pytest.mark.usefixtures("require_services")
class TestDenialClassification:
    """Verify denial response fields and classification markers."""

    @pytest.mark.asyncio
    async def test_agent_denial_fields_on_401(self, a2a_url, make_a2a_message):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url, json=make_a2a_message("Hello"), timeout=10.0,
            )
        assert resp.status_code == 401
        data = resp.json()
        assert "denial_level" in data
        assert "denial_reason" in data
        assert data["denial_level"] == "agent"

    @pytest.mark.asyncio
    async def test_agent_denial_fields_on_403(
        self, a2a_url, make_a2a_message, real_nogroup_token,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("Hello"),
                headers={"Authorization": f"Bearer {real_nogroup_token}"},
                timeout=10.0,
            )
        assert resp.status_code == 403
        data = resp.json()
        assert data["denial_level"] == "agent"
        assert data["denial_reason"] == "no_group_membership"

    @pytest.mark.asyncio
    @pytest.mark.slow
    @pytest.mark.timeout(120)
    async def test_tool_denial_contains_prefix(
        self, a2a_url, real_viewer_token, make_a2a_message, extract_agent_text,
    ):
        """Tool denial via LLM should contain [TOOL_DENIAL] or denial language."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("List my OneDrive files using the list_files tool."),
                headers={"Authorization": f"Bearer {real_viewer_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        _assert_denial(text, "tool denial prefix")

    @pytest.mark.asyncio
    async def test_all_denial_reasons_documented(self, a2a_url, make_a2a_message):
        """Verify each documented denial reason returns correctly."""
        cases = [
            (None, "missing_token"),
            ("Basic abc", "invalid_format"),
            ("Bearer garbage-not-jwt", "validation_failed"),
        ]
        for auth_value, expected_reason in cases:
            headers = {}
            if auth_value:
                headers["Authorization"] = auth_value
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    a2a_url,
                    json=make_a2a_message("test"),
                    headers=headers,
                    timeout=10.0,
                )
            assert resp.status_code == 401, f"Expected 401 for {expected_reason}"
            data = resp.json()
            assert data.get("denial_reason") == expected_reason, (
                f"Expected denial_reason={expected_reason}, got {data.get('denial_reason')}"
            )


# =============================================================================
# Class 6: Role Hierarchy
# =============================================================================

@pytest.mark.usefixtures("require_services")
class TestRoleHierarchy:
    """Verify role determination and token metadata."""

    @pytest.mark.asyncio
    async def test_multi_group_user_gets_highest_role(self, a2a_url, real_admin_token):
        """Admin token (user may be in multiple groups) resolves to admin."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=10.0,
            )
        data = resp.json()
        assert data["security"]["role"] == "admin"

    @pytest.mark.asyncio
    async def test_admin_user_has_groups_in_response(self, a2a_url, real_admin_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=10.0,
            )
        data = resp.json()
        groups = data["security"].get("groups", [])
        assert len(groups) > 0, "Admin user should have at least one group"

    @pytest.mark.asyncio
    async def test_issuer_is_valid_entra_id(self, a2a_url, real_admin_token):
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{a2a_url}/me",
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=10.0,
            )
        data = resp.json()
        issuer = data["security"].get("issuer", "")
        assert (
            "login.microsoftonline.com" in issuer
            or "sts.windows.net" in issuer
        ), f"Unexpected issuer: {issuer}"


# =============================================================================
# Class 7: Cross-Service Integration (LLM pipeline – slow)
# =============================================================================

@pytest.mark.usefixtures("require_services")
@pytest.mark.slow
class TestCrossServiceIntegration:
    """End-to-end tests through the full A2A -> ADK -> MCP pipeline."""

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_full_pipeline_identity_query(
        self, a2a_url, real_admin_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("Who am I? Tell me my name and email."),
                headers={"Authorization": f"Bearer {real_admin_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        assert len(text) > 10, f"Expected meaningful response, got: {text!r}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_full_pipeline_permission_query(
        self, a2a_url, real_developer_token, make_a2a_message, extract_agent_text,
    ):
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                a2a_url,
                json=make_a2a_message("What are my permissions? What tools can I use?"),
                headers={"Authorization": f"Bearer {real_developer_token}"},
                timeout=90.0,
            )
        assert resp.status_code == 200
        text = extract_agent_text(resp.json())
        lower = text.lower()
        assert "permission" in lower or "tool" in lower or "access" in lower, (
            f"Expected permissions info, got: {text[:300]}"
        )

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)
    async def test_second_message_reuses_session(
        self, a2a_url, real_admin_token, make_a2a_message, extract_agent_text,
    ):
        """Two consecutive messages with the same token both succeed (session reuse)."""
        headers = {"Authorization": f"Bearer {real_admin_token}"}

        async with httpx.AsyncClient() as client:
            resp1 = await client.post(
                a2a_url,
                json=make_a2a_message("Hello, who am I?"),
                headers=headers,
                timeout=90.0,
            )
        assert resp1.status_code == 200
        text1 = extract_agent_text(resp1.json())
        assert len(text1) > 5

        async with httpx.AsyncClient() as client:
            resp2 = await client.post(
                a2a_url,
                json=make_a2a_message("What did I just ask you?"),
                headers=headers,
                timeout=90.0,
            )
        assert resp2.status_code == 200
        text2 = extract_agent_text(resp2.json())
        assert len(text2) > 5
