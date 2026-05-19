"""Mocked integration tests for the ServiceNow tools.

Exercises the full Cedar pre-check + tool body + SN HTTP layer using
respx to intercept httpx calls. Tests assert both the policy decision
*and* the absence of SN calls on denial — which is the key defense
against missing the agent-side gate.

Real-tier `@slow` tests will live in this file too (see TestServiceNowReal
later in the build sequence).
"""
import json
import os
import sys
from pathlib import Path
from typing import Iterator

import httpx
import pytest
import respx

# Ensure module imports work
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mcp_server"))

# Env defaults so server.py module-load doesn't crash on missing config
os.environ.setdefault("ENTRA_CLIENT_ID", "test-client")
os.environ.setdefault("ENTRA_TENANT_ID", "test-tenant")

import server as srv  # noqa: E402 - intentional ordering after sys.path setup
from policy import AccessRequest  # noqa: E402

INSTANCE_URL = "https://test.service-now.com"


# ─── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def real_sn_client():
    """Force the global SN client to be a real (non-mock) ServiceNowClient so
    respx can intercept the httpx calls."""
    srv.init_servicenow_client(INSTANCE_URL, "admin", "test-password")
    yield
    srv.init_servicenow_client("")  # restore mock for other tests


@pytest.fixture
def permissions_toml(tmp_path, monkeypatch):
    """Create a permissions.toml the policy_evaluator can resolve roles from."""
    toml = tmp_path / "permissions.toml"
    toml.write_text("""
[group_rules.entra]
"admin-group" = "admin"
"dev-group" = "developer"
"viewer-group" = "viewer"

[users]

[defaults]
unknown_users = "none"
""")
    # Re-create the policy evaluator pointing at the test permissions.toml.
    from policy import TomlPolicyEvaluator, CedarPolicyEvaluator
    cedar_dir = ROOT / "cedar"
    new_eval = CedarPolicyEvaluator(cedar_dir, TomlPolicyEvaluator(toml))
    monkeypatch.setattr(srv, "policy_evaluator", new_eval)
    return toml


@pytest.fixture
def set_user():
    """Helper to set MCP ContextVars before calling a tool directly.

    Usage:
        set_user(email="dev@co.com", role="developer", groups=["dev-group"],
                 claims={"department": "IT"})
    """
    tokens = []

    def _set(*, email: str, role: str, groups: list[str], claims: dict | None = None,
             provider: str = "entra"):
        c = dict(claims or {})
        # detect_provider() relies on iss; default to entra
        c.setdefault("iss", "https://login.microsoftonline.com/test-tenant/v2.0")
        tokens.append(srv.current_user_email.set(email))
        tokens.append(srv.current_user_role.set(role))
        tokens.append(srv.current_user_groups.set(groups))
        tokens.append(srv.current_user_provider.set(provider))
        tokens.append(srv.current_user_token.set("test-token"))
        tokens.append(srv.current_user_claims.set(c))
        return c

    yield _set
    # Reset ContextVars to avoid bleeding between tests
    for t in reversed(tokens):
        try:
            srv.current_user_email.reset(t)
        except Exception:
            pass


def _kb(sys_id: str, title: str, dept: str) -> dict:
    return {"sys_id": sys_id, "title": title, "u_department": dept}


def _article(sys_id: str, kb_sys_id: str, short: str) -> dict:
    return {"sys_id": sys_id, "kb_knowledge_base": kb_sys_id,
            "short_description": short, "number": "KB0000001"}


# ─── Tests ─────────────────────────────────────────────────────────────


class TestServiceNowMocked:
    """End-to-end tool tests with respx-mocked HTTP and Cedar enforcement."""

    @pytest.mark.asyncio
    async def test_admin_lists_knowledge_bases(self, permissions_toml, set_user):
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={"result": [
                    _kb("kb-it", "IT KB", "IT"),
                    _kb("kb-hr", "HR KB", "HR"),
                ]})
            )
            result = await srv.list_knowledge_bases()
        assert isinstance(result, dict)
        assert "error" not in result
        assert len(result["result"]) == 2

    @pytest.mark.asyncio
    async def test_developer_lists_own_dept_kb_articles(self, permissions_toml, set_user):
        set_user(
            email="dev-it@co.com", role="developer", groups=["dev-group"],
            claims={"department": "IT"},
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={"result": [_kb("kb-it", "IT KB", "IT")]})
            )
            mock.get("/api/now/table/kb_knowledge").mock(
                return_value=httpx.Response(200, json={"result": [_article("art-1", "kb-it", "Reset VPN")]})
            )
            result = await srv.list_articles("IT KB")
        assert "error" not in result
        assert len(result["result"]) == 1

    @pytest.mark.asyncio
    async def test_developer_lists_other_dept_kb_articles_denied(self, permissions_toml, set_user):
        """Dev IT asking for HR articles → denied by Cedar; the list_articles
        endpoint must NOT be called (only the KB metadata lookup)."""
        set_user(
            email="dev-it@co.com", role="developer", groups=["dev-group"],
            claims={"department": "IT"},
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=False) as mock:
            kb_lookup = mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={"result": [_kb("kb-hr", "HR KB", "HR")]})
            )
            articles_route = mock.get("/api/now/table/kb_knowledge")
            result = await srv.list_articles("HR KB")
        assert "error" in result
        assert "TOOL_DENIAL" in result["error"]
        # KB metadata lookup happened; article fetch did NOT
        assert kb_lookup.called
        assert not articles_route.called

    @pytest.mark.asyncio
    async def test_viewer_reads_own_dept_kb_articles(self, permissions_toml, set_user):
        set_user(
            email="v-it@co.com", role="viewer", groups=["viewer-group"],
            claims={"department": "IT"},
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={"result": [_kb("kb-it", "IT KB", "IT")]})
            )
            mock.get("/api/now/table/kb_knowledge").mock(
                return_value=httpx.Response(200, json={"result": [_article("art-1", "kb-it", "Reset VPN")]})
            )
            result = await srv.list_articles("IT KB")
        assert "error" not in result

    @pytest.mark.asyncio
    async def test_viewer_blocked_from_other_dept_articles(self, permissions_toml, set_user):
        set_user(
            email="v-it@co.com", role="viewer", groups=["viewer-group"],
            claims={"department": "IT"},
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=False) as mock:
            mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={"result": [_kb("kb-hr", "HR KB", "HR")]})
            )
            articles_route = mock.get("/api/now/table/kb_knowledge")
            result = await srv.list_articles("HR KB")
        assert "error" in result and "TOOL_DENIAL" in result["error"]
        assert not articles_route.called

    @pytest.mark.asyncio
    async def test_admin_lists_incidents_no_dept_filter(self, permissions_toml, set_user):
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            mock.get("/api/now/table/incident").mock(
                return_value=httpx.Response(200, json={"result": [
                    {"sys_id": "i1", "u_department": "IT"},
                    {"sys_id": "i2", "u_department": "HR"},
                ]})
            )
            result = await srv.list_incidents()
        assert "error" not in result
        assert len(result["result"]) == 2

    @pytest.mark.asyncio
    async def test_developer_own_dept_incidents(self, permissions_toml, set_user):
        """Dev IT calls list_incidents() with no param — defaults to principal dept."""
        set_user(
            email="dev-it@co.com", role="developer", groups=["dev-group"],
            claims={"department": "IT"},
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            mock.get("/api/now/table/incident").mock(
                return_value=httpx.Response(200, json={"result": [{"sys_id": "i1"}]})
            )
            result = await srv.list_incidents()
        assert "error" not in result

    @pytest.mark.asyncio
    async def test_developer_explicit_other_dept_denied(self, permissions_toml, set_user):
        """Dev IT asks for HR incidents explicitly → Cedar denies before any SN call."""
        set_user(
            email="dev-it@co.com", role="developer", groups=["dev-group"],
            claims={"department": "IT"},
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=False) as mock:
            inc_route = mock.get("/api/now/table/incident")
            result = await srv.list_incidents(department="HR")
        assert "error" in result and "TOOL_DENIAL" in result["error"]
        assert not inc_route.called

    @pytest.mark.asyncio
    async def test_create_incident_own_dept_payload_includes_dept(
        self, permissions_toml, set_user,
    ):
        """create_incident must send u_department to ServiceNow for downstream tracking."""
        set_user(
            email="dev-it@co.com", role="developer", groups=["dev-group"],
            claims={"department": "IT"},
        )
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return httpx.Response(201, json={"result": {"sys_id": "new-1"}})

        with respx.mock(base_url=INSTANCE_URL) as mock:
            mock.post("/api/now/table/incident").mock(side_effect=capture)
            result = await srv.create_incident("Wi-Fi outage")
        assert "error" not in result
        assert captured.get("u_department") == "IT", (
            f"u_department must be on the POST body, got: {captured}"
        )

    @pytest.mark.asyncio
    async def test_update_incident_fetch_then_check_denied_cross_dept(
        self, permissions_toml, set_user,
    ):
        """Dev IT tries to update an HR incident: GET happens, Cedar denies, no PUT."""
        set_user(
            email="dev-it@co.com", role="developer", groups=["dev-group"],
            claims={"department": "IT"},
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=False) as mock:
            get_route = mock.get("/api/now/table/incident/inc-hr-1").mock(
                return_value=httpx.Response(200, json={"result": {
                    "sys_id": "inc-hr-1", "u_department": "HR"
                }})
            )
            put_route = mock.put("/api/now/table/incident/inc-hr-1")
            result = await srv.update_incident("inc-hr-1", {"state": "6"})
        assert "error" in result and "TOOL_DENIAL" in result["error"]
        assert get_route.called, "GET to fetch incident metadata MUST happen"
        assert not put_route.called, "PUT MUST NOT happen on Cedar denial"

    @pytest.mark.asyncio
    async def test_servicenow_unavailable_graceful_error(self, permissions_toml, set_user):
        """httpx ConnectError → normalised {'error': ...} dict, not a 500."""
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        with respx.mock(base_url=INSTANCE_URL) as mock:
            mock.get("/api/now/table/kb_knowledge_base").mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            result = await srv.list_knowledge_bases()
        assert "error" in result
        assert "ServiceNow unavailable" in result["error"]
