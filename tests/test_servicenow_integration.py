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
    # (ContextVar, token) pairs so the teardown resets each var with its own token.
    reset_pairs: list = []

    def _set(*, email: str, role: str, groups: list[str], claims: dict | None = None,
             provider: str = "entra"):
        c = dict(claims or {})
        # detect_provider() relies on iss; default to entra
        c.setdefault("iss", "https://login.microsoftonline.com/test-tenant/v2.0")
        for var, value in (
            (srv.current_user_email, email),
            (srv.current_user_role, role),
            (srv.current_user_groups, groups),
            (srv.current_user_provider, provider),
            (srv.current_user_token, "test-token"),
            (srv.current_user_claims, c),
        ):
            reset_pairs.append((var, var.set(value)))
        return c

    yield _set
    # Reset ContextVars in reverse order to avoid bleeding between tests
    for var, token in reversed(reset_pairs):
        try:
            var.reset(token)
        except ValueError:
            # Token created in a different context (e.g. across asyncio tasks).
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

    @pytest.mark.asyncio
    async def test_list_articles_kb_missing_u_department_is_config_error(
        self, permissions_toml, set_user,
    ):
        """KB exists but has no u_department populated → CONFIG_ERROR for
        non-admin (admin still bypasses via RBAC). Distinguishes a SN admin
        config mistake from an actual access denial."""
        set_user(
            email="dev-it@co.com", role="developer", groups=["dev-group"],
            claims={"department": "IT"},
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=False) as mock:
            mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={
                    "result": [{"sys_id": "kb-x", "title": "X KB", "u_department": ""}]
                })
            )
            articles_route = mock.get("/api/now/table/kb_knowledge")
            result = await srv.list_articles("X KB")
        assert "error" in result
        assert "CONFIG_ERROR" in result["error"], (
            f"misconfigured KB must surface as CONFIG_ERROR, got: {result['error']}"
        )
        assert not articles_route.called

    @pytest.mark.asyncio
    async def test_list_articles_kb_missing_u_department_admin_bypass(
        self, permissions_toml, set_user,
    ):
        """Same misconfigured KB: admin still succeeds (admin permit has no
        dept condition)."""
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={
                    "result": [{"sys_id": "kb-x", "title": "X KB"}]  # no u_department
                })
            )
            mock.get("/api/now/table/kb_knowledge").mock(
                return_value=httpx.Response(200, json={"result": []})
            )
            result = await srv.list_articles("X KB")
        assert "error" not in result

    def test_init_servicenow_client_raises_on_partial_config(self):
        """instance_url set but credentials empty → RuntimeError, not silent
        mock fallback. Misconfiguration must fail loudly at startup."""
        from servicenow import init_servicenow_client

        with pytest.raises(RuntimeError, match="ServiceNow misconfigured"):
            init_servicenow_client(
                instance_url="https://devXXXXX.service-now.com",
                api_user="",
                api_password="",
            )
        # Restore mock for subsequent tests (the autouse fixture only restores
        # *after* the test body, but the raise here aborts before any client
        # is reset).
        srv.init_servicenow_client("")

    @pytest.mark.asyncio
    async def test_update_incident_distinguishes_sn_error_from_404(
        self, permissions_toml, set_user,
    ):
        """A SN connect failure during the fetch-then-check phase must NOT be
        reported as `incident not found` (TOOL_DENIAL). It's a TOOL_ERROR so the
        audit trail and the LLM can distinguish availability from authorization."""
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=False) as mock:
            mock.get("/api/now/table/incident/inc-x").mock(
                side_effect=httpx.ConnectError("connection refused")
            )
            put_route = mock.put("/api/now/table/incident/inc-x")
            result = await srv.update_incident("inc-x", {"state": "6"})
        assert "error" in result
        assert "TOOL_ERROR" in result["error"], (
            f"SN failure must surface as TOOL_ERROR, not TOOL_DENIAL; got: {result['error']}"
        )
        assert "ServiceNow unavailable" in result["error"]
        assert not put_route.called


class _StubExchanger:
    """Stand-in OBO exchanger that always yields a fixed user token."""

    async def get_sn_token(self, assertion: str) -> str:
        return "fake-sn-token"


class TestServiceNowOBOSeam:
    """The OBO token seam (hybrid model, 2026-05-20 spec).

    When an exchanger yields a user token, the SN client must send
    `Authorization: Bearer <token>` so ServiceNow can apply that user's ACLs.
    Otherwise it falls back to the service-account Basic auth. Real per-user
    enforcement is verified against a live instance once SN is provisioned;
    here we assert only that the token is threaded correctly.
    """

    @pytest.mark.asyncio
    async def test_obo_token_used_when_entra_and_configured(
        self, permissions_toml, set_user, monkeypatch,
    ):
        monkeypatch.setattr(srv, "get_sn_obo_exchanger", lambda: _StubExchanger())
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            route = mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={"result": []})
            )
            await srv.list_knowledge_bases()
        assert route.calls.last.request.headers.get("Authorization") == "Bearer fake-sn-token"

    @pytest.mark.asyncio
    async def test_obo_falls_back_to_basic_when_exchanger_absent(
        self, permissions_toml, set_user, monkeypatch,
    ):
        monkeypatch.setattr(srv, "get_sn_obo_exchanger", lambda: None)
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            route = mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={"result": []})
            )
            await srv.list_knowledge_bases()
        auth = route.calls.last.request.headers.get("Authorization", "")
        assert auth.startswith("Basic "), f"expected service-account Basic, got: {auth!r}"

    @pytest.mark.asyncio
    async def test_obo_skipped_for_non_entra_user(
        self, permissions_toml, set_user, monkeypatch,
    ):
        """OBO is Entra-only: a Cognito user must use Basic even when an
        exchanger is present — the Entra guard short-circuits first."""
        monkeypatch.setattr(srv, "get_sn_obo_exchanger", lambda: _StubExchanger())
        set_user(
            email="dev@co.com", role="admin", groups=["admin-group"],
            provider="cognito",
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            route = mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={"result": []})
            )
            await srv.list_knowledge_bases()
        auth = route.calls.last.request.headers.get("Authorization", "")
        assert auth.startswith("Basic "), f"non-Entra must use Basic, got: {auth!r}"

    @pytest.mark.asyncio
    async def test_obo_threaded_through_both_list_articles_calls(
        self, permissions_toml, set_user, monkeypatch,
    ):
        """list_articles makes two SN calls (KB metadata, then articles); both
        must carry the user's OBO token."""
        monkeypatch.setattr(srv, "get_sn_obo_exchanger", lambda: _StubExchanger())
        set_user(
            email="dev-it@co.com", role="developer", groups=["dev-group"],
            claims={"department": "IT"},
        )
        with respx.mock(base_url=INSTANCE_URL, assert_all_called=True) as mock:
            kb_route = mock.get("/api/now/table/kb_knowledge_base").mock(
                return_value=httpx.Response(200, json={"result": [_kb("kb-it", "IT KB", "IT")]})
            )
            art_route = mock.get("/api/now/table/kb_knowledge").mock(
                return_value=httpx.Response(200, json={"result": [_article("a1", "kb-it", "VPN")]})
            )
            result = await srv.list_articles("IT KB")
        assert "error" not in result
        assert kb_route.calls.last.request.headers.get("Authorization") == "Bearer fake-sn-token"
        assert art_route.calls.last.request.headers.get("Authorization") == "Bearer fake-sn-token"


# ─── Real-tier @slow tests (KB-only, read-only) ─────────────────────────
#
# Gated on TEST_SERVICENOW_INSTANCE env var. Skip cleanly when not set.
# Per the 2026-05-19 spec: incident u_department field is deferred until
# the OBO follow-up, so real-tier covers ONLY KB read tools + auth failure.
# Use real admin credentials in env; admin permits are not dept-conditional.


REAL_SN_INSTANCE = os.getenv("TEST_SERVICENOW_INSTANCE", "")
REAL_SN_USER = os.getenv("TEST_SERVICENOW_USER", "")
REAL_SN_PASS = os.getenv("TEST_SERVICENOW_PASS", "")

real_sn_required = pytest.mark.skipif(
    not (REAL_SN_INSTANCE and REAL_SN_USER and REAL_SN_PASS),
    reason="TEST_SERVICENOW_* env vars not set",
)


@pytest.fixture
def real_sn_live_client():
    """Override the autouse fake-instance fixture: point the singleton at a
    real ServiceNow instance via env vars. Used by TestServiceNowReal."""
    srv.init_servicenow_client(REAL_SN_INSTANCE, REAL_SN_USER, REAL_SN_PASS)
    yield
    srv.init_servicenow_client("")  # restore mock for other tests


@pytest.mark.slow
@real_sn_required
class TestServiceNowReal:
    """Read-only @slow smoke tests against a real ServiceNow dev instance.

    Skipped unless TEST_SERVICENOW_INSTANCE, TEST_SERVICENOW_USER, and
    TEST_SERVICENOW_PASS are all set.
    """

    @pytest.mark.asyncio
    async def test_real_admin_lists_knowledge_bases(
        self, permissions_toml, real_sn_live_client, set_user,
    ):
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        result = await srv.list_knowledge_bases()
        assert "error" not in result, f"Real SN call failed: {result}"
        assert isinstance(result.get("result"), list)

    @pytest.mark.asyncio
    async def test_real_admin_lists_articles_in_kb(
        self, permissions_toml, real_sn_live_client, set_user,
    ):
        """Pick the first available KB and list its articles. Read-only."""
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        kbs = await srv.list_knowledge_bases()
        assert "error" not in kbs and kbs.get("result"), \
            "Need at least one KB to exercise list_articles"
        first_kb = kbs["result"][0]
        result = await srv.list_articles(first_kb["sys_id"])
        # Admin permits without dept context, so a KB without u_department
        # still returns articles (Cedar admin permit fires unconditionally).
        assert "error" not in result, f"Real SN list_articles failed: {result}"

    @pytest.mark.asyncio
    async def test_real_admin_gets_specific_article(
        self, permissions_toml, real_sn_live_client, set_user,
    ):
        """Round-trip: fetch a KB, list its articles, then GET one by sys_id."""
        set_user(email="admin@co.com", role="admin", groups=["admin-group"])
        kbs = await srv.list_knowledge_bases()
        first_kb = kbs["result"][0]
        articles = await srv.list_articles(first_kb["sys_id"])
        if not articles.get("result"):
            pytest.skip("Real instance has no articles in the first KB")
        first_art = articles["result"][0]
        result = await srv.get_article(first_art["sys_id"])
        assert "error" not in result
        assert result["result"]["sys_id"] == first_art["sys_id"]

    @pytest.mark.asyncio
    async def test_real_servicenow_auth_failure_handled(
        self, permissions_toml, set_user,
    ):
        """Wrong credentials → normalised auth error, not a stack trace."""
        srv.init_servicenow_client(REAL_SN_INSTANCE, "fake-user", "fake-password")
        try:
            set_user(email="admin@co.com", role="admin", groups=["admin-group"])
            result = await srv.list_knowledge_bases()
            assert "error" in result
            assert (
                "auth failed" in result["error"].lower()
                or result.get("status") == 401
                or "access denied" in result["error"].lower()
            ), f"Unexpected response for bad credentials: {result}"
        finally:
            srv.init_servicenow_client("")  # restore mock


# ─── Real-tier OBO smoke (per-user identity reaches ServiceNow) ──────────
#
# Gated on the KB real-tier env vars PLUS:
#   TEST_SERVICENOW_OBO=1
#   TEST_SERVICENOW_OBO_SCOPE = api://<sn-app-id>/.default
#   TEST_SERVICENOW_OBO_USER_TOKEN = a pre-acquired Entra user assertion JWT
#   ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET (for the exchange)
# Skips cleanly otherwise. Read-only. Proves the OBO exchange + bearer call
# succeed end-to-end and ServiceNow accepts the user's identity.

REAL_SN_OBO = os.getenv("TEST_SERVICENOW_OBO", "")
REAL_SN_OBO_SCOPE = os.getenv("TEST_SERVICENOW_OBO_SCOPE", "")
REAL_SN_OBO_USER_TOKEN = os.getenv("TEST_SERVICENOW_OBO_USER_TOKEN", "")

real_sn_obo_required = pytest.mark.skipif(
    not (
        REAL_SN_INSTANCE and REAL_SN_USER and REAL_SN_PASS
        and REAL_SN_OBO and REAL_SN_OBO_SCOPE and REAL_SN_OBO_USER_TOKEN
    ),
    reason="TEST_SERVICENOW_OBO* env vars not set",
)


@pytest.mark.slow
@real_sn_obo_required
class TestServiceNowRealOBO:
    """Read-only @slow smoke proving OBO carries the end user to ServiceNow."""

    @pytest.mark.asyncio
    async def test_real_obo_user_identity_reaches_sn(
        self, permissions_toml, set_user,
    ):
        import servicenow_obo

        srv.init_servicenow_client(REAL_SN_INSTANCE, REAL_SN_USER, REAL_SN_PASS)
        servicenow_obo.init_sn_obo_exchanger(REAL_SN_OBO_SCOPE)
        try:
            assert srv.get_sn_obo_exchanger() is not None, (
                "OBO exchanger not configured — set ENTRA_CLIENT_SECRET so the "
                "exchange path is actually exercised (not the Basic fallback)."
            )
            set_user(
                email="obo-user@co.com", role="developer", groups=["dev-group"],
                claims={"department": "IT"}, provider="entra",
            )
            # Override the placeholder token with the real Entra user assertion.
            srv.current_user_token.set(REAL_SN_OBO_USER_TOKEN)

            result = await srv.list_knowledge_bases()
            assert "error" not in result, f"Real OBO call failed: {result}"
            assert isinstance(result.get("result"), list)
        finally:
            servicenow_obo._exchanger = None
            srv.init_servicenow_client("")  # restore mock
