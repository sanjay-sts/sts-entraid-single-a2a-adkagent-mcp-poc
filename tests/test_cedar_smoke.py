"""Cedar policy tests: smoke tests, file-based policies, and CedarPolicyEvaluator.

Validates that:
1. cedarpy loads and evaluates policies correctly (inline policies)
2. File-based .cedar policies match current require_role() behavior
3. ABAC policies work (archiver attribute + resource path)
4. CedarPolicyEvaluator class works end-to-end
"""

import json
import sys
from pathlib import Path

import pytest
from cedarpy import is_authorized, Decision

# Add mcp_server to path for policy imports
sys.path.insert(0, str(Path(__file__).parent.parent / "mcp_server"))
from policy import (
    AccessRequest,
    AccessDecision,
    CedarPolicyEvaluator,
    TomlPolicyEvaluator,
)

CEDAR_DIR = Path(__file__).parent.parent / "cedar"
SCHEMA_PATH = CEDAR_DIR / "schema.cedarschema"
ENTITIES_PATH = CEDAR_DIR / "entities.json"


@pytest.fixture
def schema():
    return SCHEMA_PATH.read_text()


@pytest.fixture
def static_entities():
    return json.loads(ENTITIES_PATH.read_text())


@pytest.fixture
def file_policies():
    """Load all .cedar policy files concatenated (same as CedarPolicyEvaluator does)."""
    policies_dir = CEDAR_DIR / "policies"
    parts = []
    for f in sorted(policies_dir.glob("*.cedar")):
        parts.append(f.read_text(encoding="utf-8"))
    return "\n".join(parts)


def _user_entity(email, provider, roles, groups=None, archiver=None, department=None):
    """Build a Cedar User entity from attributes."""
    attrs = {
        "provider": provider,
        "email": email,
        "groups": groups or [],
    }
    if department is not None:
        attrs["department"] = department
    if archiver is not None:
        attrs["archiver"] = archiver

    return {
        "uid": {"__entity": {"type": "AgentAuth::User", "id": email}},
        "attrs": attrs,
        "parents": [
            {"__entity": {"type": "AgentAuth::Role", "id": role}}
            for role in roles
        ],
    }


# ── Test: cedarpy loads and evaluates ────────────────────────────────

class TestCedarSmoke:
    """Basic smoke tests for Cedar integration."""

    RBAC_POLICY = """
    // Admin can call any tool
    permit(
      principal in AgentAuth::Role::"admin",
      action == AgentAuth::Action::"call_tool",
      resource
    );

    // Developer can call developer-level tools
    permit(
      principal in AgentAuth::Role::"developer",
      action == AgentAuth::Action::"call_tool",
      resource
    ) when {
      resource == AgentAuth::Tool::"get_user_profile" ||
      resource == AgentAuth::Tool::"list_files" ||
      resource == AgentAuth::Tool::"list_s3_buckets" ||
      resource == AgentAuth::Tool::"list_s3_objects" ||
      resource == AgentAuth::Tool::"get_s3_object_info"
    };

    // Viewer can call viewer-level tools
    permit(
      principal in AgentAuth::Role::"viewer",
      action == AgentAuth::Action::"call_tool",
      resource
    ) when {
      resource == AgentAuth::Tool::"get_user_profile" ||
      resource == AgentAuth::Tool::"get_s3_object_info"
    };
    """

    def test_admin_can_call_any_tool(self, static_entities):
        """Admin should be allowed to call send_email."""
        user = _user_entity("admin@company.com", "entra", ["admin"])
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"admin@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"send_email"',
                "context": {},
            },
            policies=self.RBAC_POLICY,
            entities=entities,
        )
        assert result.allowed, f"Admin should be allowed to call send_email: {result}"

    def test_viewer_denied_send_email(self, static_entities):
        """Viewer should be denied send_email (admin only)."""
        user = _user_entity("viewer@company.com", "entra", ["viewer"])
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"viewer@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"send_email"',
                "context": {},
            },
            policies=self.RBAC_POLICY,
            entities=entities,
        )
        assert not result.allowed, "Viewer should NOT be allowed to call send_email"

    def test_developer_can_call_list_files(self, static_entities):
        """Developer should be allowed to call list_files."""
        user = _user_entity("dev@company.com", "entra", ["developer"])
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"dev@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"list_files"',
                "context": {},
            },
            policies=self.RBAC_POLICY,
            entities=entities,
        )
        assert result.allowed, "Developer should be allowed to call list_files"

    def test_viewer_can_call_get_user_profile(self, static_entities):
        """Viewer should be allowed to call get_user_profile."""
        user = _user_entity("viewer@company.com", "cognito", ["viewer"])
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"viewer@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"get_user_profile"',
                "context": {},
            },
            policies=self.RBAC_POLICY,
            entities=entities,
        )
        assert result.allowed, "Viewer should be allowed to call get_user_profile"

    def test_no_role_denied(self, static_entities):
        """User with no roles should be denied everything."""
        user = _user_entity("norole@company.com", "entra", [])
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"norole@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"get_user_profile"',
                "context": {},
            },
            policies=self.RBAC_POLICY,
            entities=entities,
        )
        assert not result.allowed, "User with no roles should be denied"


class TestCedarABAC:
    """ABAC tests — archiver attribute + resource path."""

    ABAC_POLICY = """
    // Admin can delete any S3 object
    permit(
      principal in AgentAuth::Role::"admin",
      action == AgentAuth::Action::"call_tool",
      resource == AgentAuth::Tool::"delete_s3_object"
    );

    // Developer with archiver attribute can delete in archive/ only
    permit(
      principal in AgentAuth::Role::"developer",
      action == AgentAuth::Action::"call_tool",
      resource == AgentAuth::Tool::"delete_s3_object"
    ) when {
      principal has archiver &&
      principal.archiver == true &&
      context has resource_path &&
      context.resource_path like "archive/*"
    };

    // Hard guardrail: no one can delete in protected/
    forbid(
      principal,
      action == AgentAuth::Action::"call_tool",
      resource == AgentAuth::Tool::"delete_s3_object"
    ) when {
      context has resource_path &&
      context.resource_path like "protected/*"
    };
    """

    def test_admin_can_delete_anywhere(self, static_entities):
        """Admin can delete S3 objects in any path."""
        user = _user_entity("admin@company.com", "entra", ["admin"])
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"admin@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"delete_s3_object"',
                "context": {"resource_path": "data/report.csv"},
            },
            policies=self.ABAC_POLICY,
            entities=entities,
        )
        assert result.allowed, "Admin should be allowed to delete anywhere"

    def test_archiver_can_delete_in_archive(self, static_entities):
        """Developer with archiver=true can delete in archive/ folder."""
        user = _user_entity("archiver@company.com", "entra", ["developer"], archiver=True)
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"archiver@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"delete_s3_object"',
                "context": {"resource_path": "archive/2024/old-report.csv"},
            },
            policies=self.ABAC_POLICY,
            entities=entities,
        )
        assert result.allowed, "Developer with archiver=true should delete in archive/"

    def test_archiver_denied_outside_archive(self, static_entities):
        """Developer with archiver=true cannot delete outside archive/ folder."""
        user = _user_entity("archiver@company.com", "entra", ["developer"], archiver=True)
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"archiver@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"delete_s3_object"',
                "context": {"resource_path": "data/important.csv"},
            },
            policies=self.ABAC_POLICY,
            entities=entities,
        )
        assert not result.allowed, "Archiver should NOT delete outside archive/"

    def test_developer_without_archiver_denied(self, static_entities):
        """Developer without archiver attribute cannot delete anything."""
        user = _user_entity("dev@company.com", "entra", ["developer"])
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"dev@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"delete_s3_object"',
                "context": {"resource_path": "archive/2024/old-report.csv"},
            },
            policies=self.ABAC_POLICY,
            entities=entities,
        )
        assert not result.allowed, "Developer without archiver should NOT delete"

    def test_forbid_protected_overrides_admin(self, static_entities):
        """Forbid policy: no one can delete in protected/ — not even admin."""
        user = _user_entity("admin@company.com", "entra", ["admin"])
        entities = static_entities + [user]

        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"admin@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"delete_s3_object"',
                "context": {"resource_path": "protected/secrets.key"},
            },
            policies=self.ABAC_POLICY,
            entities=entities,
        )
        assert not result.allowed, "Forbid should override admin permit for protected/"


# ── Test: file-based policies (cedar/policies/*.cedar) ───────────────

class TestCedarFilePolicies:
    """Tests using the actual .cedar policy files from cedar/policies/."""

    def test_admin_send_email_allowed(self, static_entities, file_policies):
        user = _user_entity("admin@company.com", "entra", ["admin"])
        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"admin@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"send_email"',
                "context": {},
            },
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    def test_developer_send_email_denied(self, static_entities, file_policies):
        user = _user_entity("dev@company.com", "entra", ["developer"])
        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"dev@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"send_email"',
                "context": {},
            },
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    def test_viewer_get_s3_object_info_allowed(self, static_entities, file_policies):
        user = _user_entity("viewer@company.com", "cognito", ["viewer"])
        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"viewer@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"get_s3_object_info"',
                "context": {},
            },
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    def test_viewer_list_s3_buckets_denied(self, static_entities, file_policies):
        user = _user_entity("viewer@company.com", "entra", ["viewer"])
        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"viewer@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"list_s3_buckets"',
                "context": {},
            },
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    def test_archiver_delete_in_archive_allowed(self, static_entities, file_policies):
        user = _user_entity("arch@company.com", "entra", ["developer"], archiver=True)
        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"arch@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"delete_s3_object"',
                "context": {"resource_path": "archive/old-data.csv"},
            },
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    def test_archiver_delete_outside_archive_denied(self, static_entities, file_policies):
        user = _user_entity("arch@company.com", "entra", ["developer"], archiver=True)
        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"arch@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"delete_s3_object"',
                "context": {"resource_path": "data/important.csv"},
            },
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    def test_admin_delete_in_protected_denied(self, static_entities, file_policies):
        """Forbid guardrail overrides admin permit."""
        user = _user_entity("admin@company.com", "entra", ["admin"])
        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"admin@company.com"',
                "action": 'AgentAuth::Action::"call_tool"',
                "resource": 'AgentAuth::Tool::"delete_s3_object"',
                "context": {"resource_path": "protected/secrets.key"},
            },
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    def test_list_tools_allowed_for_any_user(self, static_entities, file_policies):
        """Any authenticated user can list tools."""
        user = _user_entity("anyone@company.com", "entra", [])
        result = is_authorized(
            request={
                "principal": 'AgentAuth::User::"anyone@company.com"',
                "action": 'AgentAuth::Action::"list_tools"',
                "resource": 'AgentAuth::Tool::"send_email"',
                "context": {},
            },
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed


# ── Test: CedarPolicyEvaluator class ────────────────────────────────

class TestCedarPolicyEvaluator:
    """Tests for the CedarPolicyEvaluator Python integration."""

    @pytest.fixture
    def evaluator(self, tmp_path):
        """Create a CedarPolicyEvaluator with a mock permissions.toml."""
        # Create a minimal permissions.toml for role resolution
        toml_content = b"""
[group_rules.entra]
"admin-group" = "admin"
"dev-group" = "developer"
"viewer-group" = "viewer"

[group_rules.cognito]
"platform-admins" = "admin"
"platform-developers" = "developer"
"platform-viewers" = "viewer"

[users]
"override@company.com" = { role = "admin" }

[defaults]
unknown_users = "none"
"""
        toml_path = tmp_path / "permissions.toml"
        toml_path.write_bytes(toml_content)

        toml_eval = TomlPolicyEvaluator(toml_path)
        return CedarPolicyEvaluator(CEDAR_DIR, toml_eval)

    def test_admin_allowed(self, evaluator):
        request = AccessRequest(
            email="admin@company.com",
            provider="entra",
            groups=["admin-group"],
            tool_name="send_email",
            claims={},
            assumed_role="admin",
        )
        decision = evaluator.check_access(request, [])  # allowed_roles ignored
        assert decision.allowed
        assert decision.role == "admin"

    def test_viewer_denied_admin_tool(self, evaluator):
        request = AccessRequest(
            email="viewer@company.com",
            provider="entra",
            groups=["viewer-group"],
            tool_name="send_email",
            claims={},
            assumed_role="viewer",
        )
        decision = evaluator.check_access(request, [])
        assert not decision.allowed
        assert "Cedar denied" in decision.reason

    def test_developer_allowed_list_files(self, evaluator):
        request = AccessRequest(
            email="dev@company.com",
            provider="entra",
            groups=["dev-group"],
            tool_name="list_files",
            claims={},
            assumed_role="developer",
        )
        decision = evaluator.check_access(request, [])
        assert decision.allowed

    def test_archiver_delete_allowed(self, evaluator):
        request = AccessRequest(
            email="arch@company.com",
            provider="entra",
            groups=["dev-group"],
            tool_name="delete_s3_object",
            claims={"archiver": True},
            assumed_role="developer",
            context={"resource_path": "archive/2024/old.csv"},
        )
        decision = evaluator.check_access(request, [])
        assert decision.allowed

    def test_archiver_delete_wrong_path_denied(self, evaluator):
        request = AccessRequest(
            email="arch@company.com",
            provider="entra",
            groups=["dev-group"],
            tool_name="delete_s3_object",
            claims={"archiver": True},
            assumed_role="developer",
            context={"resource_path": "data/important.csv"},
        )
        decision = evaluator.check_access(request, [])
        assert not decision.allowed

    def test_developer_no_archiver_denied(self, evaluator):
        request = AccessRequest(
            email="dev@company.com",
            provider="entra",
            groups=["dev-group"],
            tool_name="delete_s3_object",
            claims={},
            assumed_role="developer",
            context={"resource_path": "archive/2024/old.csv"},
        )
        decision = evaluator.check_access(request, [])
        assert not decision.allowed

    def test_protected_forbid_overrides_admin(self, evaluator):
        request = AccessRequest(
            email="admin@company.com",
            provider="entra",
            groups=["admin-group"],
            tool_name="delete_s3_object",
            claims={},
            assumed_role="admin",
            context={"resource_path": "protected/secrets.key"},
        )
        decision = evaluator.check_access(request, [])
        assert not decision.allowed

    def test_get_available_roles_delegates_to_toml(self, evaluator):
        """Role resolution should come from TomlPolicyEvaluator."""
        roles = evaluator.get_available_roles("admin@company.com", "entra", ["admin-group"])
        assert roles == ["admin"]

    def test_cognito_user_works(self, evaluator):
        request = AccessRequest(
            email="coguser@company.com",
            provider="cognito",
            groups=["platform-developers"],
            tool_name="list_s3_buckets",
            claims={},
            assumed_role="developer",
        )
        decision = evaluator.check_access(request, [])
        assert decision.allowed

    def test_user_override_from_toml(self, evaluator):
        """User with direct role override in permissions.toml."""
        request = AccessRequest(
            email="override@company.com",
            provider="entra",
            groups=[],  # No groups, but has user override
            tool_name="send_email",
            claims={},
            assumed_role="admin",
        )
        decision = evaluator.check_access(request, [])
        assert decision.allowed

    def test_assumed_role_enforced_check_access(self, evaluator):
        """Multi-role user assuming viewer should be denied admin-only tools."""
        request = AccessRequest(
            email="multi@company.com",
            provider="entra",
            groups=["admin-group", "viewer-group"],
            tool_name="send_email",
            claims={},
            assumed_role="viewer",  # Explicitly downgrading
        )
        decision = evaluator.check_access(request, [])
        assert not decision.allowed, (
            "User with admin+viewer groups assuming viewer should be denied send_email"
        )

    def test_assumed_role_enforced_batch(self, evaluator):
        """Multi-role user assuming viewer: batch permissions should reflect viewer, not admin."""
        permissions = evaluator.check_access_batch(
            email="multi@company.com",
            provider="entra",
            groups=["admin-group", "viewer-group"],
            tool_names=["send_email", "get_user_profile", "delete_resource"],
            claims={},
            assumed_role="viewer",
        )
        assert permissions["get_user_profile"] is True, "Viewer can access get_user_profile"
        assert permissions["send_email"] is False, "Viewer cannot access send_email"
        assert permissions["delete_resource"] is False, "Viewer cannot access delete_resource"

    def test_assumed_admin_still_works(self, evaluator):
        """Multi-role user assuming admin should retain admin access."""
        request = AccessRequest(
            email="multi@company.com",
            provider="entra",
            groups=["admin-group", "viewer-group"],
            tool_name="send_email",
            claims={},
            assumed_role="admin",
        )
        decision = evaluator.check_access(request, [])
        assert decision.allowed, "User assuming admin should be allowed send_email"

    def test_check_access_batch_includes_servicenow(self, evaluator):
        """Batch eval must handle all 7 new ServiceNow tools without choking.

        Note: batch eval used by /me does not pass runtime context, so ABAC
        permits (which require context.target_department) won't fire for
        developer/viewer. Admin permits are RBAC and require no context, so
        admin gets all 7 tools in the matrix.
        """
        permissions = evaluator.check_access_batch(
            email="admin@company.com",
            provider="entra",
            groups=["admin-group"],
            tool_names=[
                "list_knowledge_bases", "list_articles", "get_article",
                "list_incidents", "get_incident", "create_incident", "update_incident",
            ],
            claims={"department": "IT"},
            assumed_role="admin",
        )
        assert all(permissions.values()), (
            f"Admin should be allowed all 7 SN tools, got: {permissions}"
        )


# ── Test: ServiceNow Cedar policies (RBAC + composite role+dept ABAC) ────

class TestCedarServiceNowPolicies:
    """ServiceNow tool policies: RBAC for non-dept tools, composite role+dept for dept-scoped tools.

    Validates the two-tier model:
    1. RBAC (rbac.cedar) — admin: all SN tools; developer + viewer: select tools without dept context.
    2. ABAC (abac.cedar) — developer + viewer: dept-scoped tools require principal.department == context.target_department.
    """

    def _sn_request(self, principal_email, tool, target_department=None):
        ctx = {}
        if target_department is not None:
            ctx["target_department"] = target_department
        return {
            "principal": f'AgentAuth::User::"{principal_email}"',
            "action": 'AgentAuth::Action::"call_tool"',
            "resource": f'AgentAuth::Tool::"{tool}"',
            "context": ctx,
        }

    # ── Admin: no dept condition (covered by existing rbac.cedar admin permit) ──

    def test_admin_can_list_any_kb(self, static_entities, file_policies):
        user = _user_entity("admin@co.com", "entra", ["admin"])
        result = is_authorized(
            request=self._sn_request("admin@co.com", "list_knowledge_bases"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    def test_admin_can_list_articles_any_kb(self, static_entities, file_policies):
        """Admin can call list_articles with no target_department in context."""
        user = _user_entity("admin@co.com", "entra", ["admin"])
        result = is_authorized(
            request=self._sn_request("admin@co.com", "list_articles"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    # ── Developer: composite role + department ──

    def test_developer_lists_own_dept_articles(self, static_entities, file_policies):
        user = _user_entity("dev-it@co.com", "entra", ["developer"], department="IT")
        result = is_authorized(
            request=self._sn_request("dev-it@co.com", "list_articles", target_department="IT"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    def test_developer_blocked_from_other_dept_articles(self, static_entities, file_policies):
        user = _user_entity("dev-it@co.com", "entra", ["developer"], department="IT")
        result = is_authorized(
            request=self._sn_request("dev-it@co.com", "list_articles", target_department="HR"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    def test_developer_lists_own_dept_incidents(self, static_entities, file_policies):
        user = _user_entity("dev-it@co.com", "entra", ["developer"], department="IT")
        result = is_authorized(
            request=self._sn_request("dev-it@co.com", "list_incidents", target_department="IT"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    def test_developer_blocked_other_dept_incidents(self, static_entities, file_policies):
        user = _user_entity("dev-it@co.com", "entra", ["developer"], department="IT")
        result = is_authorized(
            request=self._sn_request("dev-it@co.com", "list_incidents", target_department="HR"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    def test_developer_creates_own_dept_incident(self, static_entities, file_policies):
        user = _user_entity("dev-it@co.com", "entra", ["developer"], department="IT")
        result = is_authorized(
            request=self._sn_request("dev-it@co.com", "create_incident", target_department="IT"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    def test_developer_updates_own_dept_incident(self, static_entities, file_policies):
        """Defense-in-depth check on update_incident via fetch-then-Cedar pattern."""
        user = _user_entity("dev-it@co.com", "entra", ["developer"], department="IT")
        result = is_authorized(
            request=self._sn_request("dev-it@co.com", "update_incident", target_department="IT"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    def test_developer_blocked_updating_other_dept_incident(self, static_entities, file_policies):
        """The bug closure: dev IT must not update HR's incident even via update_incident."""
        user = _user_entity("dev-it@co.com", "entra", ["developer"], department="IT")
        result = is_authorized(
            request=self._sn_request("dev-it@co.com", "update_incident", target_department="HR"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    # ── Viewer: composite role + department, KB articles only ──

    def test_viewer_can_read_own_dept_articles(self, static_entities, file_policies):
        user = _user_entity("viewer-it@co.com", "entra", ["viewer"], department="IT")
        result = is_authorized(
            request=self._sn_request("viewer-it@co.com", "list_articles", target_department="IT"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert result.allowed

    def test_viewer_blocked_from_other_dept_articles(self, static_entities, file_policies):
        user = _user_entity("viewer-it@co.com", "entra", ["viewer"], department="IT")
        result = is_authorized(
            request=self._sn_request("viewer-it@co.com", "list_articles", target_department="HR"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    def test_viewer_cannot_list_incidents(self, static_entities, file_policies):
        """Viewer has no incident permit anywhere (RBAC nor ABAC)."""
        user = _user_entity("viewer-it@co.com", "entra", ["viewer"], department="IT")
        result = is_authorized(
            request=self._sn_request("viewer-it@co.com", "list_incidents", target_department="IT"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    # ── Edge case: principal missing department claim ──

    def test_principal_missing_department_denied(self, static_entities, file_policies):
        """Developer without department claim → denied on dept-scoped tools."""
        user = _user_entity("dev-nodept@co.com", "entra", ["developer"])  # no department=
        result = is_authorized(
            request=self._sn_request("dev-nodept@co.com", "list_articles", target_department="IT"),
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed

    # ── Edge case: tool called without target_department in context ──
    # (This is what require_cedar()'s Phase 1 sees before the tool body
    # provides context. Phase 1 passthrough must let the call through.)

    def test_phase1_no_context_denies_developer_param_tools(self, static_entities, file_policies):
        """Without target_department context, developer's ABAC permit cannot fire.
        Cedar denies; require_cedar() must rely on _ABAC_PHASE1_PASSTHROUGH to let
        the call reach Phase 2 where the tool provides context.
        """
        user = _user_entity("dev-it@co.com", "entra", ["developer"], department="IT")
        result = is_authorized(
            request=self._sn_request("dev-it@co.com", "list_articles"),  # NO target_department
            policies=file_policies,
            entities=static_entities + [user],
        )
        assert not result.allowed
