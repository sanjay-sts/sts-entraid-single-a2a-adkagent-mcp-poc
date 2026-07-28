"""Policy — agent principals resolve roles from their app id, not group claims."""
import textwrap

import pytest

from mcp_server.policy import AccessRequest, TomlPolicyEvaluator

ORCH = "11111111-1111-1111-1111-111111111111"
PEER = "22222222-2222-2222-2222-222222222222"
UNKNOWN = "99999999-9999-9999-9999-999999999999"


@pytest.fixture
def evaluator(tmp_path):
    config = tmp_path / "permissions.toml"
    config.write_text(textwrap.dedent(f"""
        [group_rules.entra]
        "admin-group-guid" = "admin"

        [agent_rules.entra]
        "{ORCH}" = "developer"
        "{PEER}" = "viewer"

        [defaults]
        unknown_users = "none"
    """))
    return TomlPolicyEvaluator(config)


def test_agent_resolves_role_from_app_id(evaluator):
    assert evaluator.get_agent_roles(ORCH, "entra") == ["developer"]


def test_second_agent_resolves_its_own_role(evaluator):
    assert evaluator.get_agent_roles(PEER, "entra") == ["viewer"]


def test_unregistered_agent_gets_no_roles(evaluator):
    """An agent absent from agent_rules gets nothing — fail closed."""
    assert evaluator.get_agent_roles(UNKNOWN, "entra") == []


def test_agent_rules_do_not_leak_into_user_roles(evaluator):
    """An app id must not be usable as a group claim."""
    assert evaluator.get_available_roles("", "entra", [ORCH]) == []


def test_group_rules_do_not_leak_into_agent_roles(evaluator):
    """A group guid must not be usable as an app id."""
    assert evaluator.get_agent_roles("admin-group-guid", "entra") == []


def test_agent_rules_are_per_provider(evaluator):
    """An Entra app id must not resolve under another provider's table."""
    assert evaluator.get_agent_roles(ORCH, "cognito") == []


def test_empty_agent_id_gets_no_roles(evaluator):
    """A missing azp claim must not resolve to anything."""
    assert evaluator.get_agent_roles("", "entra") == []


def test_check_access_allows_machine_principal_with_permitted_role(evaluator):
    request = AccessRequest(
        email="",
        provider="entra",
        groups=[],
        tool_name="list_s3_buckets",
        claims={},
        assumed_role="developer",
        principal_type="machine",
        agent_id=ORCH,
    )
    decision = evaluator.check_access(request, ["admin", "developer"])
    assert decision.allowed is True
    assert decision.role == "developer"


def test_check_access_denies_machine_principal_lacking_role(evaluator):
    request = AccessRequest(
        email="",
        provider="entra",
        groups=[],
        tool_name="send_email",
        claims={},
        assumed_role="developer",
        principal_type="machine",
        agent_id=ORCH,
    )
    decision = evaluator.check_access(request, ["admin"])
    assert decision.allowed is False
    assert "developer" in decision.reason


def test_machine_denial_names_the_agent(evaluator):
    """Audit value: a machine denial must identify WHICH agent was refused."""
    request = AccessRequest(
        email="",
        provider="entra",
        groups=[],
        tool_name="send_email",
        claims={},
        assumed_role="developer",
        principal_type="machine",
        agent_id=ORCH,
    )
    decision = evaluator.check_access(request, ["admin"])
    assert ORCH in decision.reason


def test_access_request_defaults_to_delegated():
    """Existing call sites keep working — delegated is the default."""
    request = AccessRequest(
        email="a@b.com", provider="entra", groups=[], tool_name="t", claims={}
    )
    assert request.principal_type == "delegated"
    assert request.agent_id == ""


# --- Hardening beyond the plan -------------------------------------------
# The plan's docstring claimed these properties but shipped no test for them,
# which is exactly how a green suite comes to assert nothing (see Task 3/4).


@pytest.fixture
def permissive_default_evaluator(tmp_path):
    """A tenant that grants a fallback role to unrecognised HUMANS.

    The dangerous case: if `unknown_users` leaked into the agent path, every
    unregistered app id in the tenant — including one an attacker registered
    themselves — would silently acquire this role.
    """
    config = tmp_path / "permissions.toml"
    config.write_text(textwrap.dedent(f"""
        [agent_rules.entra]
        "{ORCH}" = "developer"

        [defaults]
        unknown_users = "viewer"
    """))
    return TomlPolicyEvaluator(config)


def test_unknown_users_default_does_not_apply_to_agents(permissive_default_evaluator):
    assert permissive_default_evaluator.get_agent_roles(UNKNOWN, "entra") == []
    # Control: the same default DOES still apply to humans, so this test is
    # proving isolation rather than proving the config was ignored entirely.
    assert permissive_default_evaluator.get_available_roles(
        "nobody@example.com", "entra", []
    ) == ["viewer"]


def test_agent_id_match_is_case_insensitive(evaluator):
    """Entra app ids are RFC 4122 GUIDs — hex, and case-insensitive.

    An operator who pastes an app id in upper case from the Portal must not
    silently lock their own agent out.
    """
    assert evaluator.get_agent_roles(ORCH.upper(), "entra") == ["developer"]


def test_unrecognised_role_name_is_rejected(tmp_path):
    """A typo in agent_rules must fail closed, not invent a role."""
    config = tmp_path / "permissions.toml"
    config.write_text(textwrap.dedent(f"""
        [agent_rules.entra]
        "{ORCH}" = "adminn"
    """))
    assert TomlPolicyEvaluator(config).get_agent_roles(ORCH, "entra") == []


def test_missing_agent_rules_table_is_not_an_error(tmp_path):
    """Existing deployments have no [agent_rules] — they must keep working."""
    config = tmp_path / "permissions.toml"
    config.write_text('[group_rules.entra]\n"g" = "admin"\n')
    evaluator = TomlPolicyEvaluator(config)
    assert evaluator.get_agent_roles(ORCH, "entra") == []
    assert evaluator.get_available_roles("x@y.com", "entra", ["g"]) == ["admin"]
