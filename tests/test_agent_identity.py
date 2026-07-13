"""Agent identity — pure claim validation and principal derivation."""
from datetime import datetime, timedelta, timezone

import pytest

from agent_common.principal import (
    AgentAuthError,
    Principal,
    derive_principal,
    is_app_token,
    verify_agent_claims,
)

ORCH = "11111111-1111-1111-1111-111111111111"
PEER = "22222222-2222-2222-2222-222222222222"
ROGUE = "99999999-9999-9999-9999-999999999999"
PEER_AUD = f"api://{PEER}"


def app_claims(azp=ORCH, aud=PEER_AUD, roles=("Agent.Invoke",), idtyp="app"):
    """Claims as Entra mints them for a client-credentials (app-only) token."""
    claims = {
        "aud": aud,
        "azp": azp,
        "oid": azp,
        "sub": azp,
        "roles": list(roles),
        "iss": "https://login.microsoftonline.com/tid/v2.0",
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
    }
    if idtyp:
        claims["idtyp"] = idtyp
    return claims


def user_claims(sub="user-1", groups=("admin-group",)):
    return {
        "aud": PEER_AUD,
        "sub": sub,
        "preferred_username": "adele@example.com",
        "groups": list(groups),
        "scp": "access_as_user",
        "iss": "https://login.microsoftonline.com/tid/v2.0",
    }


# --- is_app_token -----------------------------------------------------------

def test_app_token_detected_by_idtyp():
    assert is_app_token(app_claims()) is True


def test_user_token_is_not_an_app_token():
    assert is_app_token(user_claims()) is False


def test_app_token_without_idtyp_is_rejected():
    """idtyp is an optional claim that must be configured (see
    docs/ENTRA_AGENT_SETUP.md §4). Its absence must fail closed — a token
    with roles but no idtyp must NOT be treated as a machine token."""
    assert is_app_token(app_claims(idtyp=None)) is False


def test_user_token_with_roles_is_not_an_app_token():
    """A user CAN have app roles. scp/preferred_username prove it's a user."""
    claims = user_claims()
    claims["roles"] = ["Agent.Invoke"]
    assert is_app_token(claims) is False


def test_human_token_with_app_roles_and_no_user_markers_is_not_machine():
    """A delegated token for an app-roles-only API can legitimately lack
    scp/preferred_username/upn/unique_name. Without idtyp=app, it must still
    never be classified as a machine token (fail closed, no heuristic)."""
    claims = {
        "aud": PEER_AUD,
        "sub": "user-1",
        "roles": ["Agent.Invoke"],
        "iss": "https://login.microsoftonline.com/tid/v2.0",
    }
    assert is_app_token(claims) is False


def test_app_token_with_non_app_idtyp_is_rejected():
    assert is_app_token(app_claims(idtyp="user")) is False


# --- verify_agent_claims ----------------------------------------------------

def test_valid_agent_token_passes():
    verify_agent_claims(app_claims(), PEER_AUD, [ORCH], "Agent.Invoke")


def test_wrong_audience_rejected():
    """A token minted for another hop must not be replayable here."""
    with pytest.raises(AgentAuthError) as exc:
        verify_agent_claims(
            app_claims(aud="api://someone-else"), PEER_AUD, [ORCH], "Agent.Invoke"
        )
    assert exc.value.denial_reason == "wrong_audience"


def test_unknown_caller_rejected():
    with pytest.raises(AgentAuthError) as exc:
        verify_agent_claims(app_claims(azp=ROGUE), PEER_AUD, [ORCH], "Agent.Invoke")
    assert exc.value.denial_reason == "unknown_agent"


def test_caller_without_required_role_rejected():
    with pytest.raises(AgentAuthError) as exc:
        verify_agent_claims(app_claims(roles=()), PEER_AUD, [ORCH], "Agent.Invoke")
    assert exc.value.denial_reason == "agent_not_authorized"


def test_user_token_presented_as_agent_token_rejected():
    """A user token must never satisfy the agent-identity layer."""
    with pytest.raises(AgentAuthError) as exc:
        verify_agent_claims(user_claims(), PEER_AUD, [ORCH], "Agent.Invoke")
    assert exc.value.denial_reason == "not_an_agent_token"


def test_missing_idtyp_denial_message_is_actionable():
    """An operator who skipped configuring idtyp must be able to diagnose
    this from the error message alone."""
    with pytest.raises(AgentAuthError) as exc:
        verify_agent_claims(app_claims(idtyp=None), PEER_AUD, [ORCH], "Agent.Invoke")
    assert exc.value.denial_reason == "not_an_agent_token"
    assert "idtyp" in exc.value.message
    assert "docs/ENTRA_AGENT_SETUP.md" in exc.value.message
    assert "§4" in exc.value.message


def test_verify_agent_claims_uses_appid_fallback_when_azp_absent():
    """v1.0 tokens use `appid` instead of `azp`."""
    claims = app_claims()
    del claims["azp"]
    claims["appid"] = ORCH
    verify_agent_claims(claims, PEER_AUD, [ORCH], "Agent.Invoke")


def test_verify_agent_claims_rejects_empty_expected_audience():
    with pytest.raises(Exception):
        verify_agent_claims(app_claims(), "", [ORCH], "Agent.Invoke")


def test_verify_agent_claims_rejects_empty_required_role():
    with pytest.raises(Exception):
        verify_agent_claims(app_claims(), PEER_AUD, [ORCH], "")


def test_verify_agent_claims_rejects_empty_allowed_callers():
    with pytest.raises(Exception):
        verify_agent_claims(app_claims(), PEER_AUD, [], "Agent.Invoke")


# --- derive_principal -------------------------------------------------------

def test_machine_principal_when_no_user_token():
    p = derive_principal(app_claims(), None, None)
    assert p.principal_type == "machine"
    assert p.agent_id == ORCH
    assert p.agent_roles == ("Agent.Invoke",)
    assert p.user_claims is None


def test_delegated_principal_when_user_token_present():
    p = derive_principal(app_claims(), user_claims(), "raw-user-token")
    assert p.principal_type == "delegated"
    assert p.agent_id == ORCH           # acting agent preserved for audit
    assert p.user_claims["sub"] == "user-1"
    assert p.user_token == "raw-user-token"


def test_derive_principal_uses_appid_fallback_when_azp_absent():
    """v1.0 tokens use `appid` instead of `azp`."""
    claims = app_claims()
    del claims["azp"]
    claims["appid"] = ORCH
    p = derive_principal(claims, None, None)
    assert p.agent_id == ORCH


def test_dangling_user_token_without_claims_is_not_delegated():
    """A user_token present with no verified user_claims must NOT yield a
    delegated principal — the token was never validated, so it cannot be
    trusted or echoed back either."""
    p = derive_principal(app_claims(), None, "dangling-token")
    assert p.principal_type == "machine"
    assert p.user_claims is None
    assert p.user_token is None


# --- Principal immutability --------------------------------------------------

def test_principal_type_reassignment_fails():
    p = derive_principal(app_claims(), None, None)
    with pytest.raises(Exception):
        p.principal_type = "delegated"


def test_agent_roles_is_immutable_tuple():
    """agent_roles must be a tuple (not list) so it cannot be mutated in
    place to escalate privileges."""
    p = derive_principal(app_claims(), None, None)
    assert isinstance(p.agent_roles, tuple)
    with pytest.raises(Exception):
        p.agent_roles.append("Agent.Admin")


def test_user_claims_mutation_fails():
    """user_claims must be immutable so a downstream tier cannot rewrite the
    delegated user's identity in place."""
    p = derive_principal(app_claims(), user_claims(), "raw-user-token")
    with pytest.raises(Exception):
        p.user_claims["sub"] = "someone-else"
