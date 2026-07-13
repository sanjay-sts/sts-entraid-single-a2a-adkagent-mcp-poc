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


def test_app_token_detected_without_idtyp_via_fallback():
    """idtyp is an optional claim; fall back to roles-present/scp-absent."""
    assert is_app_token(app_claims(idtyp=None)) is True


def test_user_token_with_roles_is_not_an_app_token():
    """A user CAN have app roles. scp/preferred_username prove it's a user."""
    claims = user_claims()
    claims["roles"] = ["Agent.Invoke"]
    assert is_app_token(claims) is False


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


# --- derive_principal -------------------------------------------------------

def test_machine_principal_when_no_user_token():
    p = derive_principal(app_claims(), None, None)
    assert p.principal_type == "machine"
    assert p.agent_id == ORCH
    assert p.agent_roles == ["Agent.Invoke"]
    assert p.user_claims is None


def test_delegated_principal_when_user_token_present():
    p = derive_principal(app_claims(), user_claims(), "raw-user-token")
    assert p.principal_type == "delegated"
    assert p.agent_id == ORCH           # acting agent preserved for audit
    assert p.user_claims["sub"] == "user-1"
    assert p.user_token == "raw-user-token"


def test_principal_is_immutable():
    """A downstream tier must not be able to escalate by mutating the principal."""
    p = derive_principal(app_claims(), None, None)
    with pytest.raises(Exception):
        p.principal_type = "delegated"
