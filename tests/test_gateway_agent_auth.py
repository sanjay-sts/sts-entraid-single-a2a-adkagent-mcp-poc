"""Gateway — agent tokens are authorized by app role, not group membership.

Two levels here, deliberately:

  * the helpers (`authorize_agent_caller`, `authorize_human_claims`) as pure
    unit tests — no HTTP, no JWKS;
  * the middleware itself through a TestClient with the token validator
    stubbed, because the helpers being correct says nothing about whether the
    middleware actually routes to them, and the branch wiring is where the
    interesting mistakes live.
"""
import pytest
from fastapi.testclient import TestClient

import a2a_server.server as server
from a2a_server.server import authorize_agent_caller, authorize_human_claims
from agent_common.principal import AgentAuthError

ORCH = "11111111-1111-1111-1111-111111111111"
PEER = "22222222-2222-2222-2222-222222222222"
ROGUE = "99999999-9999-9999-9999-999999999999"
GATEWAY_ID = "gw-id"
GATEWAY_AUD = f"api://{GATEWAY_ID}"

ALLOWED_GROUP = "aaaaaaaa-0000-0000-0000-000000000001"
OTHER_GROUP = "bbbbbbbb-0000-0000-0000-000000000002"


@pytest.fixture(autouse=True)
def gateway_env(monkeypatch):
    monkeypatch.setenv("ENTRA_CLIENT_ID", GATEWAY_ID)
    monkeypatch.setenv("AGENT_ORCHESTRATOR_CLIENT_ID", ORCH)
    monkeypatch.setenv("AGENT_PEER_CLIENT_ID", PEER)
    from agent_common import registry
    registry.reload()
    yield
    registry.reload()


def agent_claims(azp=ORCH, aud=GATEWAY_AUD, roles=("Agent.Invoke",), idtyp="app"):
    claims = {
        "aud": aud,
        "azp": azp,
        "roles": list(roles),
        "iss": "https://login.microsoftonline.com/tid/v2.0",
        "sub": f"sp-{azp}",
    }
    if idtyp is not None:
        claims["idtyp"] = idtyp
    return claims


def user_claims(groups=(ALLOWED_GROUP,), sub="user-oid-1"):
    return {
        "aud": GATEWAY_ID,
        "sub": sub,
        "preferred_username": "adele@example.com",
        "groups": list(groups),
        "iss": "https://login.microsoftonline.com/tid/v2.0",
        "scp": "User.Read",
    }


# --------------------------------------------------------------------------
# authorize_agent_caller — the branch that lets a group-less token in
# --------------------------------------------------------------------------


def test_authorized_agent_passes_without_any_group_claim():
    """The whole point: an agent token has no groups and must still be let in."""
    authorize_agent_caller(agent_claims())  # must not raise


def test_unregistered_agent_is_rejected():
    with pytest.raises(AgentAuthError) as exc:
        authorize_agent_caller(agent_claims(azp=ROGUE))
    assert exc.value.denial_reason == "unknown_agent"


def test_agent_without_invoke_role_is_rejected():
    with pytest.raises(AgentAuthError) as exc:
        authorize_agent_caller(agent_claims(roles=()))
    assert exc.value.denial_reason == "agent_not_authorized"


def test_token_minted_for_another_hop_is_rejected():
    """Audience narrowing — a token for the peer must not work on the gateway."""
    with pytest.raises(AgentAuthError) as exc:
        authorize_agent_caller(agent_claims(aud=f"api://{PEER}"))
    assert exc.value.denial_reason == "wrong_audience"


def test_a_human_token_cannot_take_the_agent_path():
    """No idtyp='app' means not a machine, regardless of what else it carries."""
    with pytest.raises(AgentAuthError) as exc:
        authorize_agent_caller(agent_claims(idtyp=None))
    assert exc.value.denial_reason == "not_an_agent_token"


def test_bare_app_id_audience_is_accepted():
    """Entra mints `aud` as the App ID URI or the bare app id depending on the
    resource app's accessTokenAcceptedVersion. Both name the same app.

    The gateway's own JWT validator already accepts both forms, so rejecting
    the bare form here would deny every agent call in a tenant configured the
    other way -- a failure that only shows up against a real tenant.
    """
    authorize_agent_caller(agent_claims(aud=GATEWAY_ID))  # must not raise


def test_empty_audience_is_never_a_match():
    with pytest.raises(AgentAuthError) as exc:
        authorize_agent_caller(agent_claims(aud=""))
    assert exc.value.denial_reason == "wrong_audience"


def test_list_audience_is_rejected_rather_than_crashing():
    """`aud` is a string from Entra, but the JWT spec permits a list. Fail
    closed on the shape we do not expect instead of raising AttributeError."""
    with pytest.raises(AgentAuthError) as exc:
        authorize_agent_caller(agent_claims(aud=[GATEWAY_AUD]))
    assert exc.value.denial_reason == "wrong_audience"


# --------------------------------------------------------------------------
# authorize_human_claims — one implementation, both entry paths
# --------------------------------------------------------------------------


@pytest.fixture
def human_acl(monkeypatch):
    monkeypatch.setattr(server, "ALLOWED_GROUPS", [ALLOWED_GROUP])
    monkeypatch.setattr(server, "BLOCKED_USERS", ["blocked-oid"])


def test_human_in_an_allowed_group_is_authorized(human_acl):
    assert authorize_human_claims(user_claims()) is None


def test_human_in_no_allowed_group_is_denied(human_acl):
    denial = authorize_human_claims(user_claims(groups=(OTHER_GROUP,)))
    assert denial is not None and denial.denial_reason == "no_group_membership"


def test_blocked_human_is_denied(human_acl):
    denial = authorize_human_claims(user_claims(sub="blocked-oid"))
    assert denial is not None and denial.denial_reason == "blocked_user"


def test_no_configured_groups_denies_everyone(monkeypatch):
    monkeypatch.setattr(server, "ALLOWED_GROUPS", [])
    monkeypatch.setattr(server, "BLOCKED_USERS", [])
    denial = authorize_human_claims(user_claims())
    assert denial is not None and denial.denial_reason == "no_group_configuration"


# --------------------------------------------------------------------------
# The middleware itself — is the branch actually wired up?
# --------------------------------------------------------------------------


@server.app.get("/__auth_probe_raises")
async def _auth_probe_raises():
    """Exists only so a test can prove a downstream failure is not laundered
    into an authentication failure. Reachable only with a valid token."""
    raise RuntimeError("downstream exploded")


@pytest.fixture
def client(monkeypatch, human_acl):
    """A TestClient whose token validator is a lookup table, not a network call."""
    tokens: dict[str, dict] = {}

    async def fake_validate(token: str) -> dict:
        if token not in tokens:
            raise ValueError(f"Unknown token: {token}")
        return tokens[token]

    monkeypatch.setattr(server.token_validator, "validate", fake_validate)
    monkeypatch.setattr(server, "is_auth_disabled", lambda _service: False)
    with TestClient(server.app, raise_server_exceptions=False) as c:
        yield c, tokens


def test_middleware_admits_an_agent_with_no_groups(client):
    c, tokens = client
    tokens["agent-tok"] = agent_claims()
    r = c.get("/me", headers={"Authorization": "Bearer agent-tok"})
    assert r.status_code == 200


def test_middleware_rejects_an_unknown_agent(client):
    c, tokens = client
    tokens["rogue-tok"] = agent_claims(azp=ROGUE)
    r = c.get("/me", headers={"Authorization": "Bearer rogue-tok"})
    assert r.status_code == 403
    assert r.json()["denial_reason"] == "unknown_agent"


def test_middleware_still_group_checks_a_direct_human(client):
    c, tokens = client
    tokens["outsider"] = user_claims(groups=(OTHER_GROUP,))
    r = c.get("/me", headers={"Authorization": "Bearer outsider"})
    assert r.status_code == 403
    assert r.json()["denial_reason"] == "no_group_membership"


def test_middleware_admits_a_direct_human_in_an_allowed_group(client):
    c, tokens = client
    tokens["insider"] = user_claims()
    r = c.get("/me", headers={"Authorization": "Bearer insider"})
    assert r.status_code == 200


def test_delegated_user_must_also_pass_the_group_check(client):
    """An agent must not be a way around the gateway's own ACL.

    Without this, any agent holding Agent.Invoke could present a delegated
    token for ANY user in the tenant -- including users the gateway would
    refuse to their face -- and have it accepted.
    """
    c, tokens = client
    tokens["agent-tok"] = agent_claims()
    tokens["outsider-obo"] = user_claims(groups=(OTHER_GROUP,))
    r = c.get(
        "/me",
        headers={
            "Authorization": "Bearer agent-tok",
            "X-Delegated-User-Token": "outsider-obo",
        },
    )
    assert r.status_code == 403
    assert r.json()["denial_reason"] == "no_group_membership"


def test_delegated_user_must_also_pass_the_blocklist(client):
    """Blocking a user must not be bypassable by routing through an agent."""
    c, tokens = client
    tokens["agent-tok"] = agent_claims()
    tokens["blocked-obo"] = user_claims(sub="blocked-oid")
    r = c.get(
        "/me",
        headers={
            "Authorization": "Bearer agent-tok",
            "X-Delegated-User-Token": "blocked-obo",
        },
    )
    assert r.status_code == 403
    assert r.json()["denial_reason"] == "blocked_user"


def test_a_valid_delegated_user_is_admitted(client):
    c, tokens = client
    tokens["agent-tok"] = agent_claims()
    tokens["good-obo"] = user_claims()
    r = c.get(
        "/me",
        headers={
            "Authorization": "Bearer agent-tok",
            "X-Delegated-User-Token": "good-obo",
        },
    )
    assert r.status_code == 200
    # The human, not the agent, is who the request is on behalf of.
    assert r.json()["user"]["email"] == "adele@example.com"


def test_an_invalid_delegated_token_is_rejected_not_ignored(client):
    """Silently dropping it would downgrade the call to machine privileges
    instead of refusing a token that failed validation."""
    c, tokens = client
    tokens["agent-tok"] = agent_claims()
    r = c.get(
        "/me",
        headers={
            "Authorization": "Bearer agent-tok",
            "X-Delegated-User-Token": "forged",
        },
    )
    assert r.status_code == 401


def test_an_agent_may_not_present_a_second_agent_token_as_the_user(client):
    """X-Delegated-User-Token must carry a human. An app-only token there
    would otherwise make a machine call look delegated."""
    c, tokens = client
    tokens["agent-tok"] = agent_claims()
    tokens["peer-app-tok"] = agent_claims(azp=PEER)
    r = c.get(
        "/me",
        headers={
            "Authorization": "Bearer agent-tok",
            "X-Delegated-User-Token": "peer-app-tok",
        },
    )
    assert r.status_code == 403
    assert r.json()["denial_reason"] == "delegated_token_not_a_user"


def test_downstream_failure_is_not_reported_as_an_auth_failure(client):
    """The machine branch must not run the downstream handler inside the auth
    try/except -- an application error there would surface as a 401 with a
    denial_reason, sending an operator to debug authentication instead of the
    actual crash."""
    c, tokens = client
    tokens["agent-tok"] = agent_claims()
    r = c.get("/__auth_probe_raises", headers={"Authorization": "Bearer agent-tok"})
    assert r.status_code == 500, f"got {r.status_code}: {r.text}"


def test_downstream_failure_on_the_human_path_is_also_a_500(client):
    """Control for the test above: both paths must behave the same way."""
    c, tokens = client
    tokens["insider"] = user_claims()
    r = c.get("/__auth_probe_raises", headers={"Authorization": "Bearer insider"})
    assert r.status_code == 500, f"got {r.status_code}: {r.text}"
