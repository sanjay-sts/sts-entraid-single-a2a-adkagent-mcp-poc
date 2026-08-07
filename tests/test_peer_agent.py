"""Peer agent — verifies its caller, and mints fresh tokens when it calls on.

Most of these drive the real `_authenticate` with only the JWT validator
stubbed, rather than replacing `_authenticate` wholesale. Signature checking is
covered by test_agent_registry.py; what is worth testing here is the wiring —
which checks run, in what order, and what happens to a delegated user token on
the way through. A suite that stubs the whole of `_authenticate` cannot see any
of that, and the delegated path is where the interesting mistakes live.
"""
import pytest
from fastapi.testclient import TestClient

from agent_common.jwt_validator import TokenVerificationError
from agent_common.principal import (
    AgentAuthError,
    Principal,
    verify_delegated_user,
)

ORCH = "orch-id"
PEER = "peer-id"
GATEWAY = "gw-id"
ROGUE = "rogue-id"

PEER_AUD = f"api://{PEER}"
ENTRA_ISS = "https://login.microsoftonline.com/tid/v2.0"


@pytest.fixture(autouse=True)
def peer_env(monkeypatch):
    monkeypatch.setenv("ENTRA_CLIENT_ID", GATEWAY)
    monkeypatch.setenv("AGENT_ORCHESTRATOR_CLIENT_ID", ORCH)
    monkeypatch.setenv("AGENT_PEER_CLIENT_ID", PEER)
    monkeypatch.setenv("ENTRA_TENANT_ID", "tid")
    monkeypatch.setenv("BLOCKED_USERS", "")
    from agent_common import registry
    registry.reload()
    yield
    registry.reload()


def agent_claims(azp=ORCH, aud=PEER_AUD, roles=("Agent.Invoke",)):
    return {
        "iss": ENTRA_ISS,
        "aud": aud,
        "azp": azp,
        "idtyp": "app",
        "roles": list(roles),
        "sub": f"sp-{azp}",
    }


def user_claims(sub="user-oid-1", email="adele@example.com"):
    return {
        "iss": ENTRA_ISS,
        "aud": PEER_AUD,
        "sub": sub,
        "preferred_username": email,
        "scp": "access_as_user",
    }


# --------------------------------------------------------------------------
# verify_delegated_user — shared by every agent that accepts a rider token
# --------------------------------------------------------------------------


def test_an_ordinary_user_passes():
    verify_delegated_user(user_claims(), blocked_users=[])  # must not raise


def test_an_app_token_cannot_pose_as_the_delegated_user():
    """The mirror of an agent fabricating a human: presenting a second agent
    token in the user slot would make a machine call look delegated, inventing
    a human who is not party to the request."""
    with pytest.raises(AgentAuthError) as exc:
        verify_delegated_user(agent_claims(), blocked_users=[])
    assert exc.value.denial_reason == "delegated_token_not_a_user"


def test_a_blocked_user_is_refused():
    with pytest.raises(AgentAuthError) as exc:
        verify_delegated_user(user_claims(sub="blocked-oid"), blocked_users=["blocked-oid"])
    assert exc.value.denial_reason == "blocked_user"


def test_an_unblocked_user_passes_a_populated_blocklist():
    """Control: proving the check reads `sub` rather than refusing everyone."""
    verify_delegated_user(user_claims(), blocked_users=["someone-else"])


# --------------------------------------------------------------------------
# Outbound calls — a fresh token per hop, never a forwarded one
# --------------------------------------------------------------------------


class FakeTokenProvider:
    def __init__(self):
        self.calls = []

    async def get_agent_token(self, callee):
        self.calls.append(callee)
        return f"agent-token-for-{callee}"


class FakeExchanger:
    def __init__(self):
        self.calls = []

    async def exchange_for(self, user_token, callee):
        self.calls.append((user_token, callee))
        return f"user-token-for-{callee}"


async def test_machine_principal_sends_only_its_own_token():
    from agent_common.outbound import build_agent_headers

    provider, exchanger = FakeTokenProvider(), FakeExchanger()
    principal = Principal("machine", ORCH, ("Agent.Invoke",), None, None)

    headers = await build_agent_headers("gateway", principal, provider, exchanger)

    assert headers["Authorization"] == "Bearer agent-token-for-gateway"
    assert "X-Delegated-User-Token" not in headers
    assert exchanger.calls == [], "no user assertion exists to exchange"


async def test_delegated_principal_sends_a_re_exchanged_user_token():
    """The property that keeps audience narrowing intact past the first hop.

    Forwarding the inbound user token verbatim would hand the callee a token
    minted for US — replayable by that callee anywhere WE can be called. Each
    hop exchanges for its own callee instead.
    """
    from agent_common.outbound import build_agent_headers

    provider, exchanger = FakeTokenProvider(), FakeExchanger()
    principal = Principal(
        "delegated", ORCH, ("Agent.Invoke",), user_claims(), "inbound-user-token"
    )

    headers = await build_agent_headers("gateway", principal, provider, exchanger)

    assert headers["Authorization"] == "Bearer agent-token-for-gateway"
    assert headers["X-Delegated-User-Token"] == "user-token-for-gateway"
    assert headers["X-Delegated-User-Token"] != "inbound-user-token"
    assert exchanger.calls == [("inbound-user-token", "gateway")]


async def test_a_delegated_principal_without_a_token_does_not_claim_delegation():
    """derive_principal discards a dangling user token; this must not resurrect
    the header from user_claims alone."""
    from agent_common.outbound import build_agent_headers

    provider, exchanger = FakeTokenProvider(), FakeExchanger()
    principal = Principal("delegated", ORCH, (), user_claims(), None)

    headers = await build_agent_headers("gateway", principal, provider, exchanger)

    assert "X-Delegated-User-Token" not in headers
    assert exchanger.calls == []


# --------------------------------------------------------------------------
# The peer agent over HTTP
# --------------------------------------------------------------------------


@pytest.fixture
def peer(peer_env):
    from peer_agent import server as peer_module
    return peer_module


@pytest.fixture
def client(peer, monkeypatch):
    """A TestClient whose JWT validator is a lookup table, not a network call.

    Returns (client, tokens). Registering a token means "this string is a real,
    correctly signed Entra token bearing these claims" — everything downstream
    of the signature is then exercised for real.
    """
    tokens: dict[str, dict] = {}

    class FakeValidator:
        async def validate(self, token, expected_audience):
            if token not in tokens:
                raise TokenVerificationError(f"Signing key not found for {token!r}")
            return tokens[token]

    monkeypatch.setattr(peer, "_validator", FakeValidator())
    with TestClient(peer.app) as c:
        yield c, tokens


def test_health_is_public(client):
    c, _ = client
    resp = c.get("/health")
    assert resp.status_code == 200
    assert resp.json()["agent"] == "peer"


def test_invoke_without_a_token_is_rejected(client):
    c, _ = client
    resp = c.post("/invoke", json={"action": "status", "params": {}})
    assert resp.status_code == 401
    assert resp.json()["denial_reason"] == "missing_token"


def test_invoke_with_an_unverifiable_token_is_rejected(client):
    c, _ = client
    resp = c.post(
        "/invoke",
        json={"action": "status"},
        headers={"Authorization": "Bearer forged"},
    )
    assert resp.status_code == 401
    assert resp.json()["denial_level"] == "agent"


def test_an_unauthenticated_request_is_refused_before_its_body_is_parsed(client):
    """Parsing attacker-controlled input before authenticating it is free
    attack surface, and a malformed body must not turn a 401 into a 500."""
    c, _ = client
    resp = c.post(
        "/invoke",
        content=b"{not json at all",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_an_unregistered_agent_is_rejected(client):
    c, tokens = client
    tokens["rogue"] = agent_claims(azp=ROGUE)
    resp = c.post(
        "/invoke", json={"action": "status"},
        headers={"Authorization": "Bearer rogue"},
    )
    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "unknown_agent"


def test_a_token_minted_for_another_hop_is_rejected(client):
    """Audience narrowing: a token for the gateway must not work on the peer."""
    c, tokens = client
    tokens["wrong-aud"] = agent_claims(aud=f"api://{GATEWAY}")
    resp = c.post(
        "/invoke", json={"action": "status"},
        headers={"Authorization": "Bearer wrong-aud"},
    )
    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "wrong_audience"


def test_unknown_action_is_rejected(client):
    c, tokens = client
    tokens["orch"] = agent_claims()
    resp = c.post(
        "/invoke", json={"action": "nope", "params": {}},
        headers={"Authorization": "Bearer orch"},
    )
    assert resp.status_code == 400
    assert "unknown_action" in resp.json()["error"]


def test_status_action_reports_the_machine_principal(client):
    c, tokens = client
    tokens["orch"] = agent_claims()
    body = c.post(
        "/invoke", json={"action": "status", "params": {}},
        headers={"Authorization": "Bearer orch"},
    ).json()
    assert body["principal_type"] == "machine"
    assert body["acting_agent"] == ORCH
    assert body["on_behalf_of"] == ""
    assert body["result"]["healthy"] is True


def test_echo_action_round_trips(client):
    c, tokens = client
    tokens["orch"] = agent_claims()
    body = c.post(
        "/invoke", json={"action": "echo", "params": {"text": "hi"}},
        headers={"Authorization": "Bearer orch"},
    ).json()
    assert body["result"]["echoed"] == "hi"


def test_status_action_reports_the_delegated_user(client):
    """The human stays the subject; the agent is recorded as the actor."""
    c, tokens = client
    tokens["orch"] = agent_claims()
    tokens["obo"] = user_claims()
    body = c.post(
        "/invoke", json={"action": "status"},
        headers={"Authorization": "Bearer orch", "X-Delegated-User-Token": "obo"},
    ).json()
    assert body["principal_type"] == "delegated"
    assert body["acting_agent"] == ORCH
    assert body["on_behalf_of"] == "adele@example.com"


def test_a_second_agent_token_cannot_be_passed_off_as_the_user(client):
    c, tokens = client
    tokens["orch"] = agent_claims()
    tokens["peer-app"] = agent_claims(azp=PEER)
    resp = c.post(
        "/invoke", json={"action": "status"},
        headers={"Authorization": "Bearer orch", "X-Delegated-User-Token": "peer-app"},
    )
    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "delegated_token_not_a_user"


def test_a_blocked_user_cannot_be_reached_through_an_agent(client, monkeypatch, peer):
    """Blocking someone must not be bypassable by routing around the gateway."""
    monkeypatch.setattr(peer, "BLOCKED_USERS", ["blocked-oid"])
    c, tokens = client
    tokens["orch"] = agent_claims()
    tokens["blocked-obo"] = user_claims(sub="blocked-oid")
    resp = c.post(
        "/invoke", json={"action": "status"},
        headers={"Authorization": "Bearer orch", "X-Delegated-User-Token": "blocked-obo"},
    )
    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "blocked_user"


def test_an_invalid_delegated_token_is_rejected_not_ignored(client):
    """Dropping it silently would quietly downgrade the call to machine
    privileges instead of refusing a token that failed verification."""
    c, tokens = client
    tokens["orch"] = agent_claims()
    resp = c.post(
        "/invoke", json={"action": "status"},
        headers={"Authorization": "Bearer orch", "X-Delegated-User-Token": "forged"},
    )
    assert resp.status_code == 401


# --------------------------------------------------------------------------
# The peer as a caller
# --------------------------------------------------------------------------


@pytest.fixture
def outbound(peer, monkeypatch):
    """Capture what the peer would send to the gateway, without sending it."""
    sent = {}

    provider, exchanger = FakeTokenProvider(), FakeExchanger()
    monkeypatch.setattr(peer, "_token_provider", provider)
    monkeypatch.setattr(peer, "_exchanger", exchanger)

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"role": "none"}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None):
            sent["url"] = url
            sent["headers"] = headers or {}
            return FakeResponse()

    monkeypatch.setattr(peer.httpx, "AsyncClient", FakeClient)
    return sent, provider, exchanger


def test_calling_the_gateway_mints_a_token_for_the_gateway(client, outbound):
    """The registry declares peer -> gateway. This is the edge being real."""
    sent, provider, exchanger = outbound
    c, tokens = client
    tokens["orch"] = agent_claims()

    body = c.post(
        "/invoke", json={"action": "call_gateway"},
        headers={"Authorization": "Bearer orch"},
    ).json()

    assert provider.calls == ["gateway"]
    assert sent["headers"]["Authorization"] == "Bearer agent-token-for-gateway"
    assert "X-Delegated-User-Token" not in sent["headers"]
    assert body["result"]["gateway_status"] == 200


def test_calling_the_gateway_re_exchanges_the_user_token(client, outbound):
    """The peer must not forward the token minted for itself — that would be a
    token the gateway could replay back at the peer."""
    sent, provider, exchanger = outbound
    c, tokens = client
    tokens["orch"] = agent_claims()
    tokens["obo"] = user_claims()

    c.post(
        "/invoke", json={"action": "call_gateway"},
        headers={"Authorization": "Bearer orch", "X-Delegated-User-Token": "obo"},
    )

    assert exchanger.calls == [("obo", "gateway")]
    assert sent["headers"]["X-Delegated-User-Token"] == "user-token-for-gateway"
    assert sent["headers"]["X-Delegated-User-Token"] != "obo"
