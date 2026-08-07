"""Orchestrator — fan-out is where one identity becomes several.

Every other hop in this system carries one identity to one callee. The
orchestrator turns a single inbound principal into N outbound calls, which
makes it the one place where "the user token is exchanged per hop" has to hold
N times over rather than once, and the one place where a partial failure could
quietly change what a call is authorized as.

As in test_peer_agent.py, only the JWT validator is stubbed. Replacing
`_authenticate` wholesale — as the plan's suite did — leaves the delegated
path, the registry check and the rider-token handling completely untested.
"""
import pytest
from fastapi.testclient import TestClient

from agent_common.jwt_validator import TokenVerificationError

EVT = "evt-id"
ORCH = "orch-id"
PEER = "peer-id"
GATEWAY = "gw-id"
ROGUE = "rogue-id"

ORCH_AUD = f"api://{ORCH}"
ENTRA_ISS = "https://login.microsoftonline.com/tid/v2.0"


@pytest.fixture(autouse=True)
def orch_env(monkeypatch):
    monkeypatch.setenv("ENTRA_CLIENT_ID", GATEWAY)
    monkeypatch.setenv("AGENT_ORCHESTRATOR_CLIENT_ID", ORCH)
    monkeypatch.setenv("AGENT_PEER_CLIENT_ID", PEER)
    monkeypatch.setenv("AGENT_EVENT_TRIGGER_CLIENT_ID", EVT)
    monkeypatch.setenv("ENTRA_TENANT_ID", "tid")
    monkeypatch.setenv("BLOCKED_USERS", "")
    from agent_common import registry
    registry.reload()
    yield
    registry.reload()


def agent_claims(azp=EVT, aud=ORCH_AUD, roles=("Agent.Invoke",)):
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
        "aud": ORCH_AUD,
        "sub": sub,
        "preferred_username": email,
        "scp": "access_as_user",
    }


@pytest.fixture
def orch(orch_env):
    from orchestrator_agent import server as orch_module
    return orch_module


class FakeTokenProvider:
    def __init__(self):
        self.calls = []

    async def get_agent_token(self, callee):
        self.calls.append(callee)
        return f"agent-token-for-{callee}"


class FakeExchanger:
    """Records exchanges. `fail_for` makes one callee's exchange blow up."""

    def __init__(self, fail_for=None):
        self.calls = []
        self.fail_for = fail_for

    async def exchange_for(self, user_token, callee):
        self.calls.append((user_token, callee))
        if callee == self.fail_for:
            raise RuntimeError("OBO exchange refused by the tenant")
        return f"user-token-for-{callee}"


@pytest.fixture
def client(orch, monkeypatch):
    """(client, tokens, sent, provider, exchanger) with nothing leaving the process.

    Registering a token means "this string is a genuine, correctly signed Entra
    token bearing these claims"; everything downstream of the signature is then
    exercised for real.
    """
    tokens: dict[str, dict] = {}
    sent: list[dict] = []
    provider = FakeTokenProvider()
    exchanger = FakeExchanger()

    class FakeValidator:
        async def validate(self, token, expected_audience):
            if token not in tokens:
                raise TokenVerificationError(f"Signing key not found for {token!r}")
            return tokens[token]

    class FakeResponse:
        def __init__(self, url):
            self.status_code = 403 if "deny" in url else 200

        def json(self):
            return {"echo": "subagent-response"}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None, timeout=None):
            sent.append({"url": url, "payload": json, "headers": headers or {}})
            return FakeResponse(url)

    monkeypatch.setattr(orch, "_validator", FakeValidator())
    monkeypatch.setattr(orch, "_token_provider", provider)
    monkeypatch.setattr(orch, "_token_exchanger", exchanger)
    monkeypatch.setattr(orch.httpx, "AsyncClient", FakeClient)

    with TestClient(orch.app) as c:
        yield c, tokens, sent, provider, exchanger


def sent_to(sent, callee):
    """The captured request for one callee, by URL."""
    port = "10005" if callee == "peer" else "10000"
    matches = [s for s in sent if port in s["url"]]
    return matches[0] if matches else None


# --------------------------------------------------------------------------
# Who may dispatch at all
# --------------------------------------------------------------------------


def test_health_is_public(client):
    c, *_ = client
    assert c.get("/health").json()["agent"] == "orchestrator"


def test_dispatch_without_a_token_is_rejected(client):
    c, *_ = client
    resp = c.post("/dispatch", json={"task": "status"})
    assert resp.status_code == 401
    assert resp.json()["denial_reason"] == "missing_token"


def test_dispatch_with_an_unverifiable_token_is_rejected(client):
    c, *_ = client
    resp = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer forged"},
    )
    assert resp.status_code == 401
    assert resp.json()["denial_level"] == "agent"


def test_an_unregistered_agent_cannot_dispatch(client):
    c, tokens, *_ = client
    tokens["rogue"] = agent_claims(azp=ROGUE)
    resp = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer rogue"},
    )
    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "unknown_agent"


def test_a_token_minted_for_another_hop_is_rejected(client):
    c, tokens, *_ = client
    tokens["wrong-aud"] = agent_claims(aud=f"api://{PEER}")
    resp = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer wrong-aud"},
    )
    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "wrong_audience"


def test_the_peer_cannot_dispatch(client):
    """The call graph is directed: orchestrator -> peer, never the reverse."""
    c, tokens, *_ = client
    tokens["peer-tok"] = agent_claims(azp=PEER)
    resp = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer peer-tok"},
    )
    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "unknown_agent"


def test_an_app_token_cannot_pose_as_the_delegated_user(client):
    c, tokens, *_ = client
    tokens["evt"] = agent_claims()
    tokens["peer-app"] = agent_claims(azp=PEER)
    resp = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer evt", "X-Delegated-User-Token": "peer-app"},
    )
    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "delegated_token_not_a_user"


def test_a_blocked_user_cannot_be_reached_through_an_agent(client, monkeypatch, orch):
    monkeypatch.setattr(orch, "BLOCKED_USERS", ["blocked-oid"])
    c, tokens, *_ = client
    tokens["evt"] = agent_claims()
    tokens["blocked-obo"] = user_claims(sub="blocked-oid")
    resp = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer evt", "X-Delegated-User-Token": "blocked-obo"},
    )
    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "blocked_user"


def test_an_invalid_delegated_token_is_rejected_not_ignored(client):
    c, tokens, *_ = client
    tokens["evt"] = agent_claims()
    resp = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer evt", "X-Delegated-User-Token": "forged"},
    )
    assert resp.status_code == 401


def test_an_unauthenticated_request_is_refused_before_its_body_is_parsed(client):
    c, *_ = client
    resp = c.post(
        "/dispatch", content=b"{not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_a_malformed_body_from_an_authorized_caller_is_a_400(client):
    c, tokens, *_ = client
    tokens["evt"] = agent_claims()
    resp = c.post(
        "/dispatch", content=b"{not json",
        headers={"Authorization": "Bearer evt", "Content-Type": "application/json"},
    )
    assert resp.status_code == 400


# --------------------------------------------------------------------------
# Machine fan-out — no human, so no user token anywhere
# --------------------------------------------------------------------------


def test_machine_dispatch_mints_one_token_per_callee(client):
    """Audience narrowing at fan-out: each subagent gets a token minted for IT,
    never a forwarded copy of the orchestrator's own inbound token."""
    c, tokens, sent, provider, _ = client
    tokens["evt"] = agent_claims()

    body = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer evt"},
    ).json()

    assert sorted(provider.calls) == ["gateway", "peer"]
    assert sent_to(sent, "peer")["headers"]["Authorization"] == "Bearer agent-token-for-peer"
    assert sent_to(sent, "gateway")["headers"]["Authorization"] == "Bearer agent-token-for-gateway"
    assert body["principal_type"] == "machine"
    assert body["acting_agent"] == EVT


def test_machine_dispatch_never_exchanges_a_user_token(client):
    """No human upstream — an on-behalf-of exchange has no assertion to use."""
    c, tokens, sent, _, exchanger = client
    tokens["evt"] = agent_claims()

    c.post("/dispatch", json={"task": "status"}, headers={"Authorization": "Bearer evt"})

    assert exchanger.calls == []
    for callee in ("peer", "gateway"):
        assert "X-Delegated-User-Token" not in sent_to(sent, callee)["headers"]


# --------------------------------------------------------------------------
# Delegated fan-out — one inbound user token becomes N narrow ones
# --------------------------------------------------------------------------


def test_delegated_dispatch_exchanges_the_user_token_per_callee(client):
    c, tokens, sent, _, exchanger = client
    tokens["gw"] = agent_claims(azp=EVT)
    tokens["obo"] = user_claims()

    body = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer gw", "X-Delegated-User-Token": "obo"},
    ).json()

    assert sorted(callee for _, callee in exchanger.calls) == ["gateway", "peer"]
    # Always the INBOUND token that gets exchanged, never an already-exchanged one.
    assert all(t == "obo" for t, _ in exchanger.calls)
    assert body["on_behalf_of"] == "adele@example.com"
    assert body["principal_type"] == "delegated"


def test_each_callee_receives_a_different_user_token(client):
    """The fan-out version of "exchange, never forward".

    Two subagents must not end up holding the same user token, and neither may
    hold the one the orchestrator was given — otherwise either could replay it
    at the other, or back at us.
    """
    c, tokens, sent, _, _ = client
    tokens["gw"] = agent_claims(azp=EVT)
    tokens["obo"] = user_claims()

    c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer gw", "X-Delegated-User-Token": "obo"},
    )

    peer_tok = sent_to(sent, "peer")["headers"]["X-Delegated-User-Token"]
    gw_tok = sent_to(sent, "gateway")["headers"]["X-Delegated-User-Token"]
    assert peer_tok != gw_tok
    assert "obo" not in (peer_tok, gw_tok)


def test_a_failed_exchange_fails_that_hop_rather_than_downgrading_it(client, orch, monkeypatch):
    """The quiet-privilege-change case.

    If a failing on-behalf-of exchange were caught and the call made anyway, a
    delegated request would silently proceed with machine privileges — a
    different principal than the caller asked for, with nothing in the response
    to say so. The hop must fail instead.
    """
    monkeypatch.setattr(orch, "_token_exchanger", FakeExchanger(fail_for="peer"))
    c, tokens, sent, _, _ = client
    tokens["gw"] = agent_claims(azp=EVT)
    tokens["obo"] = user_claims()

    body = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer gw", "X-Delegated-User-Token": "obo"},
    ).json()

    assert body["subagents"]["peer"]["ok"] is False
    assert sent_to(sent, "peer") is None, "the peer was called without the user token"
    # The other hop is unaffected — one failure must not take the fan-out down.
    assert body["subagents"]["gateway"]["ok"] is True


def test_a_subagent_failure_does_not_leak_the_exception_text(client, orch, monkeypatch):
    """A remote caller gets a stable reason; the detail goes to the log."""
    monkeypatch.setattr(orch, "_token_exchanger", FakeExchanger(fail_for="peer"))
    c, tokens, *_ = client
    tokens["gw"] = agent_claims(azp=EVT)
    tokens["obo"] = user_claims()

    peer = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer gw", "X-Delegated-User-Token": "obo"},
    ).json()["subagents"]["peer"]

    assert peer["error"] == "subagent_call_failed"
    assert "tenant" not in str(peer), f"exception text reached the caller: {peer}"


# --------------------------------------------------------------------------
# Reporting what actually happened
# --------------------------------------------------------------------------


def test_a_denied_subagent_is_reported_as_denied(client, orch, monkeypatch):
    """The testbed exists to show which layer refused what. A 403 from a
    subagent flattened into an indistinguishable success defeats the point."""
    monkeypatch.setattr(orch, "PEER_URL", "http://localhost:10005/deny")
    c, tokens, *_ = client
    tokens["evt"] = agent_claims()

    body = c.post(
        "/dispatch", json={"task": "status"},
        headers={"Authorization": "Bearer evt"},
    ).json()

    assert body["subagents"]["peer"]["status"] == 403
    assert body["subagents"]["peer"]["ok"] is False
    assert body["subagents"]["gateway"]["ok"] is True
