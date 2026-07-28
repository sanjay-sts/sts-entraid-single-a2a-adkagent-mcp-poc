"""MCP — machine principals resolve a role from their app id, and cannot use Graph.

Three levels, deliberately:

  * the door (`_AgentTokenVerifier`) — an app-only token carries `roles`, never
    `scp`, so it can never satisfy the delegated scope the human verifier
    requires. Without a second verifier the machine branch below is
    unreachable, and none of the rest of this file would ever run in
    production.
  * the middleware (`UserContextMiddleware._resolve_context`) — where an
    agent's role is resolved from its app id, and where the check that an
    agent may only assume a role it actually holds finally lands.
  * the tools — Graph's /me endpoints need a human, and there isn't one.

The middleware tests drive `_resolve_context` directly with the two FastMCP
dependencies stubbed, because the guard helpers being correct says nothing
about whether the middleware routes to them.
"""
import textwrap

import pytest

from mcp_server import server as mcp_server
from mcp_server.policy import TomlPolicyEvaluator
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.auth import AccessToken

ORCH = "11111111-1111-1111-1111-111111111111"
UNKNOWN_AGENT = "99999999-9999-9999-9999-999999999999"
ADMIN_GROUP = "aaaaaaaa-0000-0000-0000-000000000001"

ENTRA_ISS = "https://login.microsoftonline.com/tid/v2.0"


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_contextvars():
    """Every test starts from the module defaults and leaves them there.

    ContextVars survive across tests in the same task, so a leaked "machine"
    would silently make later Graph-tool tests pass for the wrong reason.
    """
    def reset():
        mcp_server.current_principal_type.set("delegated")
        mcp_server.current_agent_id.set("")
        mcp_server.current_user_provider.set("entra")
        mcp_server.current_user_token.set("")
        mcp_server.current_user_role.set("none")
        mcp_server.current_user_email.set("")

    reset()
    yield
    reset()


@pytest.fixture
def evaluator(tmp_path):
    """A tenant where the orchestrator is a developer and one group grants admin."""
    config = tmp_path / "permissions.toml"
    config.write_text(textwrap.dedent(f"""
        [group_rules.entra]
        "{ADMIN_GROUP}" = "admin"

        [agent_rules.entra]
        "{ORCH}" = "developer"

        [defaults]
        unknown_users = "none"
    """))
    return TomlPolicyEvaluator(config)


@pytest.fixture
def middleware(evaluator):
    return mcp_server.UserContextMiddleware(evaluator)


def agent_token(azp=ORCH, roles=("Agent.Invoke",), extra=None):
    """An Entra app-only token: `roles`, no `scp`, idtyp='app'."""
    claims = {
        "iss": ENTRA_ISS,
        "aud": "gw-id",
        "azp": azp,
        "idtyp": "app",
        "roles": list(roles),
        "sub": f"sp-{azp}",
    }
    if extra:
        claims.update(extra)
    return AccessToken(
        token="agent-token-string", client_id=azp, scopes=[], claims=claims
    )


def human_token(groups=(ADMIN_GROUP,), scopes=("access_as_user",)):
    claims = {
        "iss": ENTRA_ISS,
        "aud": "gw-id",
        "preferred_username": "adele@example.com",
        "groups": list(groups),
        "scp": " ".join(scopes),
        "sub": "user-oid-1",
    }
    return AccessToken(
        token="user-token-string",
        client_id="gw-id",
        scopes=list(scopes),
        claims=claims,
    )


@pytest.fixture
def stub_request(monkeypatch):
    """Install a token + headers for `_resolve_context` to read."""
    def install(token, headers=None):
        monkeypatch.setattr(mcp_server, "get_access_token", lambda: token)
        monkeypatch.setattr(mcp_server, "get_http_headers", lambda: headers or {})

    return install


# --------------------------------------------------------------------------
# The door: an app-only token has to be able to get in at all
# --------------------------------------------------------------------------


@pytest.fixture
def agent_verifier(monkeypatch):
    """An _AgentTokenVerifier whose JWT validation always succeeds.

    Signature/issuer/audience are the base class's job and are not what this
    verifier adds — what it adds is the refusal of anything that is not an
    app-only token, and that is all these tests exercise.
    """
    from fastmcp.server.auth.providers.azure import AzureJWTVerifier

    verifier = mcp_server._AgentTokenVerifier(client_id="gw-id", tenant_id="tid")
    holder = {}

    async def fake_super(self, token):
        return holder.get("result")

    monkeypatch.setattr(AzureJWTVerifier, "verify_token", fake_super)
    return verifier, holder


async def test_app_only_token_is_accepted_by_the_agent_verifier(agent_verifier):
    """The reason this verifier exists: an app token has no `scp`, so the human
    verifier's required_scopes can never match it."""
    verifier, holder = agent_verifier
    holder["result"] = agent_token()
    assert await verifier.verify_token("tok") is not None


async def test_a_human_token_cannot_use_the_agent_verifier(agent_verifier):
    """This verifier requires no scope. If it accepted user tokens it would be a
    way for a human token to skip the delegated scope check entirely."""
    verifier, holder = agent_verifier
    holder["result"] = human_token()
    assert await verifier.verify_token("tok") is None


async def test_a_scopeless_human_token_is_still_refused(agent_verifier):
    """The token the loosening would most plausibly leak: no scp, no idtyp."""
    verifier, holder = agent_verifier
    holder["result"] = human_token(scopes=())
    assert await verifier.verify_token("tok") is None


async def test_agent_verifier_propagates_a_base_class_rejection(agent_verifier):
    verifier, holder = agent_verifier
    holder["result"] = None
    assert await verifier.verify_token("tok") is None


def test_agent_verifier_is_registered_in_the_auth_chain(monkeypatch):
    """A verifier nothing constructs is a verifier that never runs."""
    monkeypatch.setattr(mcp_server, "TENANT_ID", "tid")
    monkeypatch.setattr(mcp_server, "CLIENT_ID", "gw-id")
    monkeypatch.setattr(mcp_server, "is_auth_disabled", lambda _s: False)

    auth = mcp_server._build_auth()

    assert any(
        isinstance(v, mcp_server._AgentTokenVerifier) for v in auth.verifiers
    ), "no _AgentTokenVerifier in the MultiAuth chain — agent tokens cannot get in"


# --------------------------------------------------------------------------
# The middleware: resolving a machine principal
# --------------------------------------------------------------------------


def test_agent_gets_its_role_from_its_app_id(middleware, stub_request):
    stub_request(agent_token())

    middleware._resolve_context(raise_on_error=True)

    assert mcp_server.current_principal_type.get() == "machine"
    assert mcp_server.current_agent_id.get() == ORCH
    assert mcp_server.current_user_role.get() == "developer"
    # No human upstream, so no email to attribute the call to.
    assert mcp_server.current_user_email.get() == ""


def test_agent_cannot_assume_a_role_it_does_not_hold(middleware, stub_request):
    """The gap carried since Task 5.

    The gateway forwards X-Assume-Role without checking it — it is not the role
    enforcement point. If this tier does not check it either, an agent simply
    names 'admin' and is granted it.
    """
    stub_request(agent_token(), {"x-assume-role": "admin"})

    with pytest.raises(ToolError) as exc:
        middleware._resolve_context(raise_on_error=True)

    assert "[TOOL_DENIAL]" in str(exc.value)
    assert ORCH in str(exc.value)


def test_agent_may_assume_the_role_it_does_hold(middleware, stub_request):
    """Control for the test above — proving it denies the wrong role rather than
    denying the header outright."""
    stub_request(agent_token(), {"x-assume-role": "developer"})

    middleware._resolve_context(raise_on_error=True)

    assert mcp_server.current_user_role.get() == "developer"


def test_unregistered_agent_gets_no_role(middleware, stub_request):
    stub_request(agent_token(azp=UNKNOWN_AGENT))

    with pytest.raises(ToolError) as exc:
        middleware._resolve_context(raise_on_error=True)

    assert "[TOOL_DENIAL]" in str(exc.value)
    assert UNKNOWN_AGENT in str(exc.value)


def test_group_claims_on_an_agent_token_grant_nothing(middleware, stub_request):
    """An app token is not supposed to carry `groups`, but nothing stops one.

    If the machine path fell through to the human path — or consulted group
    rules as well as agent rules — an agent could be handed admin by a claim
    its own app registration controls.
    """
    stub_request(agent_token(azp=UNKNOWN_AGENT, extra={"groups": [ADMIN_GROUP]}))

    with pytest.raises(ToolError):
        middleware._resolve_context(raise_on_error=True)


def test_a_registered_agent_is_not_upgraded_by_group_claims(middleware, stub_request):
    """Same isolation, from the other side: the agent is known, and its
    agent_rules role must win over an admin group claim it should not have."""
    stub_request(agent_token(extra={"groups": [ADMIN_GROUP]}))

    middleware._resolve_context(raise_on_error=True)

    assert mcp_server.current_user_role.get() == "developer"


def test_tool_listing_for_a_roleless_agent_does_not_raise(middleware, stub_request):
    """Listing is lenient for humans; it must stay lenient for agents, or an
    unregistered agent gets an exception where it should get an empty list."""
    stub_request(agent_token(azp=UNKNOWN_AGENT))

    middleware._resolve_context(raise_on_error=False)

    assert mcp_server.current_user_role.get() == "none"


def test_agent_needs_no_assume_role_header(middleware, stub_request):
    """A human without the header is told to pick a role. An agent has nobody to
    ask, and get_agent_roles returns at most one role, so there is nothing to
    pick — requiring the header would just break every event-triggered call."""
    stub_request(agent_token())

    middleware._resolve_context(raise_on_error=True)  # must not raise

    assert mcp_server.current_user_role.get() == "developer"


# --------------------------------------------------------------------------
# The middleware: the human path must be unchanged, and must clear machine state
# --------------------------------------------------------------------------


def test_human_still_resolves_from_groups(middleware, stub_request):
    stub_request(human_token(), {"x-assume-role": "admin"})

    middleware._resolve_context(raise_on_error=True)

    assert mcp_server.current_principal_type.get() == "delegated"
    assert mcp_server.current_user_role.get() == "admin"
    assert mcp_server.current_user_email.get() == "adele@example.com"


def test_human_request_clears_a_previous_machine_principal(middleware, stub_request):
    """Stateless HTTP reuses contexts. If the human path did not reset these,
    a Graph call after an agent call would be refused for no visible reason."""
    mcp_server.current_principal_type.set("machine")
    mcp_server.current_agent_id.set(ORCH)
    stub_request(human_token(), {"x-assume-role": "admin"})

    middleware._resolve_context(raise_on_error=True)

    assert mcp_server.current_principal_type.get() == "delegated"
    assert mcp_server.current_agent_id.get() == ""


def test_dev_bypass_clears_a_previous_machine_principal(middleware):
    """Same staleness, via the other entry point."""
    mcp_server.current_principal_type.set("machine")
    mcp_server.current_agent_id.set(ORCH)

    middleware._set_bypass_context()

    assert mcp_server.current_principal_type.get() == "delegated"
    assert mcp_server.current_agent_id.get() == ""


# --------------------------------------------------------------------------
# The guard helper
# --------------------------------------------------------------------------


def test_require_delegated_user_refuses_a_machine():
    mcp_server.current_principal_type.set("machine")
    mcp_server.current_agent_id.set(ORCH)

    error = mcp_server._require_delegated_user()

    assert error is not None
    assert error["error"] == "no_delegated_user"
    # Name the agent: with no human in the request there is nothing else for an
    # operator to correlate the refusal against.
    assert error["agent_id"] == ORCH


def test_require_delegated_user_allows_a_human():
    assert mcp_server._require_delegated_user() is None


# --------------------------------------------------------------------------
# OBO is never attempted without a user assertion
# --------------------------------------------------------------------------


@pytest.fixture
def recording_exchanger(monkeypatch):
    """A stand-in OBO exchanger that records whether it was asked to exchange.

    Asserting `_get_graph_token(...) is None` alone proves nothing — it returns
    None when no exchanger is configured, which is the case in every test
    environment. The property that matters is that the exchange is never
    ATTEMPTED, and only a recording double can show that.
    """
    calls = []

    class FakeExchanger:
        async def get_graph_token(self, user_token, scopes=None):
            calls.append((user_token, scopes))
            return "graph-token"

    monkeypatch.setattr(mcp_server, "get_obo_exchanger", lambda: FakeExchanger())
    return calls


async def test_obo_is_never_attempted_for_a_machine_principal(recording_exchanger):
    """OBO exchanges a *user* assertion. A machine has none — sending the agent's
    own token would ask Entra to treat the agent as the subject."""
    mcp_server.current_principal_type.set("machine")
    mcp_server.current_user_token.set("agent-token-string")

    token = await mcp_server._get_graph_token(["https://graph.microsoft.com/User.Read"])

    assert token is None
    assert recording_exchanger == [], "OBO was attempted for a machine principal"


async def test_obo_is_attempted_for_a_delegated_principal(recording_exchanger):
    """Control: without this, the test above passes even if the guard is absent."""
    mcp_server.current_principal_type.set("delegated")
    mcp_server.current_user_token.set("user-token-string")

    token = await mcp_server._get_graph_token(["https://graph.microsoft.com/User.Read"])

    assert token == "graph-token"
    assert len(recording_exchanger) == 1


# --------------------------------------------------------------------------
# The Graph tools
# --------------------------------------------------------------------------


@pytest.fixture
def no_http(monkeypatch):
    """Make any outbound HTTP call a hard failure.

    The guards must return before a request is built — a tool that refuses only
    after calling Graph with an app-only token has already leaked the call.
    """
    class Exploding:
        def __init__(self, *a, **kw):
            raise AssertionError("a Graph request was made for a machine principal")

    monkeypatch.setattr(mcp_server.httpx, "AsyncClient", Exploding)


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda: mcp_server.get_user_profile(), id="get_user_profile"),
        pytest.param(lambda: mcp_server.list_files(), id="list_files"),
        pytest.param(
            lambda: mcp_server.send_email("a@b.com", "s", "b"), id="send_email"
        ),
    ],
)
async def test_graph_tools_refuse_a_machine_principal(call, no_http):
    mcp_server.current_principal_type.set("machine")
    mcp_server.current_agent_id.set(ORCH)

    result = await call()

    assert result["error"] == "no_delegated_user"
    assert result["agent_id"] == ORCH


async def test_graph_tool_still_serves_a_delegated_user(monkeypatch):
    """Control: the guard must not be refusing everyone."""
    mcp_server.current_principal_type.set("delegated")
    mcp_server.current_user_provider.set("entra")
    mcp_server.current_user_token.set("user-token-string")
    monkeypatch.setattr(mcp_server, "get_obo_exchanger", lambda: None)

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"displayName": "Adele"}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **kw):
            return FakeResponse()

    monkeypatch.setattr(mcp_server.httpx, "AsyncClient", FakeClient)

    result = await mcp_server.get_user_profile()

    assert result["displayName"] == "Adele"
