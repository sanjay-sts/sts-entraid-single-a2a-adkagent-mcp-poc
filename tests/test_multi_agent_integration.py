"""Multi-agent integration — real Entra tokens, real services.

Everything else in this suite proves our *logic* against claims we constructed
ourselves. These are the only tests that can answer the question the whole
phase exists to settle: does Entra accept a certificate-signed assertion from
these app registrations, and what does it put in the tokens it returns?

Nothing here can be mutation-tested the way the rest of the branch was — there
is no tenant to run against yet. So each assertion was instead checked against
the code that has to satisfy it, and each failure message names the
configuration step that fixes it, because the operator running these will be
reading the message and not this file.

Skips cleanly until docs/ENTRA_AGENT_SETUP.md has been completed. The
delegated tests skip separately, since they additionally need a user token.
"""
import os
import time

import jwt
import pytest

pytestmark = pytest.mark.integration


def _claims(token: str) -> dict:
    """Read a token we just received from Entra over TLS.

    Signature verification is deliberately off: these tests inspect what Entra
    minted, and re-verifying a token fetched from the issuer over an
    authenticated channel would test PyJWT, not the tenant. Every *service* in
    this system verifies signatures — see agent_common/jwt_validator.py.
    """
    return jwt.decode(token, options={"verify_signature": False})


def _names_app(audience, client_id: str) -> bool:
    """True when `audience` names `client_id` in either form Entra emits.

    `aud` comes back as `api://<app-id>` or the bare app id depending on the
    resource app's accessTokenAcceptedVersion — a property of the tenant, not
    of the caller. Both are accepted everywhere in this codebase, so which one
    this tenant emits changes nothing; asserting only one form would fail a
    correctly configured tenant half the time.
    """
    return isinstance(audience, str) and audience.removeprefix("api://") == client_id


# ---------------------------------------------------------------------------
# The token itself — needs the tenant, not the services
# ---------------------------------------------------------------------------

@pytest.fixture
async def event_trigger_token(agents_configured):
    """A real app-only token, minted for the orchestrator with our certificate."""
    from agent_common import registry
    from agent_common.tokens import AgentTokenProvider

    provider = AgentTokenProvider(registry.get_agent("event-trigger"))
    try:
        yield await provider.get_agent_token("orchestrator")
    finally:
        await provider.close()


async def test_certificate_assertion_mints_a_token(event_trigger_token):
    """Entra accepted our cert-signed client assertion.

    This is the load-bearing test of the phase. If it fails, nothing else in
    this file is meaningful — check that the certificate uploaded to the app
    registration is the one in pki/certs (ENTRA_AGENT_SETUP.md §2).
    """
    assert event_trigger_token
    assert len(event_trigger_token.split(".")) == 3


async def test_minted_token_is_a_machine_token(event_trigger_token):
    from agent_common.principal import is_app_token

    claims = _claims(event_trigger_token)
    assert claims.get("idtyp") == "app", (
        "idtyp claim missing — configure the optional claim (ENTRA_AGENT_SETUP.md §4). "
        "is_app_token fails closed without it, so every agent call will be refused."
    )
    assert is_app_token(claims) is True


async def test_minted_token_is_narrowed_to_the_orchestrator(event_trigger_token):
    """Audience narrowing is the whole anti-replay story.

    Asserts the negative as well as the positive: a token that named every
    agent would satisfy the positive assertion alone while providing no
    narrowing at all.
    """
    claims = _claims(event_trigger_token)

    assert _names_app(claims.get("aud"), os.environ["AGENT_ORCHESTRATOR_CLIENT_ID"])
    assert not _names_app(claims.get("aud"), os.environ["AGENT_PEER_CLIENT_ID"])
    assert not _names_app(claims.get("aud"), os.environ["ENTRA_CLIENT_ID"])


async def test_minted_token_carries_the_invoke_role(event_trigger_token):
    claims = _claims(event_trigger_token)
    assert "Agent.Invoke" in claims.get("roles", []), (
        "Agent.Invoke not assigned to the event trigger on the orchestrator app "
        "— see ENTRA_AGENT_SETUP.md §5"
    )


async def test_minted_token_is_not_expired_on_arrival(event_trigger_token):
    """Cheap, but it catches a badly skewed clock before it looks like a bad key."""
    claims = _claims(event_trigger_token)
    assert claims.get("exp", 0) > time.time()


# ---------------------------------------------------------------------------
# The delegated exchange — needs the tenant and a user token
#
# This is the riskiest unknown in the phase and the plan had no test for it.
# The gateway→orchestrator hop is the first delegated exchange in the chain,
# and a browser sign-in produces exactly the gateway-audienced token it takes.
# ---------------------------------------------------------------------------

@pytest.fixture
async def obo_token(agents_configured, delegated_user_token):
    """The user's token, exchanged by the gateway for the orchestrator."""
    from agent_common import registry
    from agent_common.tokens import DelegatedTokenExchanger

    exchanger = DelegatedTokenExchanger(registry.get_agent("gateway"))
    return await exchanger.exchange_for(delegated_user_token, "orchestrator")


async def test_obo_exchange_narrows_the_user_token_to_the_callee(obo_token):
    """Per-hop exchange, not forwarding. The audience must move to the callee."""
    claims = _claims(obo_token)
    assert _names_app(claims.get("aud"), os.environ["AGENT_ORCHESTRATOR_CLIENT_ID"])


async def test_obo_token_still_names_the_human(obo_token, delegated_user_token):
    """Delegation, not impersonation: `sub` stays the person who signed in.

    If this ever flips to the agent's own identity, every downstream audit
    record silently attributes the human's actions to a service.
    """
    assert _claims(obo_token)["sub"] == _claims(delegated_user_token)["sub"]


async def test_obo_token_is_still_a_user_token(obo_token):
    """An exchanged token that came back app-only would be refused downstream.

    Every agent runs verify_delegated_user on the rider token, which rejects an
    app-only token outright. That check is correct; this asserts the exchange
    does not trip it.
    """
    from agent_common.principal import is_app_token

    assert is_app_token(_claims(obo_token)) is False


async def test_obo_token_carries_group_membership(obo_token):
    """The open question flagged since Task 6, finally answerable.

    The gateway authorizes humans by group membership. If the OBO-minted token
    drops the `groups` claim, every delegated agent call is denied
    `no_group_membership` — and the denial names group membership, not the
    exchange, so it reads like a permissions problem in the wrong place.
    """
    claims = _claims(obo_token)
    assert claims.get("groups"), (
        "OBO token has no `groups` claim. Add the groups optional claim to the "
        "gateway app registration's Access token, or the gateway will deny every "
        "delegated agent call with no_group_membership."
    )


# ---------------------------------------------------------------------------
# The machine fan-out — needs the tenant and every service running
# ---------------------------------------------------------------------------

@pytest.fixture
async def fanout(agents_configured, require_agent_services):
    """One event-triggered dispatch, shared by the assertions below.

    `fire` returns (http_status, body) — the status is checked here so a
    refused dispatch fails once, on the refusal, rather than as three
    confusing KeyErrors on a body that is an error document.
    """
    from event_trigger import fire

    status, body = await fire("status")
    assert 200 <= status < 300, f"orchestrator refused the dispatch ({status}): {body}"
    return body


async def test_event_triggered_fanout_resolves_a_machine_principal(fanout):
    assert fanout["principal_type"] == "machine"
    assert fanout["on_behalf_of"] == ""
    assert set(fanout["subagents"]) == {"peer", "gateway"}


async def test_both_legs_of_the_fanout_actually_succeeded(fanout):
    """`subagents` always has both keys, so membership proves nothing.

    The orchestrator reports each leg's outcome in `ok` precisely so a denial
    is not shape-indistinguishable from success. A test that only checked the
    keys were present would pass with both legs refused.
    """
    for callee, leg in fanout["subagents"].items():
        assert leg["ok"] is True, f"{callee} leg failed: {leg}"


async def test_peer_subagent_independently_resolved_the_machine_principal(fanout):
    """The peer verified the *orchestrator* — not the event trigger that started it.

    Each hop authenticates its immediate caller. The event trigger's identity
    does not travel; the orchestrator's does.
    """
    peer = fanout["subagents"]["peer"]["response"]

    assert peer["principal_type"] == "machine"
    assert peer["acting_agent"] == os.environ["AGENT_ORCHESTRATOR_CLIENT_ID"]
    assert peer["on_behalf_of"] == ""
    assert peer["result"]["healthy"] is True


# ---------------------------------------------------------------------------
# Rejection paths
# ---------------------------------------------------------------------------

async def test_peer_rejects_a_token_minted_for_the_orchestrator(
    agents_configured, require_agent_services, peer_url, event_trigger_token
):
    """Cross-hop replay: a token for the orchestrator must not open the peer.

    The status is 401/`validation_failed`, not 403/`wrong_audience`: the peer
    checks the audience twice, and the JWKS validator gets there first, so the
    claim-level check never sees a live token with the wrong audience. That
    check is not redundant — it is what holds if the validator is ever swapped
    — but it is not what answers this request, and a test asserting otherwise
    would fail against a peer that is behaving perfectly.
    """
    import httpx

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{peer_url}/invoke",
            json={"action": "status", "params": {}},
            headers={"Authorization": f"Bearer {event_trigger_token}"},
            timeout=10.0,
        )

    assert not 200 <= resp.status_code < 300, "peer accepted a token minted for another agent"
    assert resp.status_code == 401
    assert resp.json()["denial_reason"] == "validation_failed"


async def test_peer_rejects_an_unauthenticated_call(
    agents_configured, require_agent_services, peer_url
):
    import httpx

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{peer_url}/invoke", json={"action": "status", "params": {}}, timeout=10.0
        )

    assert resp.status_code == 401
    assert resp.json()["denial_reason"] == "missing_token"
