"""Agent registry — identity lookup and call-graph authorization."""
import os

import pytest

from agent_common import registry


@pytest.fixture(autouse=True)
def agent_env(monkeypatch, tmp_path):
    """Configure a full agent registry against throwaway cert paths."""
    certs = tmp_path / "certs"
    certs.mkdir()
    for name in ["gateway", "orchestrator", "peer", "event-trigger"]:
        (certs / f"{name}.crt").write_text("cert")
        (certs / f"{name}.key").write_text("key")

    monkeypatch.setenv("ENTRA_CLIENT_ID", "gw-id")
    monkeypatch.setenv("AGENT_ORCHESTRATOR_CLIENT_ID", "orch-id")
    monkeypatch.setenv("AGENT_PEER_CLIENT_ID", "peer-id")
    monkeypatch.setenv("AGENT_EVENT_TRIGGER_CLIENT_ID", "evt-id")
    monkeypatch.setenv("AGENT_CERT_DIR", str(certs))
    monkeypatch.setenv("ENTRA_TENANT_ID", "tid")
    registry.reload()
    yield
    registry.reload()


def test_agent_identity_resolves_client_id_and_paths():
    peer = registry.get_agent("peer")
    assert peer.client_id == "peer-id"
    assert peer.cert_path.name == "peer.crt"
    assert peer.key_path.name == "peer.key"


def test_audience_is_the_app_id_uri():
    """Tokens are narrowed to api://<callee-app-id>."""
    assert registry.get_agent("peer").audience == "api://peer-id"


def test_gateway_reuses_the_existing_entra_app():
    assert registry.get_agent("gateway").client_id == "gw-id"


def test_unconfigured_agent_raises():
    with pytest.raises(KeyError):
        registry.get_agent("nonexistent")


def test_call_graph_authorizes_orchestrator_to_call_peer():
    """The peer accepts calls from the orchestrator and the gateway only."""
    callers = registry.allowed_callers_for("peer")
    assert "orch-id" in callers
    assert "gw-id" in callers
    assert "evt-id" not in callers


def test_call_graph_authorizes_event_trigger_to_call_orchestrator():
    callers = registry.allowed_callers_for("orchestrator")
    assert callers == ["evt-id"]


def test_missing_env_var_means_agent_is_not_registered(monkeypatch):
    monkeypatch.delenv("AGENT_PEER_CLIENT_ID")
    registry.reload()
    with pytest.raises(KeyError):
        registry.get_agent("peer")


# --- JWT verification -------------------------------------------------------

@pytest.mark.asyncio
async def test_forged_token_is_rejected_before_any_claim_is_read():
    """The attack this defends against: a hand-crafted token with perfect claims.

    Every azp/roles/audience check passes on this token's CLAIMS. Only the
    signature betrays it — which is why the signature must be checked first.
    """
    import jwt as pyjwt

    from agent_common.jwt_validator import EntraJWTValidator, TokenVerificationError

    forged = pyjwt.encode(
        {
            "aud": "api://peer-id",
            "azp": "orch-id",              # impersonating the orchestrator
            "roles": ["Agent.Invoke"],     # granting itself the role
            "idtyp": "app",
            "iss": "https://login.microsoftonline.com/tid/v2.0",
        },
        "attacker-key",
        algorithm="HS256",
    )

    validator = EntraJWTValidator(tenant_id="tid")
    with pytest.raises(TokenVerificationError):
        await validator.validate(forged, "api://peer-id")


@pytest.mark.asyncio
async def test_malformed_token_is_rejected():
    from agent_common.jwt_validator import EntraJWTValidator, TokenVerificationError

    validator = EntraJWTValidator(tenant_id="tid")
    with pytest.raises(TokenVerificationError):
        await validator.validate("not-a-jwt", "api://peer-id")
