"""Unit tests for the ServiceNow OBO token exchanger (servicenow_obo.py).

OBO can't be exercised against a live ServiceNow until the instance is
provisioned, so these mock OnBehalfOfCredential and verify the seam: the
configured scope is requested, exchange failures degrade to None, credentials
are cached per assertion, and the exchanger stays disabled when unconfigured.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mcp_server"))

import servicenow_obo  # noqa: E402 - after sys.path setup

SN_SCOPE = "api://servicenow-app-id/.default"


class _FakeToken:
    def __init__(self, token: str):
        self.token = token


class _FakeCredential:
    """Stand-in for azure.identity.aio.OnBehalfOfCredential."""

    last_scopes: tuple = ()

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def get_token(self, *scopes):
        _FakeCredential.last_scopes = scopes
        return _FakeToken("sn-access-token")

    async def close(self):
        pass


class _RaisingCredential:
    def __init__(self, **kwargs):
        pass

    async def get_token(self, *scopes):
        raise RuntimeError("AAD rejected the on-behalf-of exchange")

    async def close(self):
        pass


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Keep the module-level exchanger from leaking across tests/files."""
    servicenow_obo._exchanger = None
    yield
    servicenow_obo._exchanger = None


@pytest.mark.asyncio
async def test_get_sn_token_requests_configured_scope(monkeypatch):
    monkeypatch.setattr(servicenow_obo, "OnBehalfOfCredential", _FakeCredential)
    exchanger = servicenow_obo.ServiceNowOBOExchanger(
        "tenant", "client", "secret", SN_SCOPE,
    )
    token = await exchanger.get_sn_token("user-assertion-jwt")
    assert token == "sn-access-token"
    assert _FakeCredential.last_scopes == (SN_SCOPE,)


@pytest.mark.asyncio
async def test_get_sn_token_returns_none_on_exchange_failure(monkeypatch):
    monkeypatch.setattr(servicenow_obo, "OnBehalfOfCredential", _RaisingCredential)
    exchanger = servicenow_obo.ServiceNowOBOExchanger(
        "tenant", "client", "secret", SN_SCOPE,
    )
    assert await exchanger.get_sn_token("user-assertion-jwt") is None


@pytest.mark.asyncio
async def test_credentials_cached_per_assertion(monkeypatch):
    monkeypatch.setattr(servicenow_obo, "OnBehalfOfCredential", _FakeCredential)
    exchanger = servicenow_obo.ServiceNowOBOExchanger(
        "tenant", "client", "secret", SN_SCOPE,
    )
    await exchanger.get_sn_token("assertion-A")
    await exchanger.get_sn_token("assertion-A")  # cache hit
    await exchanger.get_sn_token("assertion-B")
    assert len(exchanger._credentials) == 2


def test_init_disabled_without_scope():
    servicenow_obo.init_sn_obo_exchanger("")  # empty scope → disabled
    assert servicenow_obo.get_sn_obo_exchanger() is None


def test_init_disabled_without_client_secret(monkeypatch):
    monkeypatch.delenv("ENTRA_CLIENT_SECRET", raising=False)
    servicenow_obo.init_sn_obo_exchanger(SN_SCOPE)
    assert servicenow_obo.get_sn_obo_exchanger() is None


def test_init_enabled_with_full_config(monkeypatch):
    monkeypatch.setenv("ENTRA_TENANT_ID", "tenant")
    monkeypatch.setenv("ENTRA_CLIENT_ID", "client")
    monkeypatch.setenv("ENTRA_CLIENT_SECRET", "secret")
    servicenow_obo.init_sn_obo_exchanger(SN_SCOPE)
    exchanger = servicenow_obo.get_sn_obo_exchanger()
    assert exchanger is not None
    assert exchanger._scope == SN_SCOPE
