"""Agent registry — identity lookup and call-graph authorization."""
import base64
import hmac
import json
import os
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
#
# Hermetic — no network access. A fake `_get_jwks` stands in for the real
# HTTPS call, backed by two REAL RSA-2048 keypairs generated in-process: a
# "real" tenant key (whose public half is what the fake JWKS serves) and an
# "attacker" key the forged-token tests sign with. This means the
# forged-token test can only pass because the signature check rejected it —
# not because a `kid` lookup or network call failed first.

TENANT_ID = "tid"
FIXED_KID = "test-signing-key-001"
AUDIENCE = "api://peer-id"
ISSUER = "https://login.microsoftonline.com/tid/v2.0"


def _b64url_uint(number: int) -> str:
    length = (number.bit_length() + 7) // 8 or 1
    return base64.urlsafe_b64encode(number.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def _jwk_for(public_key, kid: str) -> dict:
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def _private_pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _claims(**overrides) -> dict:
    now = int(time.time())
    base = {
        "aud": AUDIENCE,
        "azp": "orch-id",
        "roles": ["Agent.Invoke"],
        "idtyp": "app",
        "iss": ISSUER,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    base.update(overrides)
    return base


def _mint(private_key, kid: str, claims: dict, alg: str = "RS256", headers: dict | None = None) -> str:
    hdrs = {"kid": kid}
    if headers:
        hdrs.update(headers)
    return pyjwt.encode(claims, _private_pem(private_key), algorithm=alg, headers=hdrs)


def _b64url_segment(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode("ascii")


def _unsigned_none_token(claims: dict, kid: str) -> str:
    """Hand-build an `alg: none` token — PyJWT's encode() refuses to mint one."""
    header = {"alg": "none", "typ": "JWT", "kid": kid}
    return f"{_b64url_segment(header)}.{_b64url_segment(claims)}."


def _manual_hs256_token(claims: dict, kid: str, secret: bytes) -> str:
    """Hand-build an HS256 token signed with an arbitrary secret. PyJWT's
    encode() refuses to use PEM-shaped key material as an HMAC secret (a
    built-in guard against exactly this confusion attack), so a real
    attacker — who does not get that guard rail — is simulated by signing
    by hand instead."""
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    signing_input = f"{_b64url_segment(header)}.{_b64url_segment(claims)}".encode()
    signature = hmac.new(secret, signing_input, "sha256").digest()
    sig_segment = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{signing_input.decode()}.{sig_segment}"


@pytest.fixture(scope="module")
def rsa_keypairs():
    """One real (tenant-held) keypair, one attacker-held keypair."""
    real_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return real_key, attacker_key


@pytest.fixture
def jwks_validator(monkeypatch, rsa_keypairs):
    """An EntraJWTValidator whose `_get_jwks` is faked to serve the real key,
    without ever touching the network. `jwks_calls` records every lookup so
    tests can prove the JWKS path was actually reached."""
    from agent_common.jwt_validator import EntraJWTValidator

    real_key, _ = rsa_keypairs
    jwks_calls: list[str] = []

    async def fake_get_jwks(self, uri: str) -> dict:
        jwks_calls.append(uri)
        return {"keys": [_jwk_for(real_key.public_key(), FIXED_KID)]}

    monkeypatch.setattr(EntraJWTValidator, "_get_jwks", fake_get_jwks)
    validator = EntraJWTValidator(tenant_id=TENANT_ID)
    return validator, jwks_calls


@pytest.mark.asyncio
async def test_genuine_token_is_accepted(jwks_validator, rsa_keypairs):
    """Positive control: a properly signed, properly claimed token must pass."""
    validator, jwks_calls = jwks_validator
    real_key, _ = rsa_keypairs
    token = _mint(real_key, FIXED_KID, _claims())

    claims = await validator.validate(token, AUDIENCE)

    assert claims["azp"] == "orch-id"
    assert claims["aud"] == AUDIENCE
    assert jwks_calls, "JWKS lookup must have been reached"


@pytest.mark.asyncio
async def test_forged_token_is_rejected_before_any_claim_is_read(jwks_validator, rsa_keypairs):
    """The attack this defends against: a hand-crafted token with perfect claims.

    Every azp/roles/audience check passes on this token's CLAIMS — it is
    signed with the attacker's own key, but carries the SAME `kid` as the
    real tenant key, so the real key is exactly what gets tried against it.
    Only the signature betrays it — which is why the signature must be
    checked, and checked against the REAL key material, before any claim is
    trusted. Asserting `jwks_calls` proves the denial came from the
    signature check, not from a missing key or a failed fetch.
    """
    validator, jwks_calls = jwks_validator
    _, attacker_key = rsa_keypairs

    from agent_common.jwt_validator import TokenVerificationError

    forged = _mint(attacker_key, FIXED_KID, _claims(azp="orch-id"))

    with pytest.raises(TokenVerificationError):
        await validator.validate(forged, AUDIENCE)

    assert jwks_calls, "JWKS lookup must have been reached (real key was actually tried)"


@pytest.mark.asyncio
async def test_expired_token_is_rejected(jwks_validator, rsa_keypairs):
    from agent_common.jwt_validator import TokenVerificationError

    validator, _ = jwks_validator
    real_key, _ = rsa_keypairs
    now = int(time.time())
    token = _mint(real_key, FIXED_KID, _claims(iat=now - 1000, nbf=now - 1000, exp=now - 100))

    with pytest.raises(TokenVerificationError):
        await validator.validate(token, AUDIENCE)


@pytest.mark.asyncio
async def test_wrong_audience_is_rejected(jwks_validator, rsa_keypairs):
    from agent_common.jwt_validator import TokenVerificationError

    validator, _ = jwks_validator
    real_key, _ = rsa_keypairs
    token = _mint(real_key, FIXED_KID, _claims(aud="api://someone-else"))

    with pytest.raises(TokenVerificationError):
        await validator.validate(token, AUDIENCE)


@pytest.mark.asyncio
async def test_wrong_issuer_is_rejected(jwks_validator, rsa_keypairs):
    from agent_common.jwt_validator import TokenVerificationError

    validator, _ = jwks_validator
    real_key, _ = rsa_keypairs
    token = _mint(real_key, FIXED_KID, _claims(iss="https://evil.example.com/tid/v2.0"))

    with pytest.raises(TokenVerificationError):
        await validator.validate(token, AUDIENCE)


@pytest.mark.asyncio
async def test_bare_client_id_audience_is_still_accepted(jwks_validator, rsa_keypairs):
    """Entra mints aud as either the App ID URI or the bare client id — both
    must be accepted for the same expected_audience."""
    validator, _ = jwks_validator
    real_key, _ = rsa_keypairs
    token = _mint(real_key, FIXED_KID, _claims(aud="peer-id"))

    claims = await validator.validate(token, AUDIENCE)
    assert claims["aud"] == "peer-id"


@pytest.mark.asyncio
async def test_alg_none_token_is_rejected(jwks_validator):
    """Algorithm confusion: an unsigned `alg: none` token must never pass —
    proves the RS256 pin is load-bearing, not decoration."""
    from agent_common.jwt_validator import TokenVerificationError

    validator, _ = jwks_validator
    token = _unsigned_none_token(_claims(), FIXED_KID)

    with pytest.raises(TokenVerificationError):
        await validator.validate(token, AUDIENCE)


@pytest.mark.asyncio
async def test_hs256_confusion_with_public_key_as_secret_is_rejected(jwks_validator, rsa_keypairs):
    """Classic RS256->HS256 downgrade attack: sign with HS256 using the
    REAL public key's PEM bytes as the HMAC secret (attacker knows the
    public key — it's public). Must be rejected because algorithms=["RS256"]
    is pinned in jwt.decode."""
    from agent_common.jwt_validator import TokenVerificationError

    validator, _ = jwks_validator
    real_key, _ = rsa_keypairs
    public_pem = real_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    confused = _manual_hs256_token(_claims(), FIXED_KID, public_pem)

    with pytest.raises(TokenVerificationError):
        await validator.validate(confused, AUDIENCE)


@pytest.mark.asyncio
async def test_malformed_token_is_rejected():
    from agent_common.jwt_validator import EntraJWTValidator, TokenVerificationError

    validator = EntraJWTValidator(tenant_id="tid")
    with pytest.raises(TokenVerificationError):
        await validator.validate("not-a-jwt", "api://peer-id")


# --- JWKS cache TTL -----------------------------------------------------------

@pytest.mark.asyncio
async def test_jwks_entry_is_cached_until_ttl_then_refetched(monkeypatch, rsa_keypairs):
    """Exercises the real `_get_jwks` code path (httpx is faked at the
    transport level, not by replacing `_get_jwks` itself) to prove: an entry
    is served from cache before its TTL elapses, and refetched once the TTL
    has elapsed."""
    from agent_common.jwt_validator import EntraJWTValidator

    real_key, _ = rsa_keypairs
    calls: list[str] = []

    class FakeResponse:
        def __init__(self, body):
            self._body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self._body

    class FakeAsyncClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, uri, timeout=None):
            calls.append(uri)
            return FakeResponse({"keys": [_jwk_for(real_key.public_key(), FIXED_KID)]})

    import agent_common.jwt_validator as jv

    monkeypatch.setattr(jv.httpx, "AsyncClient", FakeAsyncClient)

    fake_time = {"now": 0.0}
    validator = EntraJWTValidator(
        tenant_id=TENANT_ID, jwks_ttl_seconds=10, clock=lambda: fake_time["now"]
    )
    uri = validator._jwks_uris[0]

    await validator._get_jwks(uri)
    assert len(calls) == 1

    fake_time["now"] += 5  # before TTL
    await validator._get_jwks(uri)
    assert len(calls) == 1, "must not refetch before TTL expires"

    fake_time["now"] += 10  # now past TTL (15s since first fetch)
    await validator._get_jwks(uri)
    assert len(calls) == 2, "must refetch after TTL expires"


# --- OBO credential cache: true LRU, not FIFO --------------------------------

def test_obo_credential_cache_evicts_least_recently_used(monkeypatch, tmp_path):
    """`_credentials` must evict the LEAST-recently-USED entry, not the
    oldest-inserted one. Uses a dummy stand-in for OnBehalfOfCredential so no
    real credential object or network call is ever involved — this is purely
    about the OrderedDict eviction bookkeeping in `_get_credential`."""
    import agent_common.tokens as tokens_mod

    class DummyCredential:
        def __init__(self, **kwargs):
            pass

    monkeypatch.setattr(tokens_mod, "OnBehalfOfCredential", DummyCredential)

    (tmp_path / "peer.crt").write_text("cert")
    (tmp_path / "peer.key").write_text("key")
    identity = registry.AgentIdentity(
        name="peer",
        client_id="peer-id",
        cert_path=tmp_path / "peer.crt",
        key_path=tmp_path / "peer.key",
    )

    exchanger = tokens_mod.DelegatedTokenExchanger(identity, tenant_id="tid")
    exchanger._max_cache = 3

    import hashlib

    def digest(token: str) -> str:
        return hashlib.sha256(f"{token}|callee".encode()).hexdigest()

    exchanger._get_credential("token-a", "callee")
    exchanger._get_credential("token-b", "callee")
    exchanger._get_credential("token-c", "callee")
    assert list(exchanger._credentials.keys()) == [digest(t) for t in ("token-a", "token-b", "token-c")]

    # Re-request "a" — a cache HIT — must mark it most-recently-used.
    exchanger._get_credential("token-a", "callee")
    assert list(exchanger._credentials.keys()) == [digest(t) for t in ("token-b", "token-c", "token-a")]

    # Cache is now full at 3. Inserting a 4th must evict "b" — the true LRU —
    # not "a", even though "a" was inserted first.
    exchanger._get_credential("token-d", "callee")

    assert digest("token-b") not in exchanger._credentials
    assert list(exchanger._credentials.keys()) == [digest(t) for t in ("token-c", "token-a", "token-d")]


async def test_evicted_obo_credential_is_closed(monkeypatch, tmp_path):
    """Eviction must CLOSE the credential, not just drop it — each one holds a
    live HTTP transport, so a dropped credential is a leaked connection every
    time the cache turns over. Driven from an async context because the close
    is scheduled on the running loop; the LRU test above covers the no-loop
    path, where there is no transport to leak either."""
    import asyncio

    import agent_common.tokens as tokens_mod

    closed = []

    class DummyCredential:
        def __init__(self, **kwargs):
            self.assertion = kwargs.get("user_assertion")

        async def close(self):
            closed.append(self.assertion)

    monkeypatch.setattr(tokens_mod, "OnBehalfOfCredential", DummyCredential)

    (tmp_path / "peer.crt").write_text("cert")
    (tmp_path / "peer.key").write_text("key")
    identity = registry.AgentIdentity(
        name="peer",
        client_id="peer-id",
        cert_path=tmp_path / "peer.crt",
        key_path=tmp_path / "peer.key",
    )

    exchanger = tokens_mod.DelegatedTokenExchanger(identity, tenant_id="tid")
    exchanger._max_cache = 2

    exchanger._get_credential("token-a", "callee")
    exchanger._get_credential("token-b", "callee")
    exchanger._get_credential("token-c", "callee")  # evicts "a"

    # The close is a scheduled task, not awaited inline — one yield lets the
    # task run, a second lets its done-callback (which drops the reference)
    # fire, since callbacks are queued for the next loop iteration.
    await asyncio.sleep(0)
    assert closed == ["token-a"]

    await asyncio.sleep(0)
    assert not exchanger._closing, "finished close task must not be retained"
