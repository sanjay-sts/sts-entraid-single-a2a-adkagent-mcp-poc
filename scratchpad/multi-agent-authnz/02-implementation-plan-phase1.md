# Multi-Agent Authn/z — Phase 1 Implementation Plan (Identity & Token Layer)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an orchestrator + two subagents where every inter-agent call carries the calling agent's own certificate-backed Entra app token, and — when a human is upstream — a per-hop OBO-exchanged user token, with each callee cryptographically verifying who called it.

**Architecture:** Each agent is an Entra app registration whose credential is an x509 certificate; it authenticates by signing a short-lived client assertion (`azure-identity` `CertificateCredential`). Every request carries `Authorization: Bearer <agent app token>` (always) and `X-Delegated-User-Token` (only when a human is upstream). Principal type is *derived* from which tokens are present, never declared. Both tokens are audience-narrowed to the callee at every hop. A shared `agent_common/` library owns the contract so it cannot drift across services. mTLS is Phase 2; this phase runs over plain HTTP.

**Tech Stack:** Python 3.10+, FastAPI, `azure-identity` (`CertificateCredential`, `OnBehalfOfCredential`), `cryptography` (PKI generation), PyJWT, httpx, pytest. All already in `requirements.txt` — **no new dependencies**.

**Spec:** `docs/superpowers/specs/2026-07-13-multi-agent-authnz-design.md`
**Baseline:** `HANDOFF.md`

## Global Constraints

- **No new dependencies.** `azure-identity` provides cert-based client credentials and OBO; `cryptography` provides PKI generation. Do not add `msal`.
- **Ports:** orchestrator `10004`, peer agent `10005`. Existing services keep 10000–10003.
- **Principal type is derived, never declared.** A client must never be able to assert its own principal type via a header or body field.
- **Audience narrowing per hop.** Every token minted or exchanged targets the immediate callee. Never forward a token verbatim to a hop it was not issued for.
- **Pure auth logic must be unit-testable without a tenant.** Network-dependent code (token acquisition, OBO) lives behind an interface; claim validation is pure functions tested with HS256 mock tokens, following the existing `tests/conftest.py` pattern.
- **Secrets and keys never committed.** `pki/certs/` is gitignored. Real `.env`, `permissions.toml` stay gitignored as today.
- **Lazy logger formatting** (`logger.info("msg: %s", val)`), per repo convention #11.
- **Fail closed.** Any validation error denies the request. No "log and continue" paths.

---

### Task 1: PKI — mini-CA and per-agent key pairs

Generates a local root CA and one key pair per agent. Each agent's public certificate is uploaded to its Entra app registration (Task 2); the private key signs client assertions. In production an enterprise CA (AWS Private CA, DigiCert) fills this seam unchanged — see spec §6.

**Files:**
- Create: `pki/generate_certs.py`
- Create: `pki/README.md`
- Modify: `.gitignore`
- Test: `tests/test_pki.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `pki/certs/<agent>.key` (PEM private key), `pki/certs/<agent>.crt` (PEM cert), `pki/certs/ca.crt` (root CA). Agent names: `gateway`, `orchestrator`, `peer`, `event-trigger`. Task 4's `AgentTokenProvider` reads these paths.

- [ ] **Step 1: Write the failing test**

Create `tests/test_pki.py`:

```python
"""PKI generation tests — mini-CA and per-agent key pairs."""
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

PKI_DIR = Path(__file__).parent.parent / "pki"
CERT_DIR = PKI_DIR / "certs"

AGENT_NAMES = ["gateway", "orchestrator", "peer", "event-trigger"]


@pytest.fixture(scope="module")
def generated_certs(tmp_path_factory):
    """Run the generator into a temp dir and return that dir."""
    out = tmp_path_factory.mktemp("certs")
    result = subprocess.run(
        [sys.executable, str(PKI_DIR / "generate_certs.py"), "--out", str(out)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"generator failed: {result.stderr}"
    return out


def test_ca_cert_created(generated_certs):
    ca_path = generated_certs / "ca.crt"
    assert ca_path.exists()
    ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
    # A CA must be marked as one, or it cannot sign.
    basic = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is True


@pytest.mark.parametrize("agent", AGENT_NAMES)
def test_agent_keypair_created(generated_certs, agent):
    key_path = generated_certs / f"{agent}.key"
    crt_path = generated_certs / f"{agent}.crt"
    assert key_path.exists(), f"missing key for {agent}"
    assert crt_path.exists(), f"missing cert for {agent}"

    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == f"agent-{agent}"

    # Private key must load and must be the pair of the cert's public key.
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()


@pytest.mark.parametrize("agent", AGENT_NAMES)
def test_agent_cert_signed_by_ca(generated_certs, agent):
    ca = x509.load_pem_x509_certificate((generated_certs / "ca.crt").read_bytes())
    cert = x509.load_pem_x509_certificate((generated_certs / f"{agent}.crt").read_bytes())
    assert cert.issuer == ca.subject
    # Raises InvalidSignature if the CA did not sign this cert.
    ca.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        __import__("cryptography.hazmat.primitives.asymmetric.padding", fromlist=["padding"]).PKCS1v15(),
        cert.signature_hash_algorithm,
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_pki.py -v`
Expected: FAIL — the generator does not exist, so `subprocess` returns non-zero and the assert on `returncode` fires.

- [ ] **Step 3: Write the generator**

Create `pki/generate_certs.py`:

```python
"""Generate a local mini-CA and one key pair per agent.

The private key signs Entra client assertions; the public certificate is
uploaded to that agent's app registration. In Phase 2 the same certs serve
as mTLS identities.

Production note: an enterprise CA (AWS Private CA, DigiCert, Vault PKI)
replaces this script without any code change downstream — Entra verifies
the assertion against the uploaded public cert and does not walk a chain.
"""
import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

AGENT_NAMES = ["gateway", "orchestrator", "peer", "event-trigger"]
KEY_SIZE = 2048
CA_VALID_DAYS = 3650
AGENT_VALID_DAYS = 365


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    print(f"wrote {path}")


def _private_key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_ca(out: Path) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "identity-agent-poc-root-ca"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "identity-agent-poc"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write(out / "ca.key", _private_key_pem(key))
    _write(out / "ca.crt", cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def _make_agent_cert(
    out: Path, name: str, ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, f"agent-{name}"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "identity-agent-poc"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=AGENT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # localhost SAN so these same certs work for mTLS in Phase 2.
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write(out / f"{name}.key", _private_key_pem(key))
    _write(out / f"{name}.crt", cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate mini-CA and agent certs")
    parser.add_argument(
        "--out",
        default=str(Path(__file__).parent / "certs"),
        help="output directory (default: pki/certs)",
    )
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = _make_ca(out)
    for name in AGENT_NAMES:
        _make_agent_cert(out, name, ca_key, ca_cert)

    print(f"\nDone. Upload each <agent>.crt to its Entra app registration.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_pki.py -v`
Expected: PASS — 9 tests (1 CA + 4 keypair + 4 signature).

- [ ] **Step 5: Generate the real certs and gitignore them**

Run: `uv run python pki/generate_certs.py`
Expected: writes `pki/certs/ca.key`, `ca.crt`, and 4 agent key/cert pairs.

Append to `.gitignore`:

```
# Agent PKI — private keys and generated certs, never commit
pki/certs/
```

- [ ] **Step 6: Write `pki/README.md`**

```markdown
# Agent PKI

Local mini-CA issuing one key pair per agent. Each agent's **private key**
signs its Entra client assertion; the **public certificate** is uploaded to
that agent's app registration.

## Generate

    uv run python pki/generate_certs.py

Produces `pki/certs/`: `ca.key`, `ca.crt`, and `<agent>.key` / `<agent>.crt`
for `gateway`, `orchestrator`, `peer`, `event-trigger`.

`pki/certs/` is gitignored. Regenerating invalidates every uploaded cert —
you must re-upload to Entra (see `docs/ENTRA_AGENT_SETUP.md`).

## Production

An enterprise CA (AWS Private CA, DigiCert, Venafi, Vault PKI) replaces this
script with **no code change**:

- For **Entra client assertions**, the CA is irrelevant — Entra matches the
  assertion signature against the exact uploaded public cert; it does not
  walk a chain. Self-signed and CA-issued are equivalent here.
- For **mTLS** (Phase 2), the CA chain *is* the trust root, replacing `ca.crt`.

What the CA buys: policy-controlled issuance, central inventory, automated
rotation, revocation (CRL/OCSP), audit trail.
```

- [ ] **Step 7: Commit**

```bash
git add pki/generate_certs.py pki/README.md tests/test_pki.py .gitignore
git commit -m "feat(pki): mini-CA and per-agent key pair generation"
```

---

### Task 2: Entra app registrations (HUMAN STEP — requires tenant admin)

**This task is executed by a human, not an agent.** It provisions the four app registrations the rest of the phase depends on. Unit tests (Tasks 3–5) do **not** depend on it; integration tests (Task 11) do and will skip cleanly until it is done.

**Files:**
- Create: `docs/ENTRA_AGENT_SETUP.md`
- Modify: `.env.example`

**Interfaces:**
- Consumes: `pki/certs/*.crt` from Task 1.
- Produces: env vars `AGENT_ORCHESTRATOR_CLIENT_ID`, `AGENT_PEER_CLIENT_ID`, `AGENT_EVENT_TRIGGER_CLIENT_ID` (gateway reuses `ENTRA_CLIENT_ID`), consumed by Task 4's config.

- [ ] **Step 1: Write `docs/ENTRA_AGENT_SETUP.md`**

````markdown
# Entra Setup — Agent Identities

Provisions one app registration per agent, each authenticating with an x509
certificate (no client secrets). **Requires tenant admin.**

Prerequisite: `uv run python pki/generate_certs.py` (Task 1).

Login: `az login --tenant <ENTRA_TENANT_ID>`

## 1. Create the app registrations

```bash
for AGENT in orchestrator peer event-trigger; do
  az ad app create --display-name "agent-$AGENT" --sign-in-audience AzureADMyOrg
done
```

Record each `appId`. Set them in `.env` as `AGENT_ORCHESTRATOR_CLIENT_ID`,
`AGENT_PEER_CLIENT_ID`, `AGENT_EVENT_TRIGGER_CLIENT_ID`. The **gateway**
reuses the existing app (`ENTRA_CLIENT_ID`).

Create a service principal for each (required for app-role assignment):

```bash
az ad sp create --id <appId>
```

## 2. Upload the certificate to each app

The private key stays local; only the public cert is uploaded. Entra
verifies client assertions against this exact cert.

```bash
az ad app credential reset --id <orchestrator-appId>   --cert "@pki/certs/orchestrator.crt"   --append
az ad app credential reset --id <peer-appId>           --cert "@pki/certs/peer.crt"           --append
az ad app credential reset --id <event-trigger-appId>  --cert "@pki/certs/event-trigger.crt"  --append
az ad app credential reset --id <ENTRA_CLIENT_ID>      --cert "@pki/certs/gateway.crt"        --append
```

`--append` preserves the gateway's existing client secret (still used for
user-token OBO to Graph).

## 3. Expose each callee as an API, with an app role

Callees are: **peer**, **gateway** (as a subagent), and **orchestrator**.
Each must expose an API (so callers can request a token for it) and define
the `Agent.Invoke` app role (so callers can be authorized).

Set the App ID URI (`api://<appId>` — no domain verification needed):

```bash
az ad app update --id <appId> --identifier-uris "api://<appId>"
```

Define the app role. Save as `approles.json` (generate a fresh GUID per app
with `uuidgen` / `[guid]::NewGuid()`):

```json
[
  {
    "allowedMemberTypes": ["Application"],
    "description": "Permits a registered agent to invoke this agent",
    "displayName": "Agent Invoke",
    "id": "<FRESH-GUID>",
    "isEnabled": true,
    "value": "Agent.Invoke"
  }
]
```

```bash
az ad app update --id <callee-appId> --app-roles @approles.json
```

## 4. Emit the `idtyp` claim

`idtyp: "app"` is the canonical marker distinguishing a machine token from a
user token. It is an **optional claim** and must be requested explicitly.
Save as `optionalclaims.json`:

```json
{
  "optionalClaims": {
    "accessToken": [{ "name": "idtyp", "essential": false }]
  }
}
```

Apply to **every** app (callers and callees):

```bash
az rest --method PATCH \
  --url "https://graph.microsoft.com/v1.0/applications/<objectId>" \
  --body @optionalclaims.json
```

(`<objectId>` is the app's `id`, not `appId`: `az ad app show --id <appId> --query id -o tsv`)

> The code falls back to a heuristic (`roles` present, `scp`/`preferred_username`
> absent) if `idtyp` is missing, but configure it — the heuristic is a safety
> net, not the contract.

## 5. Assign `Agent.Invoke` to the callers

Who may call whom:

| Caller | Callee |
|---|---|
| orchestrator | peer, gateway |
| gateway | peer |
| peer | gateway |
| event-trigger | orchestrator |

For each pair, assign the callee's `Agent.Invoke` role to the caller's SP:

```bash
CALLER_SP=$(az ad sp show --id <caller-appId> --query id -o tsv)
CALLEE_SP=$(az ad sp show --id <callee-appId> --query id -o tsv)
ROLE_ID=$(az ad app show --id <callee-appId> --query "appRoles[?value=='Agent.Invoke'].id | [0]" -o tsv)

az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$CALLEE_SP/appRoleAssignedTo" \
  --body "{\"principalId\":\"$CALLER_SP\",\"resourceId\":\"$CALLEE_SP\",\"appRoleId\":\"$ROLE_ID\"}"
```

## 6. Enable per-hop user-token OBO (delegated path)

For the orchestrator to exchange a user's token for one scoped to a subagent,
each callee must expose a delegated scope and pre-authorize the orchestrator.

Expose `access_as_user` on each callee (Portal: *Expose an API → Add a scope*,
value `access_as_user`, admins+users), then pre-authorize the orchestrator's
appId on that scope (*Expose an API → Add a client application*).

Grant the orchestrator delegated permission to each callee and consent:

```bash
az ad app permission add --id <orchestrator-appId> \
  --api <callee-appId> --api-permissions <scope-guid>=Scope
az ad app permission admin-consent --id <orchestrator-appId>
```

## 7. Verify

```bash
uv run pytest tests/test_agent_identity.py -v -m integration
```

Integration tests skip cleanly if any `AGENT_*_CLIENT_ID` is unset.
````

- [ ] **Step 2: Add the new env vars to `.env.example`**

Append:

```bash
# =============================================================================
# Agent Identities (multi-agent authn/z — see docs/ENTRA_AGENT_SETUP.md)
# =============================================================================
# One Entra app registration per agent, each authenticating with an x509
# certificate from pki/certs/. The gateway reuses ENTRA_CLIENT_ID above.
AGENT_ORCHESTRATOR_CLIENT_ID=
AGENT_PEER_CLIENT_ID=
AGENT_EVENT_TRIGGER_CLIENT_ID=

# Directory holding the generated key pairs (pki/generate_certs.py)
AGENT_CERT_DIR=pki/certs

# App role a caller must hold to invoke an agent
AGENT_REQUIRED_ROLE=Agent.Invoke

# Ports for the new agents
ORCHESTRATOR_PORT=10004
PEER_AGENT_PORT=10005
```

- [ ] **Step 3: Commit**

```bash
git add docs/ENTRA_AGENT_SETUP.md .env.example
git commit -m "docs: Entra app registration setup for agent identities"
```

- [ ] **Step 4: HUMAN — execute the guide**

Follow `docs/ENTRA_AGENT_SETUP.md` and populate `.env`. Until this is done,
Tasks 3–10 still proceed (their unit tests use mock tokens); only Task 11's
integration tests skip.

---

### Task 3: `agent_common` — pure claim validation and principal derivation

The heart of the contract. Pure functions, no network, fully unit-testable without a tenant.

**Files:**
- Create: `agent_common/__init__.py`
- Create: `agent_common/principal.py`
- Test: `tests/test_agent_identity.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `class AgentAuthError(Exception)` with attribute `denial_reason: str`
  - `is_app_token(claims: dict) -> bool`
  - `@dataclass(frozen=True) Principal` with fields `principal_type: str` (`"delegated"`|`"machine"`), `agent_id: str`, `agent_roles: list[str]`, `user_claims: dict | None`, `user_token: str | None`
  - `verify_agent_claims(claims: dict, expected_audience: str, allowed_callers: list[str], required_role: str) -> None` — raises `AgentAuthError`
  - `derive_principal(agent_claims: dict, user_claims: dict | None, user_token: str | None) -> Principal`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_agent_identity.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_agent_identity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent_common'`.

- [ ] **Step 3: Write the implementation**

Create `agent_common/__init__.py`:

```python
"""Shared agent-to-agent identity contract.

Every agent imports this so the request contract cannot drift across services.
"""
```

Create `agent_common/principal.py`:

```python
"""Pure claim validation and principal derivation for agent-to-agent calls.

No network, no I/O — every function here is a pure function of its claims,
so the security contract is unit-testable without a tenant.

The contract (spec §4):
  Authorization: Bearer <agent app token>    always — "who is calling"
  X-Delegated-User-Token: <user token>       only when a human is upstream

Principal type is DERIVED from which tokens are present. A caller can never
declare it.
"""
from dataclasses import dataclass

# Principal types
DELEGATED = "delegated"
MACHINE = "machine"


class AgentAuthError(Exception):
    """Agent-identity verification failed. Carries a stable denial reason."""

    def __init__(self, denial_reason: str, message: str):
        super().__init__(message)
        self.denial_reason = denial_reason
        self.message = message


def is_app_token(claims: dict) -> bool:
    """True if these claims came from a client-credentials (app-only) token.

    Primary signal: the `idtyp` optional claim, which Entra sets to "app" for
    app-only tokens. It must be configured on the app registration
    (docs/ENTRA_AGENT_SETUP.md §4).

    Fallback for when `idtyp` was not configured: an app-only token has no
    delegated-user markers. Note a *user* token can legitimately carry `roles`,
    so roles alone prove nothing — the absence of `scp` and of a user-name
    claim is what distinguishes them.
    """
    idtyp = claims.get("idtyp")
    if idtyp:
        return idtyp == "app"

    has_user_markers = bool(
        claims.get("scp")
        or claims.get("preferred_username")
        or claims.get("upn")
        or claims.get("unique_name")
    )
    return not has_user_markers and bool(claims.get("roles"))


def verify_agent_claims(
    claims: dict,
    expected_audience: str,
    allowed_callers: list[str],
    required_role: str,
) -> None:
    """Verify an agent token's claims. Raises AgentAuthError on any failure.

    Signature/issuer/expiry are verified separately (by the caller's JWT
    validator) before this runs. This function enforces the agent-identity
    layer on top of an already-authentic token:

      1. It really is a machine token, not a user token wearing a hat.
      2. It was minted for US — audience narrowing, so a token captured at
         another hop cannot be replayed here.
      3. The caller is a known agent.
      4. The caller holds the app role required to invoke us.

    Fails closed: any failure raises.
    """
    if not is_app_token(claims):
        raise AgentAuthError(
            "not_an_agent_token",
            "Authorization token is not a machine (app-only) token",
        )

    audience = claims.get("aud", "")
    if audience != expected_audience:
        raise AgentAuthError(
            "wrong_audience",
            f"Token audience '{audience}' was not minted for '{expected_audience}'",
        )

    caller = claims.get("azp") or claims.get("appid", "")
    if caller not in allowed_callers:
        raise AgentAuthError(
            "unknown_agent",
            f"Calling agent '{caller}' is not an authorized caller",
        )

    roles = claims.get("roles", [])
    if required_role not in roles:
        raise AgentAuthError(
            "agent_not_authorized",
            f"Calling agent '{caller}' lacks the '{required_role}' app role",
        )


@dataclass(frozen=True)
class Principal:
    """Who is making this request, and on whose behalf.

    Frozen: a downstream tier must not be able to escalate by mutating it.
    """

    principal_type: str        # DELEGATED | MACHINE
    agent_id: str              # calling agent's app id (azp) — always present
    agent_roles: list[str]     # calling agent's app roles
    user_claims: dict | None   # None when MACHINE
    user_token: str | None     # None when MACHINE

    @property
    def is_machine(self) -> bool:
        return self.principal_type == MACHINE

    @property
    def user_email(self) -> str:
        if not self.user_claims:
            return ""
        return (
            self.user_claims.get("preferred_username")
            or self.user_claims.get("upn")
            or self.user_claims.get("email", "")
        )


def derive_principal(
    agent_claims: dict,
    user_claims: dict | None,
    user_token: str | None,
) -> Principal:
    """Derive the principal from the tokens actually presented.

    Delegated when a validated user token rode along; machine otherwise. The
    acting agent is preserved in both cases so delegation is auditable.
    """
    caller = agent_claims.get("azp") or agent_claims.get("appid", "")
    roles = list(agent_claims.get("roles", []))

    if user_claims:
        return Principal(
            principal_type=DELEGATED,
            agent_id=caller,
            agent_roles=roles,
            user_claims=user_claims,
            user_token=user_token,
        )

    return Principal(
        principal_type=MACHINE,
        agent_id=caller,
        agent_roles=roles,
        user_claims=None,
        user_token=None,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_agent_identity.py -v`
Expected: PASS — 12 tests.

- [ ] **Step 5: Commit**

```bash
git add agent_common/ tests/test_agent_identity.py
git commit -m "feat(agent-common): agent claim validation and principal derivation"
```

---

### Task 4: `agent_common` — agent registry and cert-backed token acquisition

The network half: which agents exist, and how one gets a token for another.

**Files:**
- Create: `agent_common/registry.py`
- Create: `agent_common/tokens.py`
- Test: `tests/test_agent_registry.py`

**Interfaces:**
- Consumes: `Principal` / `AgentAuthError` from Task 3; `pki/certs/` from Task 1; env vars from Task 2.
- Produces:
  - `@dataclass(frozen=True) AgentIdentity` with fields `name: str`, `client_id: str`, `cert_path: Path`, `key_path: Path`, `audience: str`
  - `get_agent(name: str) -> AgentIdentity` — raises `KeyError` if unconfigured
  - `allowed_callers_for(name: str) -> list[str]`
  - `REQUIRED_ROLE: str`
  - `class AgentTokenProvider` with `async def get_agent_token(self, callee: str) -> str`
  - `class DelegatedTokenExchanger` with `async def exchange_for(self, user_token: str, callee: str) -> str`
  - `class EntraJWTValidator` with `async def validate(self, token: str, expected_audience: str) -> dict`
  - `class TokenVerificationError(Exception)`

- [ ] **Step 1: Write the failing test**

Create `tests/test_agent_registry.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_agent_registry.py -v`
Expected: FAIL — `ImportError: cannot import name 'registry' from 'agent_common'`.

- [ ] **Step 3: Write the registry**

Create `agent_common/registry.py`:

```python
"""Who the agents are, and who may call whom.

The call graph is declared here rather than scattered across services, so the
authorization topology is reviewable in one place. It must mirror the app-role
assignments made in Entra (docs/ENTRA_AGENT_SETUP.md §5) — Entra is the
enforcement point; this is the local allow-list that backs it up.
"""
import os
from dataclasses import dataclass
from pathlib import Path

# App role a caller must hold to invoke an agent.
REQUIRED_ROLE = os.getenv("AGENT_REQUIRED_ROLE", "Agent.Invoke")

# Each agent's client id comes from its own env var. The gateway reuses the
# existing app registration.
_CLIENT_ID_ENV = {
    "gateway": "ENTRA_CLIENT_ID",
    "orchestrator": "AGENT_ORCHESTRATOR_CLIENT_ID",
    "peer": "AGENT_PEER_CLIENT_ID",
    "event-trigger": "AGENT_EVENT_TRIGGER_CLIENT_ID",
}

# Who may call whom. Keys are callees; values are the agents allowed to call them.
_CALL_GRAPH = {
    "orchestrator": ["event-trigger"],
    "peer": ["orchestrator", "gateway"],
    "gateway": ["orchestrator", "peer"],
}


@dataclass(frozen=True)
class AgentIdentity:
    """One agent's Entra identity and the key pair it authenticates with."""

    name: str
    client_id: str
    cert_path: Path
    key_path: Path

    @property
    def audience(self) -> str:
        """The App ID URI tokens for this agent are minted against."""
        return f"api://{self.client_id}"

    @property
    def scope(self) -> str:
        """The client-credentials scope a caller requests to reach this agent."""
        return f"{self.audience}/.default"


_agents: dict[str, AgentIdentity] = {}


def reload() -> None:
    """Rebuild the registry from the current environment.

    Agents whose client id is unset are simply not registered — the system
    runs with whatever subset is configured, and callers get a clean KeyError.
    """
    global _agents
    cert_dir = Path(os.getenv("AGENT_CERT_DIR", "pki/certs"))

    _agents = {}
    for name, env_var in _CLIENT_ID_ENV.items():
        client_id = os.getenv(env_var, "").strip()
        if not client_id:
            continue
        _agents[name] = AgentIdentity(
            name=name,
            client_id=client_id,
            cert_path=cert_dir / f"{name}.crt",
            key_path=cert_dir / f"{name}.key",
        )


def get_agent(name: str) -> AgentIdentity:
    """Look up an agent. Raises KeyError if it is not configured."""
    if not _agents:
        reload()
    if name not in _agents:
        raise KeyError(
            f"Agent '{name}' is not configured. "
            f"Set {_CLIENT_ID_ENV.get(name, 'its client id env var')} in .env."
        )
    return _agents[name]


def allowed_callers_for(name: str) -> list[str]:
    """Client ids of the agents permitted to call `name`.

    Unregistered callers are dropped, so a partially configured environment
    fails closed rather than authorizing an empty string.
    """
    if not _agents:
        reload()
    out = []
    for caller in _CALL_GRAPH.get(name, []):
        if caller in _agents:
            out.append(_agents[caller].client_id)
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_agent_registry.py -v`
Expected: PASS — 7 tests.

- [ ] **Step 5: Write the token providers**

Create `agent_common/tokens.py`:

```python
"""Acquiring tokens for agent-to-agent calls.

Two flows, both certificate-backed (no client secrets):

  AgentTokenProvider      client-credentials — "here is who I am"
                          Mints an app-only token for a specific callee.

  DelegatedTokenExchanger on-behalf-of — "here is who I act for"
                          Exchanges an inbound user token for one narrowed
                          to the next hop. This is what keeps a token captured
                          at hop N from being replayable at hop N+1.

Both cache credentials per (agent, callee); azure-identity caches the tokens
themselves and refreshes them before expiry.
"""
import hashlib
import logging
import os

from azure.identity.aio import CertificateCredential, OnBehalfOfCredential

from agent_common.registry import AgentIdentity, get_agent

logger = logging.getLogger("agent_common.tokens")


class AgentTokenProvider:
    """Mints this agent's own app-only tokens, audience-narrowed per callee."""

    def __init__(self, identity: AgentIdentity, tenant_id: str | None = None):
        self._identity = identity
        self._tenant_id = tenant_id or os.getenv("ENTRA_TENANT_ID", "")
        self._credential: CertificateCredential | None = None

    def _get_credential(self) -> CertificateCredential:
        """One credential per agent — it is not bound to a callee."""
        if self._credential is None:
            self._credential = CertificateCredential(
                tenant_id=self._tenant_id,
                client_id=self._identity.client_id,
                certificate_path=str(self._identity.cert_path),
                # The private key signs the client assertion. It never leaves
                # this process; only the public cert lives in Entra.
                password=None,
            )
        return self._credential

    async def get_agent_token(self, callee: str) -> str:
        """An app-only token for calling `callee`.

        The returned token carries aud=api://<callee>, azp=<this agent>,
        idtyp=app, and this agent's app roles on the callee.
        """
        target = get_agent(callee)
        credential = self._get_credential()
        token = await credential.get_token(target.scope)
        logger.debug("Minted agent token for callee %s", callee)
        return token.token

    async def close(self) -> None:
        if self._credential is not None:
            await self._credential.close()
            self._credential = None


class DelegatedTokenExchanger:
    """Exchanges an inbound user token for one scoped to the next hop (OBO)."""

    def __init__(self, identity: AgentIdentity, tenant_id: str | None = None):
        self._identity = identity
        self._tenant_id = tenant_id or os.getenv("ENTRA_TENANT_ID", "")
        self._cert_bytes: bytes | None = None
        # An OnBehalfOfCredential is bound to one user assertion, so it must be
        # cached per (assertion, callee), not globally.
        self._credentials: dict[str, OnBehalfOfCredential] = {}
        self._max_cache = 128

    def _certificate(self) -> bytes:
        """Cert + private key, PEM, as azure-identity expects for OBO."""
        if self._cert_bytes is None:
            self._cert_bytes = (
                self._identity.key_path.read_bytes()
                + b"\n"
                + self._identity.cert_path.read_bytes()
            )
        return self._cert_bytes

    def _get_credential(self, user_token: str, callee: str) -> OnBehalfOfCredential:
        digest = hashlib.sha256(f"{user_token}|{callee}".encode()).hexdigest()
        if digest not in self._credentials:
            if len(self._credentials) >= self._max_cache:
                del self._credentials[next(iter(self._credentials))]
            self._credentials[digest] = OnBehalfOfCredential(
                tenant_id=self._tenant_id,
                client_id=self._identity.client_id,
                client_certificate=self._certificate(),
                user_assertion=user_token,
            )
        return self._credentials[digest]

    async def exchange_for(self, user_token: str, callee: str) -> str:
        """Exchange `user_token` for one whose audience is `callee`.

        The exchanged token keeps the human in `sub` — this agent appears as
        the actor, not as the subject. Delegation, not impersonation.
        """
        target = get_agent(callee)
        credential = self._get_credential(user_token, callee)
        token = await credential.get_token(target.scope)
        logger.debug("Exchanged user token for callee %s", callee)
        return token.token

    async def close(self) -> None:
        for credential in self._credentials.values():
            try:
                await credential.close()
            except Exception:
                pass
        self._credentials.clear()
```

- [ ] **Step 6: Write the JWT signature validator**

**This is the load-bearing security step of the whole phase.** Every check in
`verify_agent_claims` — audience, `azp`, roles — reads claims out of a token.
Those claims are worth exactly nothing unless the signature is verified first:
a rogue could otherwise hand-craft a JWT with `azp` set to the orchestrator's
app id and `roles: ["Agent.Invoke"]` and satisfy every check. **Claims are only
trustworthy after the signature is verified against Entra's JWKS.**

Create `agent_common/jwt_validator.py`:

```python
"""JWT signature verification for agent-to-agent calls.

Verifies signature, issuer, audience and expiry against Entra's JWKS before any
claim is trusted. Without this, verify_agent_claims() is decoration: an attacker
can hand-craft a token with any azp and roles they like.

One implementation, shared by every agent, so no service can accidentally skip it.
"""
import logging
import os

import httpx
import jwt

logger = logging.getLogger("agent_common.jwt")


class TokenVerificationError(Exception):
    """Signature, issuer, audience or expiry check failed."""


class EntraJWTValidator:
    """Verifies Entra-issued JWTs against the tenant's JWKS."""

    def __init__(self, tenant_id: str | None = None):
        self._tenant_id = tenant_id or os.getenv("ENTRA_TENANT_ID", "")
        self._jwks_cache: dict[str, dict] = {}

    @property
    def _jwks_uris(self) -> list[str]:
        return [
            f"https://login.microsoftonline.com/{self._tenant_id}/discovery/v2.0/keys",
            f"https://login.microsoftonline.com/{self._tenant_id}/discovery/keys",
        ]

    @property
    def _issuers(self) -> list[str]:
        return [
            f"https://login.microsoftonline.com/{self._tenant_id}/v2.0",
            f"https://sts.windows.net/{self._tenant_id}/",
        ]

    async def _get_jwks(self, uri: str) -> dict:
        if uri not in self._jwks_cache:
            async with httpx.AsyncClient() as client:
                response = await client.get(uri, timeout=10.0)
                response.raise_for_status()
                self._jwks_cache[uri] = response.json()
        return self._jwks_cache[uri]

    def clear_cache(self) -> None:
        self._jwks_cache = {}

    async def _keys_for(self, kid: str) -> list:
        keys = []
        for uri in self._jwks_uris:
            try:
                jwks = await self._get_jwks(uri)
            except Exception as e:
                logger.debug("JWKS fetch failed for %s: %s", uri, e)
                continue
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    keys.append(jwt.algorithms.RSAAlgorithm.from_jwk(key))
        return keys

    async def validate(self, token: str, expected_audience: str) -> dict:
        """Verify the token and return its claims. Raises TokenVerificationError.

        `expected_audience` is checked here as well as in verify_agent_claims —
        belt and braces, because a token accepted for the wrong audience is the
        replay attack we are specifically defending against.
        """
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except Exception as e:
            raise TokenVerificationError(f"Malformed token: {e}") from e

        keys = await self._keys_for(kid)
        if not keys:
            # Key rotation: drop the cache and try once more before giving up.
            self.clear_cache()
            keys = await self._keys_for(kid)
        if not keys:
            raise TokenVerificationError(f"Signing key '{kid}' not found in JWKS")

        # Entra mints the audience as either the app id or the App ID URI.
        bare_client_id = expected_audience.removeprefix("api://")
        audiences = [expected_audience, bare_client_id]

        last_error: Exception | None = None
        for key in keys:
            try:
                return jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],
                    audience=audiences,
                    issuer=self._issuers,
                )
            except jwt.InvalidSignatureError as e:
                last_error = e  # wrong key of several — try the next
            except jwt.ExpiredSignatureError as e:
                raise TokenVerificationError("Token has expired") from e
            except jwt.InvalidAudienceError as e:
                raise TokenVerificationError(
                    f"Token audience is not '{expected_audience}'"
                ) from e
            except jwt.InvalidIssuerError as e:
                raise TokenVerificationError("Token issuer is not this tenant") from e
            except Exception as e:
                last_error = e

        raise TokenVerificationError(f"Signature verification failed: {last_error}")
```

- [ ] **Step 7: Test that unsigned tokens are rejected**

Append to `tests/test_agent_registry.py`:

```python
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
```

- [ ] **Step 8: Run the full unit suite**

Run: `uv run pytest tests/test_agent_identity.py tests/test_agent_registry.py tests/test_pki.py -v`
Expected: PASS — 30 tests. (`tokens.py` has no unit tests: it is pure network I/O, covered by Task 11's integration tests. Do not mock `azure-identity` here — a mocked token provider would prove nothing about whether Entra accepts our assertion, which is the entire question.)

- [ ] **Step 9: Commit**

```bash
git add agent_common/registry.py agent_common/tokens.py agent_common/jwt_validator.py tests/test_agent_registry.py
git commit -m "feat(agent-common): registry, cert-backed tokens, JWT signature verification"
```

---

### Task 5: Policy — agent principals and `principal_type`

Teaches the policy layer that a principal can be an agent, not just a human. This finally calls the dormant `check_access()` seam (`HANDOFF.md` §13 #15).

**Files:**
- Modify: `mcp_server/policy.py`
- Modify: `permissions.example.toml`
- Test: `tests/test_agent_policy.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (policy stays dependency-free).
- Produces:
  - `AccessRequest` gains fields `principal_type: str = "delegated"` and `agent_id: str = ""`
  - `PolicyEvaluator.get_agent_roles(agent_id: str, provider: str) -> list[str]` (abstract)
  - `TomlPolicyEvaluator.get_agent_roles` reads `[agent_rules.<provider>]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_agent_policy.py`:

```python
"""Policy — agent principals resolve roles from their app id, not group claims."""
import textwrap

import pytest

from mcp_server.policy import AccessRequest, TomlPolicyEvaluator

ORCH = "11111111-1111-1111-1111-111111111111"
PEER = "22222222-2222-2222-2222-222222222222"
UNKNOWN = "99999999-9999-9999-9999-999999999999"


@pytest.fixture
def evaluator(tmp_path):
    config = tmp_path / "permissions.toml"
    config.write_text(textwrap.dedent(f"""
        [group_rules.entra]
        "admin-group-guid" = "admin"

        [agent_rules.entra]
        "{ORCH}" = "developer"
        "{PEER}" = "viewer"

        [defaults]
        unknown_users = "none"
    """))
    return TomlPolicyEvaluator(config)


def test_agent_resolves_role_from_app_id(evaluator):
    assert evaluator.get_agent_roles(ORCH, "entra") == ["developer"]


def test_second_agent_resolves_its_own_role(evaluator):
    assert evaluator.get_agent_roles(PEER, "entra") == ["viewer"]


def test_unregistered_agent_gets_no_roles(evaluator):
    """An agent absent from agent_rules gets nothing — fail closed."""
    assert evaluator.get_agent_roles(UNKNOWN, "entra") == []


def test_agent_rules_do_not_leak_into_user_roles(evaluator):
    """An app id must not be usable as a group claim."""
    assert evaluator.get_available_roles("", "entra", [ORCH]) == []


def test_group_rules_do_not_leak_into_agent_roles(evaluator):
    """A group guid must not be usable as an app id."""
    assert evaluator.get_agent_roles("admin-group-guid", "entra") == []


def test_check_access_allows_machine_principal_with_permitted_role(evaluator):
    request = AccessRequest(
        email="",
        provider="entra",
        groups=[],
        tool_name="list_s3_buckets",
        claims={},
        assumed_role="developer",
        principal_type="machine",
        agent_id=ORCH,
    )
    decision = evaluator.check_access(request, ["admin", "developer"])
    assert decision.allowed is True
    assert decision.role == "developer"


def test_check_access_denies_machine_principal_lacking_role(evaluator):
    request = AccessRequest(
        email="",
        provider="entra",
        groups=[],
        tool_name="send_email",
        claims={},
        assumed_role="developer",
        principal_type="machine",
        agent_id=ORCH,
    )
    decision = evaluator.check_access(request, ["admin"])
    assert decision.allowed is False
    assert "developer" in decision.reason


def test_access_request_defaults_to_delegated():
    """Existing call sites keep working — delegated is the default."""
    request = AccessRequest(
        email="a@b.com", provider="entra", groups=[], tool_name="t", claims={}
    )
    assert request.principal_type == "delegated"
    assert request.agent_id == ""
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_agent_policy.py -v`
Expected: FAIL — `TypeError: AccessRequest.__init__() got an unexpected keyword argument 'principal_type'` and `AttributeError: 'TomlPolicyEvaluator' object has no attribute 'get_agent_roles'`.

- [ ] **Step 3: Extend `AccessRequest` and the evaluator interface**

In `mcp_server/policy.py`, replace the `AccessRequest` dataclass:

```python
@dataclass
class AccessRequest:
    """All attributes available for a policy decision."""

    email: str
    provider: str  # "entra", "cognito", "auth0"
    groups: list[str]  # IdP group IDs/names from token claims
    tool_name: str  # The MCP tool being called
    claims: dict  # Full JWT claims (for ABAC extensibility)
    assumed_role: str = ""  # Role explicitly selected by user
    # Multi-agent: a principal may be a machine (an agent acting on its own
    # behalf) rather than a human. Defaults preserve existing call sites.
    principal_type: str = "delegated"  # "delegated" | "machine"
    agent_id: str = ""  # calling agent's app id, when known
```

Add the abstract method to `PolicyEvaluator`, after `get_available_roles`:

```python
    @abstractmethod
    def get_agent_roles(self, agent_id: str, provider: str) -> list[str]:
        """Return the roles a machine principal (agent) qualifies for.

        Agents have no group claims and no email — their role comes from their
        app id alone.
        """
        ...
```

- [ ] **Step 4: Implement `get_agent_roles` on `TomlPolicyEvaluator`**

Add to `TomlPolicyEvaluator`, after `get_available_roles`:

```python
    def get_agent_roles(self, agent_id: str, provider: str = "entra") -> list[str]:
        """Resolve a machine principal's roles from [agent_rules.<provider>].

        Deliberately separate from get_available_roles: an app id must never be
        usable as a group claim, nor a group guid as an app id. Fails closed —
        an unregistered agent gets no roles, and `defaults.unknown_users` does
        NOT apply to agents.
        """
        self._load()
        if not agent_id:
            return []

        agent_rules = self._config.get("agent_rules", {}).get(provider, {})
        role = agent_rules.get(agent_id)
        if not role:
            return []
        return [role] if role in self.ROLE_PRIORITY else []
```

- [ ] **Step 5: Make `check_access` principal-aware**

Replace `TomlPolicyEvaluator.check_access`:

```python
    def check_access(
        self, request: AccessRequest, allowed_roles: list[str]
    ) -> AccessDecision:
        """RBAC check: verify the assumed role is allowed for this tool.

        Identical for both principal types — what differs is where the role
        came from (groups for a human, app id for an agent), which the caller
        has already resolved.
        """
        role = request.assumed_role or "none"
        allowed = role in allowed_roles
        if allowed:
            return AccessDecision(allowed=True, role=role, reason="")

        actor = (
            f"Agent '{request.agent_id}'"
            if request.principal_type == "machine"
            else f"Role '{role}'"
        )
        reason = (
            f"{actor} with role '{role}' cannot use '{request.tool_name}'. "
            f"Required: {allowed_roles}"
        )
        return AccessDecision(allowed=False, role=role, reason=reason)
```

- [ ] **Step 6: Add `[agent_rules]` to `permissions.example.toml`**

Insert after the `[group_rules.auth0]` block:

```toml
# MACHINE PRINCIPALS: map an agent's Entra app id to a role.
# Agents have no group claims and no email — their role comes from their app
# id alone. Used when an agent calls a tool on its OWN behalf (event-triggered,
# no human upstream). When a human IS upstream, the human's role applies and
# these rules are not consulted.
#
# Fails closed: an agent absent from this table gets no roles, and
# [defaults].unknown_users does NOT apply.
[agent_rules.entra]
# "<orchestrator-app-id>" = "developer"
# "<peer-agent-app-id>"   = "viewer"
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_agent_policy.py -v`
Expected: PASS — 8 tests.

- [ ] **Step 8: Verify no regression in the existing suite**

Run: `uv run pytest tests/test_access_control.py -v`
Expected: PASS — unchanged. The new `AccessRequest` fields are defaulted, so existing call sites are untouched.

- [ ] **Step 9: Commit**

```bash
git add mcp_server/policy.py permissions.example.toml tests/test_agent_policy.py
git commit -m "feat(policy): machine principals resolve roles from app id"
```

---

### Task 6: A2A gateway accepts agent tokens

The gateway currently rejects any token without a group claim (`HANDOFF.md` §12 #1). Teach it that an agent token is authorized by app role, not group membership.

**Files:**
- Modify: `a2a_server/server.py` (auth middleware, ~line 553–651)
- Test: `tests/test_gateway_agent_auth.py`

**Interfaces:**
- Consumes: `is_app_token`, `verify_agent_claims`, `AgentAuthError` (Task 3); `registry` (Task 4).
- Produces: `current_principal: ContextVar[Principal | None]` in `a2a_server/server.py`, read by the executor. New denial reasons: `not_an_agent_token`, `wrong_audience`, `unknown_agent`, `agent_not_authorized`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_gateway_agent_auth.py`:

```python
"""Gateway — agent tokens are authorized by app role, not group membership."""
import pytest

from agent_common.principal import AgentAuthError

# The gateway's middleware delegates to this helper; testing it directly keeps
# the test a unit test (no HTTP, no JWKS) while covering the real branch logic.
from a2a_server.server import authorize_agent_caller

ORCH = "11111111-1111-1111-1111-111111111111"
ROGUE = "99999999-9999-9999-9999-999999999999"
GATEWAY_AUD = "api://gw-id"


@pytest.fixture(autouse=True)
def gateway_env(monkeypatch):
    monkeypatch.setenv("ENTRA_CLIENT_ID", "gw-id")
    monkeypatch.setenv("AGENT_ORCHESTRATOR_CLIENT_ID", ORCH)
    monkeypatch.setenv("AGENT_PEER_CLIENT_ID", "peer-id")
    from agent_common import registry
    registry.reload()
    yield
    registry.reload()


def agent_claims(azp=ORCH, aud=GATEWAY_AUD, roles=("Agent.Invoke",)):
    return {
        "aud": aud,
        "azp": azp,
        "roles": list(roles),
        "idtyp": "app",
        "iss": "https://login.microsoftonline.com/tid/v2.0",
    }


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
        authorize_agent_caller(agent_claims(aud="api://peer-id"))
    assert exc.value.denial_reason == "wrong_audience"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_gateway_agent_auth.py -v`
Expected: FAIL — `ImportError: cannot import name 'authorize_agent_caller' from 'a2a_server.server'`.

- [ ] **Step 3: Add the helper and the ContextVar**

In `a2a_server/server.py`, add to the imports near the top (after the `dev_config` import):

```python
from agent_common.principal import (
    AgentAuthError,
    Principal,
    derive_principal,
    is_app_token,
    verify_agent_claims,
)
from agent_common import registry
```

Add alongside the existing ContextVars (after line 27):

```python
# Multi-agent: the resolved principal (human-delegated or machine) for this request.
current_principal: ContextVar[Principal | None] = ContextVar("current_principal", default=None)
```

Add this function next to the other module-level helpers (near `_detect_provider`, ~line 710):

```python
def authorize_agent_caller(claims: dict) -> None:
    """Authorize a machine caller. Raises AgentAuthError on any failure.

    Agent tokens carry no group claims — they are authorized by app role and
    audience instead. This is the branch that lets an agent through the
    gateway's group check.
    """
    gateway = registry.get_agent("gateway")
    verify_agent_claims(
        claims=claims,
        expected_audience=gateway.audience,
        allowed_callers=registry.allowed_callers_for("gateway"),
        required_role=registry.REQUIRED_ROLE,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_gateway_agent_auth.py -v`
Expected: PASS — 4 tests.

- [ ] **Step 5: Branch the auth middleware on principal type**

In `a2a_server/server.py`, inside `auth_middleware`, replace the block from `# Check group membership (provider-aware)` through the `current_assumed_role.set(...)` line (~lines 612–639) with:

```python
        provider = _detect_provider(claims)

        # Machine caller: an agent acting on its own or a user's behalf. It has
        # no group claims, so the group check below cannot apply — it is
        # authorized by app role and audience instead.
        if is_app_token(claims):
            try:
                authorize_agent_caller(claims)
            except AgentAuthError as e:
                logger.warning("Agent caller rejected (%s): %s", e.denial_reason, e.message)
                return _auth_error(request, 403, "access_denied", e.message, e.denial_reason)

            # A delegated user token may ride alongside. It is validated with the
            # same machinery as any user token — an agent cannot fabricate one.
            user_token = request.headers.get("X-Delegated-User-Token", "")
            user_claims = None
            if user_token:
                try:
                    user_claims = await token_validator.validate(user_token)
                except Exception as e:
                    logger.warning("Delegated user token invalid: %s", e)
                    return _auth_error(request, 401, "auth_failed",
                                       "Delegated user token is invalid", "validation_failed")

            principal = derive_principal(claims, user_claims, user_token or None)
            logger.info(
                "Agent %s authorized (principal=%s)",
                principal.agent_id, principal.principal_type,
            )

            current_principal.set(principal)
            current_user_claims.set(user_claims or claims)
            current_access_token.set(user_token or token)
            current_assumed_role.set(request.headers.get("X-Assume-Role", ""))
            request.state.user_claims = user_claims or claims
            request.state.access_token = user_token or token
            return await call_next(request)

        # Human caller: authorized by group membership, as before.
        if provider == "cognito":
            user_groups = claims.get("cognito:groups", [])
            allowed = COGNITO_ALLOWED_GROUPS
        else:
            user_groups = claims.get("groups", [])
            allowed = ALLOWED_GROUPS
        logger.debug("User groups (%s): %s", provider, user_groups)

        if not allowed:
            logger.warning("No allowed groups configured for provider %s — denying access", provider)
            return _auth_error(request, 403, "access_denied",
                               "Agent access control not configured", "no_group_configuration")
        if not any(g in allowed for g in user_groups):
            logger.warning("User %s not in allowed groups. Has: %s, Allowed: %s", user_id, user_groups, allowed)
            return _auth_error(request, 403, "access_denied",
                               "Not a member of any authorized group", "no_group_membership")

        logger.debug("Access control passed, storing claims in request state")
        request.state.user_claims = claims
        request.state.access_token = token

        current_principal.set(derive_principal({}, claims, token))
        current_user_claims.set(claims)
        current_access_token.set(token)
        current_assumed_role.set(request.headers.get("X-Assume-Role", ""))
```

- [ ] **Step 6: Verify no regression**

Run: `uv run pytest tests/test_access_control.py tests/test_gateway_agent_auth.py -v`
Expected: PASS — human callers unaffected, agent callers authorized.

- [ ] **Step 7: Commit**

```bash
git add a2a_server/server.py tests/test_gateway_agent_auth.py
git commit -m "feat(gateway): authorize agent callers by app role, not group membership"
```

---

### Task 7: MCP server resolves machine principals

The MCP tier currently resolves a role from group claims and an email. An agent has neither. Teach `UserContextMiddleware` to resolve a machine principal from its app id, and make the Graph tools refuse machine principals cleanly (there is no human to act "on behalf of").

**Files:**
- Modify: `mcp_server/server.py`
- Test: `tests/test_mcp_machine_principal.py`

**Interfaces:**
- Consumes: `is_app_token` (Task 3); `get_agent_roles` (Task 5).
- Produces: `current_principal_type: ContextVar[str]` and `current_agent_id: ContextVar[str]` in `mcp_server/server.py`; `_require_delegated_user() -> dict | None` helper.

- [ ] **Step 1: Write the failing test**

Create `tests/test_mcp_machine_principal.py`:

```python
"""MCP — machine principals resolve roles from app id and cannot use Graph tools."""
import pytest

from mcp_server import server as mcp_server


@pytest.fixture(autouse=True)
def reset_contextvars():
    mcp_server.current_principal_type.set("delegated")
    mcp_server.current_agent_id.set("")
    mcp_server.current_user_provider.set("entra")
    yield
    mcp_server.current_principal_type.set("delegated")
    mcp_server.current_agent_id.set("")


def test_graph_tool_refuses_machine_principal():
    """No human upstream means there is nobody to act on behalf of."""
    mcp_server.current_principal_type.set("machine")
    mcp_server.current_agent_id.set("orch-id")

    error = mcp_server._require_delegated_user()

    assert error is not None
    assert error["error"] == "no_delegated_user"
    assert "orch-id" in error["agent_id"]


def test_graph_tool_allows_delegated_principal():
    mcp_server.current_principal_type.set("delegated")
    assert mcp_server._require_delegated_user() is None


@pytest.mark.asyncio
async def test_get_user_profile_returns_no_delegated_user_for_machine():
    mcp_server.current_principal_type.set("machine")
    mcp_server.current_agent_id.set("orch-id")

    result = await mcp_server.get_user_profile.fn()

    assert result["error"] == "no_delegated_user"


@pytest.mark.asyncio
async def test_obo_is_never_attempted_for_a_machine_principal():
    """OBO requires a user assertion by definition — never call it without one."""
    mcp_server.current_principal_type.set("machine")
    mcp_server.current_user_token.set("some-agent-token")

    token = await mcp_server._get_graph_token(["https://graph.microsoft.com/User.Read"])

    assert token is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_mcp_machine_principal.py -v`
Expected: FAIL — `AttributeError: module 'mcp_server.server' has no attribute 'current_principal_type'`.

- [ ] **Step 3: Add the ContextVars and the guard helper**

In `mcp_server/server.py`, add alongside the existing ContextVars (after line 39):

```python
# Multi-agent: is the caller acting for a human ("delegated") or on its own
# behalf ("machine")? Derived by the middleware, never declared by the caller.
current_principal_type: ContextVar[str] = ContextVar("current_principal_type", default="delegated")
current_agent_id: ContextVar[str] = ContextVar("current_agent_id", default="")
```

Add next to `_require_entra_provider` (~line 359):

```python
def _require_delegated_user() -> dict | None:
    """Return an error dict if the caller is a machine principal, else None.

    Graph's /me endpoints are meaningless without a human: there is nobody for
    the agent to be "on behalf of". An app-only Graph token would read the
    *application's* mailbox and drive, which is emphatically not what these
    tools mean. Refuse rather than silently return the wrong identity's data.
    """
    if current_principal_type.get() == "machine":
        return {
            "error": "no_delegated_user",
            "agent_id": current_agent_id.get(),
            "note": (
                "This tool acts on behalf of a signed-in user. The caller is an "
                "agent with no user context (event-triggered). Invoke it through "
                "a user session instead."
            ),
        }
    return None
```

- [ ] **Step 4: Guard `_get_graph_token`**

In `mcp_server/server.py`, add at the top of `_get_graph_token` (before the provider check, ~line 340):

```python
    # OBO requires a user assertion by definition — a machine principal has none.
    if current_principal_type.get() == "machine":
        return None
```

- [ ] **Step 5: Guard the three Graph tools**

In `get_user_profile`, insert immediately after `user_role = current_user_role.get()`:

```python
    delegation_error = _require_delegated_user()
    if delegation_error:
        return delegation_error
```

In `list_files` and `send_email`, insert as the first statement of each function body:

```python
    delegation_error = _require_delegated_user()
    if delegation_error:
        return delegation_error
```

- [ ] **Step 6: Resolve machine principals in the middleware**

In `mcp_server/server.py`, add the import near the `policy` import (line 31):

```python
from agent_common.principal import is_app_token
```

In `UserContextMiddleware._resolve_context`, insert immediately after the `provider = _detect_provider(token.claims)` line:

```python
        # Machine principal: an agent calling on its own behalf. It has no email
        # and no groups — its role comes from its app id via [agent_rules].
        if is_app_token(token.claims):
            agent_id = token.claims.get("azp") or token.claims.get("appid", "")
            available_roles = self.policy_evaluator.get_agent_roles(agent_id, provider)

            headers = get_http_headers()
            assumed_role = headers.get("x-assume-role", "")

            if assumed_role and assumed_role not in available_roles:
                raise ToolError(
                    f"[TOOL_DENIAL] Agent '{agent_id}' cannot assume role "
                    f"'{assumed_role}'. Available roles: {available_roles}"
                )
            if not assumed_role:
                if not available_roles and raise_on_error:
                    raise ToolError(
                        f"[TOOL_DENIAL] Agent '{agent_id}' has no roles. "
                        f"Add it to [agent_rules] in permissions.toml."
                    )
                assumed_role = available_roles[0] if available_roles else "none"

            current_user_token.set(token.token)
            current_user_email.set("")
            current_user_role.set(assumed_role)
            current_user_provider.set(provider)
            current_principal_type.set("machine")
            current_agent_id.set(agent_id)

            logger.info(
                "Agent %s assumed role '%s' (available: %s)",
                agent_id, assumed_role, available_roles,
            )
            return

        current_principal_type.set("delegated")
        current_agent_id.set("")
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/test_mcp_machine_principal.py -v`
Expected: PASS — 4 tests.

- [ ] **Step 8: Verify no regression**

Run: `uv run pytest tests/test_access_control.py tests/test_agent_policy.py -v`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add mcp_server/server.py tests/test_mcp_machine_principal.py
git commit -m "feat(mcp): resolve machine principals; Graph tools require a delegated user"
```

---

### Task 8: Peer agent (subagent 2)

A minimal A2A-style agent: no LLM, deterministic tools. It is both a callee (from the orchestrator and the gateway) and a caller (to the gateway, for the peer scenario).

**Files:**
- Create: `peer_agent/__init__.py`
- Create: `peer_agent/server.py`
- Test: `tests/test_peer_agent.py`

**Interfaces:**
- Consumes: `agent_common.principal`, `agent_common.registry`, `agent_common.tokens` (Tasks 3–4).
- Produces: HTTP service on `PEER_AGENT_PORT` (10005) with `POST /invoke` (agent-authenticated) and `GET /health` (public). `/invoke` body: `{"action": str, "params": dict}`. Response: `{"agent": "peer", "action": str, "principal_type": str, "acting_agent": str, "on_behalf_of": str, "result": dict}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_peer_agent.py`:

```python
"""Peer agent — verifies its caller and reports the principal it resolved."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def peer_env(monkeypatch):
    monkeypatch.setenv("ENTRA_CLIENT_ID", "gw-id")
    monkeypatch.setenv("AGENT_ORCHESTRATOR_CLIENT_ID", "orch-id")
    monkeypatch.setenv("AGENT_PEER_CLIENT_ID", "peer-id")
    from agent_common import registry
    registry.reload()
    yield
    registry.reload()


@pytest.fixture
def client(peer_env):
    from peer_agent.server import app
    return TestClient(app)


def test_health_is_public(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["agent"] == "peer"


def test_invoke_without_a_token_is_rejected(client):
    resp = client.post("/invoke", json={"action": "status", "params": {}})
    assert resp.status_code == 401
    assert resp.json()["denial_reason"] == "missing_token"


def test_invoke_with_an_unverifiable_token_is_rejected(client):
    resp = client.post(
        "/invoke",
        json={"action": "status", "params": {}},
        headers={"Authorization": "Bearer not-a-real-jwt"},
    )
    assert resp.status_code in (401, 403)
    assert resp.json()["denial_level"] == "agent"


def stub_principal(peer, **overrides):
    """Replace _authenticate with one that yields a fixed, already-verified principal.

    Verification itself is covered by test_agent_identity.py (claim logic) and
    test_agent_registry.py (signature). These tests are about what the peer DOES
    with a principal once it has one.
    """
    fields = {
        "principal_type": "machine",
        "agent_id": "orch-id",
        "agent_roles": ["Agent.Invoke"],
        "user_claims": None,
        "user_token": None,
    }
    fields.update(overrides)

    async def _stub(request):
        return peer.Principal(**fields)

    return _stub


def test_unknown_action_is_rejected(client, monkeypatch):
    """Authorized caller, but asking for something the peer does not do."""
    from peer_agent import server as peer

    monkeypatch.setattr(peer, "_authenticate", stub_principal(peer))
    resp = client.post("/invoke", json={"action": "nope", "params": {}})
    assert resp.status_code == 400
    assert "unknown_action" in resp.json()["error"]


def test_status_action_reports_the_machine_principal(client, monkeypatch):
    from peer_agent import server as peer

    monkeypatch.setattr(peer, "_authenticate", stub_principal(peer))
    body = client.post("/invoke", json={"action": "status", "params": {}}).json()
    assert body["principal_type"] == "machine"
    assert body["acting_agent"] == "orch-id"
    assert body["on_behalf_of"] == ""
    assert body["result"]["healthy"] is True


def test_status_action_reports_the_delegated_user(client, monkeypatch):
    """The human stays the subject; the agent is recorded as the actor."""
    from peer_agent import server as peer

    monkeypatch.setattr(
        peer, "_authenticate",
        stub_principal(
            peer,
            principal_type="delegated",
            user_claims={"sub": "u1", "preferred_username": "adele@example.com"},
            user_token="user-token",
        ),
    )
    body = client.post("/invoke", json={"action": "status", "params": {}}).json()
    assert body["principal_type"] == "delegated"
    assert body["acting_agent"] == "orch-id"
    assert body["on_behalf_of"] == "adele@example.com"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_peer_agent.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'peer_agent'`.

- [ ] **Step 3: Write the peer agent**

Create `peer_agent/__init__.py`:

```python
"""Minimal subagent — deterministic tools, no LLM. Auth is what is under test."""
```

Create `peer_agent/server.py`:

```python
"""Peer agent — a minimal subagent that verifies who is calling it.

No LLM: the actions are deterministic. This exists to exercise the agent
identity contract, not to be clever. It is both a callee (orchestrator,
gateway) and a caller (gateway), which is what makes the peer-to-peer mutual
verification scenario possible.
"""
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent_common import registry
from agent_common.jwt_validator import EntraJWTValidator, TokenVerificationError
from agent_common.principal import (
    AgentAuthError,
    Principal,
    derive_principal,
    verify_agent_claims,
)

load_dotenv()

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_DIR / "peer_agent.log"), logging.StreamHandler()],
)
logger = logging.getLogger("peer_agent")

PEER_AGENT_PORT = int(os.getenv("PEER_AGENT_PORT", 10005))

app = FastAPI(title="Peer Agent")


def _deny(status: int, reason: str, message: str) -> Response:
    """Deny with the same shape the gateway uses, so the frontend classifier works."""
    return Response(
        status_code=status,
        media_type="application/json",
        content=json.dumps({
            "error": "access_denied",
            "message": message,
            "denial_level": "agent",
            "denial_reason": reason,
        }),
    )


_validator = EntraJWTValidator()


async def _authenticate(request: Request) -> Principal:
    """Verify the caller and derive the principal. Raises AgentAuthError.

    Signature FIRST, claims second. A claim read out of an unverified token is
    an attacker-supplied string — every azp/roles/audience check below is
    meaningless until the signature has been checked against Entra's JWKS.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise AgentAuthError("missing_token", "Missing agent token")

    me = registry.get_agent("peer")

    try:
        agent_claims = await _validator.validate(auth_header[7:], me.audience)
    except TokenVerificationError as e:
        raise AgentAuthError("validation_failed", str(e))

    verify_agent_claims(
        claims=agent_claims,
        expected_audience=me.audience,
        allowed_callers=registry.allowed_callers_for("peer"),
        required_role=registry.REQUIRED_ROLE,
    )

    # A delegated user token may ride alongside. It is verified with the same
    # rigour — an agent must not be able to fabricate a user.
    user_token = request.headers.get("X-Delegated-User-Token", "")
    user_claims = None
    if user_token:
        try:
            user_claims = await _validator.validate(user_token, me.audience)
        except TokenVerificationError as e:
            raise AgentAuthError("validation_failed", f"Delegated user token: {e}")

    return derive_principal(agent_claims, user_claims, user_token or None)


ACTIONS = {"status", "echo"}


@app.post("/invoke")
async def invoke(request: Request):
    """Run a deterministic action, reporting the principal that was resolved."""
    try:
        principal = await _authenticate(request)
    except AgentAuthError as e:
        logger.warning("Caller rejected (%s): %s", e.denial_reason, e.message)
        status = 401 if e.denial_reason in ("missing_token", "validation_failed") else 403
        return _deny(status, e.denial_reason, e.message)

    body = await request.json()
    action = body.get("action", "")
    params = body.get("params", {})

    if action not in ACTIONS:
        return Response(
            status_code=400,
            media_type="application/json",
            content=json.dumps({"error": f"unknown_action: {action}"}),
        )

    if action == "status":
        result = {"healthy": True, "known_actions": sorted(ACTIONS)}
    else:  # echo
        result = {"echoed": params.get("text", "")}

    logger.info(
        "Action '%s' by agent %s (principal=%s)",
        action, principal.agent_id, principal.principal_type,
    )

    return {
        "agent": "peer",
        "action": action,
        "principal_type": principal.principal_type,
        "acting_agent": principal.agent_id,
        "on_behalf_of": principal.user_email,
        "result": result,
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "agent": "peer"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PEER_AGENT_PORT)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_peer_agent.py -v`
Expected: PASS — 6 tests.

- [ ] **Step 5: Commit**

```bash
git add peer_agent/ tests/test_peer_agent.py
git commit -m "feat(peer-agent): minimal subagent that verifies its caller"
```

---

### Task 9: Orchestrator

Fans out to both subagents. Deterministic routing — no LLM. Mints a fresh agent token per callee, and when a human is upstream, OBO-exchanges the user token per callee.

**Files:**
- Create: `orchestrator_agent/__init__.py`
- Create: `orchestrator_agent/server.py`
- Test: `tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `agent_common` (Tasks 3–4); the peer agent's `POST /invoke` (Task 8); the gateway's `POST /` (Task 6).
- Produces: HTTP service on `ORCHESTRATOR_PORT` (10004) with `POST /dispatch` and `GET /health`. `/dispatch` body: `{"task": str}`. Response: `{"principal_type": str, "acting_agent": str, "on_behalf_of": str, "subagents": {"peer": {...}, "gateway": {...}}}`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_orchestrator.py`:

```python
"""Orchestrator — mints per-callee tokens and fans out to both subagents."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def orch_env(monkeypatch):
    monkeypatch.setenv("ENTRA_CLIENT_ID", "gw-id")
    monkeypatch.setenv("AGENT_ORCHESTRATOR_CLIENT_ID", "orch-id")
    monkeypatch.setenv("AGENT_PEER_CLIENT_ID", "peer-id")
    monkeypatch.setenv("AGENT_EVENT_TRIGGER_CLIENT_ID", "evt-id")
    from agent_common import registry
    registry.reload()
    yield
    registry.reload()


@pytest.fixture
def client(orch_env):
    from orchestrator_agent.server import app
    return TestClient(app)


def stub_authenticate(orch, **overrides):
    """Replace _authenticate with one yielding a fixed, already-verified principal.

    Verification itself is covered by test_agent_identity.py and
    test_agent_registry.py. These tests are about what the orchestrator DOES
    with a principal — specifically, which tokens it mints for the next hop.
    """
    fields = {
        "principal_type": "machine",
        "agent_id": "evt-id",
        "agent_roles": ["Agent.Invoke"],
        "user_claims": None,
        "user_token": None,
    }
    fields.update(overrides)

    async def _stub(request):
        return orch.Principal(**fields)

    return _stub


async def _fixed_token(callee):
    return f"agent-token-for-{callee}"


@pytest.fixture
def authorized(monkeypatch):
    """Stand in for a verified event-trigger caller (machine principal)."""
    from orchestrator_agent import server as orch

    monkeypatch.setattr(orch, "_authenticate", stub_authenticate(orch))


def test_health_is_public(client):
    assert client.get("/health").json()["agent"] == "orchestrator"


def test_dispatch_without_a_token_is_rejected(client):
    resp = client.post("/dispatch", json={"task": "status"})
    assert resp.status_code == 401
    assert resp.json()["denial_reason"] == "missing_token"


def test_machine_dispatch_mints_one_token_per_callee(client, authorized, monkeypatch):
    """Audience narrowing: each subagent gets a token minted for IT, not a
    forwarded copy of the orchestrator's inbound token."""
    from orchestrator_agent import server as orch

    minted = []

    async def fake_agent_token(callee):
        minted.append(callee)
        return f"agent-token-for-{callee}"

    async def fake_call(callee, agent_token, user_token, task):
        return {"agent": callee, "token_seen": agent_token}

    monkeypatch.setattr(orch, "_mint_agent_token", fake_agent_token)
    monkeypatch.setattr(orch, "_call_subagent", fake_call)

    body = client.post("/dispatch", json={"task": "status"}).json()

    assert sorted(minted) == ["gateway", "peer"]
    assert body["subagents"]["peer"]["token_seen"] == "agent-token-for-peer"
    assert body["subagents"]["gateway"]["token_seen"] == "agent-token-for-gateway"
    assert body["principal_type"] == "machine"


def test_machine_dispatch_never_exchanges_a_user_token(client, authorized, monkeypatch):
    """No human upstream — OBO must not be attempted."""
    from orchestrator_agent import server as orch

    exchanged = []

    async def fake_exchange(user_token, callee):
        exchanged.append(callee)
        return "should-not-happen"

    async def fake_call(callee, agent_token, user_token, task):
        return {"user_token_forwarded": user_token}

    monkeypatch.setattr(orch, "_mint_agent_token", _fixed_token)
    monkeypatch.setattr(orch, "_exchange_user_token", fake_exchange)
    monkeypatch.setattr(orch, "_call_subagent", fake_call)

    body = client.post("/dispatch", json={"task": "status"}).json()

    assert exchanged == []
    assert body["subagents"]["peer"]["user_token_forwarded"] is None


def test_delegated_dispatch_exchanges_the_user_token_per_callee(client, monkeypatch):
    """A human IS upstream: each subagent gets a user token minted for IT."""
    from orchestrator_agent import server as orch

    monkeypatch.setattr(
        orch, "_authenticate",
        stub_authenticate(
            orch,
            principal_type="delegated",
            agent_id="gw-id",
            user_claims={"sub": "u1", "preferred_username": "adele@example.com"},
            user_token="inbound-user-token",
        ),
    )

    exchanged = []

    async def fake_exchange(user_token, callee):
        exchanged.append((user_token, callee))
        return f"user-token-for-{callee}"

    async def fake_call(callee, agent_token, user_token, task):
        return {"user_token_forwarded": user_token}

    monkeypatch.setattr(orch, "_mint_agent_token", _fixed_token)
    monkeypatch.setattr(orch, "_exchange_user_token", fake_exchange)
    monkeypatch.setattr(orch, "_call_subagent", fake_call)

    body = client.post("/dispatch", json={"task": "status"}).json()

    assert sorted(c for _, c in exchanged) == ["gateway", "peer"]
    # The inbound token is never forwarded verbatim.
    assert all(t == "inbound-user-token" for t, _ in exchanged)
    assert body["subagents"]["peer"]["user_token_forwarded"] == "user-token-for-peer"
    assert body["on_behalf_of"] == "adele@example.com"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_orchestrator.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'orchestrator_agent'`.

- [ ] **Step 3: Write the orchestrator**

Create `orchestrator_agent/__init__.py`:

```python
"""Orchestrator — deterministic fan-out to subagents. No LLM; auth is under test."""
```

Create `orchestrator_agent/server.py`:

```python
"""Orchestrator — fans out to two subagents, carrying identity to each.

Routing is deterministic on purpose. What is being tested is the identity
contract, not planning:

  - It mints a FRESH agent token per callee (audience-narrowed), never
    forwarding its own inbound token onward.
  - When a human is upstream, it OBO-exchanges the user token PER CALLEE, so a
    token captured at one hop cannot be replayed at another.
  - When no human is upstream (event-triggered), it sends no user token at all,
    and the subagents' machine-principal path applies.
"""
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent_common import registry
from agent_common.jwt_validator import EntraJWTValidator, TokenVerificationError
from agent_common.principal import (
    AgentAuthError,
    Principal,
    derive_principal,
    verify_agent_claims,
)
from agent_common.tokens import AgentTokenProvider, DelegatedTokenExchanger

load_dotenv()

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "orchestrator.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("orchestrator")

ORCHESTRATOR_PORT = int(os.getenv("ORCHESTRATOR_PORT", 10004))
PEER_URL = f"http://localhost:{os.getenv('PEER_AGENT_PORT', 10005)}"
GATEWAY_URL = f"http://localhost:{os.getenv('A2A_SERVER_PORT', 10000)}"

SUBAGENTS = ["peer", "gateway"]
CALL_TIMEOUT = 30.0

app = FastAPI(title="Orchestrator Agent")

_token_provider: AgentTokenProvider | None = None
_token_exchanger: DelegatedTokenExchanger | None = None


def _providers() -> tuple[AgentTokenProvider, DelegatedTokenExchanger]:
    """Lazily build the token machinery — the registry must be loaded first."""
    global _token_provider, _token_exchanger
    if _token_provider is None:
        me = registry.get_agent("orchestrator")
        _token_provider = AgentTokenProvider(me)
        _token_exchanger = DelegatedTokenExchanger(me)
    return _token_provider, _token_exchanger


def _deny(status: int, reason: str, message: str) -> Response:
    return Response(
        status_code=status,
        media_type="application/json",
        content=json.dumps({
            "error": "access_denied",
            "message": message,
            "denial_level": "agent",
            "denial_reason": reason,
        }),
    )


_validator = EntraJWTValidator()


async def _authenticate(request: Request) -> Principal:
    """Verify the caller and derive the principal. Raises AgentAuthError.

    Signature FIRST, claims second — see agent_common/jwt_validator.py.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise AgentAuthError("missing_token", "Missing agent token")

    me = registry.get_agent("orchestrator")

    try:
        agent_claims = await _validator.validate(auth_header[7:], me.audience)
    except TokenVerificationError as e:
        raise AgentAuthError("validation_failed", str(e))

    verify_agent_claims(
        claims=agent_claims,
        expected_audience=me.audience,
        allowed_callers=registry.allowed_callers_for("orchestrator"),
        required_role=registry.REQUIRED_ROLE,
    )

    user_token = request.headers.get("X-Delegated-User-Token", "")
    user_claims = None
    if user_token:
        try:
            user_claims = await _validator.validate(user_token, me.audience)
        except TokenVerificationError as e:
            raise AgentAuthError("validation_failed", f"Delegated user token: {e}")

    return derive_principal(agent_claims, user_claims, user_token or None)


async def _mint_agent_token(callee: str) -> str:
    """This orchestrator's own app token, minted for `callee`."""
    provider, _ = _providers()
    return await provider.get_agent_token(callee)


async def _exchange_user_token(user_token: str, callee: str) -> str:
    """The inbound user token, re-minted for `callee` via OBO."""
    _, exchanger = _providers()
    return await exchanger.exchange_for(user_token, callee)


async def _call_subagent(
    callee: str, agent_token: str, user_token: str | None, task: str
) -> dict:
    """Invoke a subagent with this hop's own credentials."""
    headers = {"Authorization": f"Bearer {agent_token}"}
    if user_token:
        headers["X-Delegated-User-Token"] = user_token

    if callee == "peer":
        url, payload = f"{PEER_URL}/invoke", {"action": "status", "params": {}}
    else:  # gateway — speaks A2A JSON-RPC
        url = f"{GATEWAY_URL}/"
        payload = {
            "jsonrpc": "2.0",
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": f"orch-{callee}",
                    "role": "user",
                    "parts": [{"kind": "text", "text": task}],
                }
            },
            "id": 1,
        }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=payload, headers=headers, timeout=CALL_TIMEOUT)
        try:
            return response.json()
        except Exception:
            return {"error": "invalid_response", "status": response.status_code}


async def _dispatch_to(callee: str, principal: Principal, task: str) -> dict:
    """One hop: fresh agent token, and a fresh user token if a human is upstream."""
    agent_token = await _mint_agent_token(callee)

    user_token = None
    if principal.principal_type == "delegated" and principal.user_token:
        user_token = await _exchange_user_token(principal.user_token, callee)

    return await _call_subagent(callee, agent_token, user_token, task)


@app.post("/dispatch")
async def dispatch(request: Request):
    """Fan out to both subagents, carrying identity to each."""
    try:
        principal = await _authenticate(request)
    except AgentAuthError as e:
        logger.warning("Caller rejected (%s): %s", e.denial_reason, e.message)
        status = 401 if e.denial_reason in ("missing_token", "validation_failed") else 403
        return _deny(status, e.denial_reason, e.message)

    body = await request.json()
    task = body.get("task", "status")

    logger.info(
        "Dispatching '%s' for agent %s (principal=%s)",
        task, principal.agent_id, principal.principal_type,
    )

    results = await asyncio.gather(
        *(_dispatch_to(callee, principal, task) for callee in SUBAGENTS),
        return_exceptions=True,
    )

    subagents = {}
    for callee, result in zip(SUBAGENTS, results):
        if isinstance(result, Exception):
            logger.error("Subagent %s failed: %s: %s", callee, type(result).__name__, result)
            subagents[callee] = {"error": str(result)}
        else:
            subagents[callee] = result

    return {
        "principal_type": principal.principal_type,
        "acting_agent": principal.agent_id,
        "on_behalf_of": principal.user_email,
        "subagents": subagents,
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "agent": "orchestrator"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=ORCHESTRATOR_PORT)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_orchestrator.py -v`
Expected: PASS — 5 tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator_agent/ tests/test_orchestrator.py
git commit -m "feat(orchestrator): fan out to subagents with per-hop token narrowing"
```

---

### Task 10: Event trigger (the M2M entry point)

A script, not a service. Simulates a cron job or event source: it authenticates with its own certificate and calls the orchestrator with **no user token**, exercising the pure machine path end to end.

**Files:**
- Create: `event_trigger.py`
- Modify: `README.md` (running the new services)

**Interfaces:**
- Consumes: `agent_common.tokens.AgentTokenProvider`, `agent_common.registry` (Task 4); the orchestrator's `POST /dispatch` (Task 9).
- Produces: a CLI. `uv run python event_trigger.py --task status`.

- [ ] **Step 1: Write the script**

Create `event_trigger.py`:

```python
"""Event-triggered agent invocation — the machine-to-machine entry point.

There is no human here. This authenticates with its own certificate, calls the
orchestrator with an agent token and NO user token, and the whole downstream
chain therefore resolves a machine principal: the agents' own app roles decide
what they may do, and the Graph tools correctly refuse.

    uv run python event_trigger.py --task status
"""
import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent))

from agent_common import registry
from agent_common.tokens import AgentTokenProvider

load_dotenv()

ORCHESTRATOR_URL = f"http://localhost:{os.getenv('ORCHESTRATOR_PORT', 10004)}"


async def fire(task: str) -> dict:
    """Mint our own agent token for the orchestrator and dispatch."""
    import httpx

    me = registry.get_agent("event-trigger")
    provider = AgentTokenProvider(me)
    try:
        agent_token = await provider.get_agent_token("orchestrator")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{ORCHESTRATOR_URL}/dispatch",
                json={"task": task},
                # Note what is ABSENT: no X-Delegated-User-Token. No human.
                headers={"Authorization": f"Bearer {agent_token}"},
                timeout=60.0,
            )
            return response.json()
    finally:
        await provider.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Fire an event-triggered agent task")
    parser.add_argument("--task", default="status", help="task to dispatch")
    args = parser.parse_args()

    try:
        registry.get_agent("event-trigger")
    except KeyError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("Run through docs/ENTRA_AGENT_SETUP.md first.", file=sys.stderr)
        sys.exit(1)

    result = asyncio.run(fire(args.task))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run it (expect a clean failure until Task 2 is done)**

Run: `uv run python event_trigger.py --task status`
Expected (Entra not yet configured): exits 1 with `ERROR: Agent 'event-trigger' is not configured. Set AGENT_EVENT_TRIGGER_CLIENT_ID in .env.`
Expected (Entra configured, services running): JSON showing `"principal_type": "machine"` and both subagents' results.

- [ ] **Step 3: Document the new services in `README.md`**

In the "Starting Services" section, after the frontend line, add:

````markdown
Multi-agent testbed (see `docs/ENTRA_AGENT_SETUP.md` for one-time Entra setup):

```bash
# Terminal 5: Peer agent (subagent 2)
uv run python peer_agent/server.py

# Terminal 6: Orchestrator
uv run python orchestrator_agent/server.py

# Fire a machine-to-machine (event-triggered) dispatch — no human involved
uv run python event_trigger.py --task status
```
````

- [ ] **Step 4: Commit**

```bash
git add event_trigger.py README.md
git commit -m "feat(event-trigger): machine-to-machine entry point"
```

---

### Task 11: Integration tests against the real tenant

Everything so far is unit-tested with mock claims — which proves our *logic*, not that **Entra accepts our certificate assertions**. That is the one question mocks cannot answer, and it is the question this whole phase exists to settle. These tests skip cleanly until Task 2 is done.

**Files:**
- Modify: `tests/conftest.py`
- Create: `tests/test_multi_agent_integration.py`
- Modify: `pyproject.toml` (register the `integration` marker)

**Interfaces:**
- Consumes: everything from Tasks 1–10.
- Produces: nothing downstream.

- [ ] **Step 1: Register the marker**

In `pyproject.toml`, extend `markers`:

```toml
markers = [
    "slow: marks tests that go through the LLM pipeline (10-30s each)",
    "integration: hits the real Entra tenant and running services (skips if unconfigured)",
]
```

- [ ] **Step 2: Add fixtures**

Append to `tests/conftest.py`:

```python
# ---------------------------------------------------------------------------
# Multi-agent fixtures (real Entra app registrations — see docs/ENTRA_AGENT_SETUP.md)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def agents_configured():
    """Skip unless every agent app registration and its cert are present."""
    from pathlib import Path

    required = [
        "ENTRA_TENANT_ID",
        "ENTRA_CLIENT_ID",
        "AGENT_ORCHESTRATOR_CLIENT_ID",
        "AGENT_PEER_CLIENT_ID",
        "AGENT_EVENT_TRIGGER_CLIENT_ID",
    ]
    missing = [v for v in required if not os.getenv(v, "").strip()]
    if missing:
        pytest.skip(f"agent identities not configured: {', '.join(missing)}")

    cert_dir = Path(os.getenv("AGENT_CERT_DIR", "pki/certs"))
    for name in ["gateway", "orchestrator", "peer", "event-trigger"]:
        if not (cert_dir / f"{name}.key").exists():
            pytest.skip(f"missing {name} key — run: uv run python pki/generate_certs.py")

    from agent_common import registry
    registry.reload()


@pytest.fixture(scope="session")
def orchestrator_url():
    return os.getenv("ORCHESTRATOR_URL", "http://localhost:10004")


@pytest.fixture(scope="session")
def peer_url():
    return os.getenv("PEER_URL", "http://localhost:10005")


@pytest.fixture(scope="session")
def require_agent_services(orchestrator_url, peer_url):
    """Skip unless the orchestrator and peer agent are running."""
    import httpx

    for label, url in [("Orchestrator", orchestrator_url), ("Peer agent", peer_url)]:
        try:
            resp = httpx.get(f"{url}/health", timeout=5.0)
            if resp.status_code != 200:
                pytest.skip(f"{label} at {url} returned {resp.status_code}")
        except Exception:
            pytest.skip(f"{label} not running at {url}")
```

- [ ] **Step 3: Write the integration tests**

Create `tests/test_multi_agent_integration.py`:

```python
"""Multi-agent integration — real Entra tokens, real services.

These are the tests that prove Entra actually accepts our certificate-signed
assertions and mints the tokens we expect. Unit tests cannot answer that.

Skips unless docs/ENTRA_AGENT_SETUP.md has been completed AND the orchestrator
and peer agent are running.
"""
import jwt
import pytest

pytestmark = pytest.mark.integration


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


# --- The token itself -------------------------------------------------------

async def test_certificate_assertion_mints_a_token(event_trigger_token):
    """Entra accepted our cert-signed client assertion. Nothing else works if this fails."""
    assert event_trigger_token
    assert len(event_trigger_token.split(".")) == 3


async def test_minted_token_is_a_machine_token(event_trigger_token):
    claims = jwt.decode(event_trigger_token, options={"verify_signature": False})
    from agent_common.principal import is_app_token

    assert is_app_token(claims) is True
    assert claims.get("idtyp") == "app", (
        "idtyp claim missing — configure the optional claim (ENTRA_AGENT_SETUP.md §4)"
    )


async def test_minted_token_is_narrowed_to_the_orchestrator(event_trigger_token):
    """Audience narrowing is what stops a token being replayed at another hop."""
    import os

    claims = jwt.decode(event_trigger_token, options={"verify_signature": False})
    orch_id = os.getenv("AGENT_ORCHESTRATOR_CLIENT_ID")
    assert claims["aud"] in (orch_id, f"api://{orch_id}")


async def test_minted_token_carries_the_invoke_role(event_trigger_token):
    claims = jwt.decode(event_trigger_token, options={"verify_signature": False})
    assert "Agent.Invoke" in claims.get("roles", []), (
        "Agent.Invoke not assigned — see ENTRA_AGENT_SETUP.md §5"
    )


# --- The M2M fan-out --------------------------------------------------------

async def test_event_triggered_fanout_reaches_both_subagents(
    agents_configured, require_agent_services
):
    from event_trigger import fire

    result = await fire("status")

    assert result["principal_type"] == "machine"
    assert result["on_behalf_of"] == ""
    assert "peer" in result["subagents"]
    assert "gateway" in result["subagents"]


async def test_peer_subagent_resolved_the_machine_principal(
    agents_configured, require_agent_services
):
    """The peer independently verified the orchestrator — not the event trigger."""
    import os

    from event_trigger import fire

    result = await fire("status")
    peer = result["subagents"]["peer"]

    assert peer["principal_type"] == "machine"
    assert peer["acting_agent"] == os.getenv("AGENT_ORCHESTRATOR_CLIENT_ID")
    assert peer["result"]["healthy"] is True


# --- Rejection paths (a preview of the Phase 3 harness) ---------------------

async def test_peer_rejects_a_token_minted_for_the_orchestrator(
    agents_configured, require_agent_services, peer_url, event_trigger_token
):
    """Replay across hops: a token for the orchestrator must not open the peer."""
    import httpx

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{peer_url}/invoke",
            json={"action": "status", "params": {}},
            headers={"Authorization": f"Bearer {event_trigger_token}"},
            timeout=10.0,
        )

    assert resp.status_code == 403
    assert resp.json()["denial_reason"] == "wrong_audience"


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
```

- [ ] **Step 4: Run the unit suite (must stay green, integration skips)**

Run: `uv run pytest tests/ -v -m "not integration"`
Expected: PASS — all unit tests; integration tests deselected.

- [ ] **Step 5: Run the integration suite**

Prerequisites: Task 2 complete, `.env` populated, and MCP + ADK + gateway + peer + orchestrator all running.

Run: `uv run pytest tests/test_multi_agent_integration.py -v -m integration`
Expected: PASS — 8 tests. If any skip, the skip message names exactly what is missing.

- [ ] **Step 6: Commit**

```bash
git add tests/conftest.py tests/test_multi_agent_integration.py pyproject.toml
git commit -m "test: multi-agent integration against the real tenant"
```

---

### Task 12: Update project docs

Fold the new reality into the docs a future reader (or model) will trust.

**Files:**
- Modify: `HANDOFF.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update `HANDOFF.md`**

In §12 "Design assumptions", replace assumptions 1–4 — they are now false. New text:

```markdown
1. **A principal may be a human OR an agent.** `is_app_token()` distinguishes
   them (`idtyp=app`, with a `roles`-present/`scp`-absent fallback). Humans are
   authorized by group membership; agents by app role (`Agent.Invoke`) and
   audience. `permissions.toml` maps groups→roles for humans under
   `[group_rules]` and app-ids→roles for agents under `[agent_rules]`.
2. **A token may be delegated or app-only.** Graph tools require a delegated
   user (`_require_delegated_user()`); a machine principal gets
   `no_delegated_user` rather than silently reading the *application's* mailbox.
3. **The gateway is one of several agents.** An orchestrator (:10004) fans out
   to the gateway and a peer agent (:10005). The call graph is declared in
   `agent_common/registry.py` and enforced by Entra app-role assignments.
4. **Tokens are audience-narrowed per hop.** Each agent mints a fresh app token
   for its callee, and OBO-exchanges any inbound user token for that callee. A
   token captured at hop N is rejected at hop N+1 (`wrong_audience`). The old
   verbatim-forwarding behaviour survives only on the gateway→ADK→MCP path.
```

Add to §13 (known limitations):

```markdown
| 19 | Agent hops run over plain HTTP — no mTLS yet | orchestrator, peer agent | A rogue that squats a callee's port can harvest tokens and replay them to the real callee. Closed in Phase 2 (mTLS + azp↔peer-cert binding) |
| 20 | Two JWT validators now exist | `a2a_server/server.py` `TokenValidator` (multi-IdP) and `agent_common/jwt_validator.py` `EntraJWTValidator` (Entra-only) | Duplicated JWKS logic. The gateway's is multi-IdP and predates the agent work; converging them is a follow-up |
| 21 | `EntraJWTValidator` JWKS cache has no TTL | `agent_common/jwt_validator.py` | Same limitation as #4 — clears and retries on a `kid` miss |
```

- [ ] **Step 2: Update `CLAUDE.md`**

In "Project Structure", add after the `mcp_server/` block:

```
├── agent_common/
│   ├── principal.py           # Pure claim validation + principal derivation
│   ├── registry.py            # Agent identities + call graph
│   └── tokens.py              # Cert-backed token acquisition + per-hop OBO
├── orchestrator_agent/
│   └── server.py              # Fan-out to subagents (:10004, no LLM)
├── peer_agent/
│   └── server.py              # Minimal subagent (:10005, no LLM)
├── pki/
│   └── generate_certs.py      # Mini-CA + per-agent key pairs
├── event_trigger.py           # M2M entry point (no human)
```

Add a new section after "Three-Tier Access Control":

```markdown
### Multi-Agent Identity

Every inter-agent call carries the caller's own certificate-backed Entra app
token (`Authorization: Bearer`), and — only when a human is upstream — an
OBO-exchanged user token (`X-Delegated-User-Token`). **Principal type is
derived from which tokens are present, never declared by the caller**:

| Principal | When | Authorized by | Graph tools |
|---|---|---|---|
| `delegated` | a human is upstream | the human's role (groups → `[group_rules]`) | allowed |
| `machine` | event-triggered, no human | the agent's role (app id → `[agent_rules]`) | `no_delegated_user` |

Both tokens are **audience-narrowed per hop** — each agent mints fresh
credentials for its callee rather than forwarding what it received.

Agents authenticate with an x509 certificate (`pki/certs/`), never a client
secret. Setup: `docs/ENTRA_AGENT_SETUP.md`.
```

- [ ] **Step 3: Commit**

```bash
git add HANDOFF.md CLAUDE.md
git commit -m "docs: record multi-agent identity model"
```

---

## Phase 1 Definition of Done

- [ ] `uv run pytest tests/ -m "not integration"` — all green.
- [ ] `uv run pytest tests/ -m integration` — all green with the tenant configured and all five services running.
- [ ] `uv run python event_trigger.py --task status` prints `"principal_type": "machine"` with results from both subagents.
- [ ] A human chat through the frontend still works end to end, unchanged.
- [ ] **A forged token — correct `azp`, correct `roles`, correct `aud`, wrong signature — is rejected.** If this passes and nothing else does, the phase still has value; if this fails, nothing else in the phase means anything.
- [ ] A token minted for one agent is rejected by another with `wrong_audience`.
- [ ] A Graph tool invoked on the machine path returns `no_delegated_user` rather than the application's own mailbox.

## Deferred to later phases

**Phase 2 — transport & binding:** mTLS across all agent hops (uvicorn `ssl_ca_certs` + `CERT_REQUIRED`, httpx client certs), the `azp`↔peer-cert binding check that makes bearer tokens sender-constrained, and a dev_config toggle so the difference is demonstrable.

**Phase 3 — adversarial harness:** `rogue_agent.py` running the attack matrix (spec §8) with mTLS on and off, proving which layer catches what. Two attacks in that matrix — endpoint squatting and token replay to the real callee — **succeed** until Phase 2 lands. That is the demonstration.

Each gets its own plan document.
