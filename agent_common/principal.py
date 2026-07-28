"""Pure claim validation and principal derivation for agent-to-agent calls.

No network, no I/O — every function here is a pure function of its claims,
so the security contract is unit-testable without a tenant.

The contract (spec §4):
  Authorization: Bearer <agent app token>    always — "who is calling"
  X-Delegated-User-Token: <user token>       only when a human is upstream

Principal type is DERIVED from which tokens are present. A caller can never
declare it.

SECURITY WARNING: every function in this module operates on claims taken at
face value. None of them verify a JWT signature, issuer, or expiry — that is
the caller's job (see `agent_common/jwt_validator.py`). A claims dict handed
to `is_app_token`, `verify_agent_claims`, or `derive_principal` from a token
whose signature has not already been verified is nothing but an
attacker-supplied string dressed up as JSON. Calling these functions on an
unverified token provides no security whatsoever — always verify the
signature first.
"""
from dataclasses import dataclass
from types import MappingProxyType

# Principal types
DELEGATED = "delegated"
MACHINE = "machine"

# Claims that, when present, indicate a delegated (human) token rather than
# an app-only (machine) token. Centralized so the "is this a human" heuristic
# — used both for the user-email lookup and (historically) for is_app_token's
# fallback — is auditable in exactly one place.
USER_IDENTITY_CLAIMS = ("preferred_username", "upn", "unique_name")


class AgentAuthError(Exception):
    """Agent-identity verification failed. Carries a stable denial reason."""

    def __init__(self, denial_reason: str, message: str):
        super().__init__(message)
        self.denial_reason = denial_reason
        self.message = message


def is_app_token(claims: dict) -> bool:
    """True if these claims came from a client-credentials (app-only) token.

    SECURITY WARNING: this function trusts `claims` completely. Only call it
    on claims taken from a token whose signature has already been verified —
    otherwise `idtyp` is just an attacker-supplied string.

    The only signal is the `idtyp` optional claim, which Entra sets to
    "app" for app-only tokens. It MUST be configured on every app
    registration — see docs/ENTRA_AGENT_SETUP.md §4.

    There is deliberately no fallback heuristic. A prior version of this
    function treated "roles present, no user-name/scp claims" as a machine
    token, but a delegated token for an API that authorizes purely via app
    roles can legitimately lack `scp` and (depending on optional-claims
    config) lack `preferred_username`/`upn`/`unique_name` too — which would
    make a genuine human token indistinguishable from a machine token under
    that heuristic. So when `idtyp` is absent, this fails closed and returns
    False; see `docs/ENTRA_AGENT_SETUP.md` §4 to configure it.
    """
    return claims.get("idtyp") == "app"


def _audience_matches(actual, expected: str) -> bool:
    """True when `actual` names the same application as `expected`.

    Entra mints `aud` as either the App ID URI (`api://<app-id>`) or the bare
    app id, depending on the resource app registration's
    `accessTokenAcceptedVersion`. Both forms name the same application, and
    which one you get is a property of the tenant rather than of the caller —
    so accepting only one would deny every legitimate agent call in a tenant
    configured the other way, a failure that surfaces only against a real
    tenant. The JWT validators on both sides already accept both forms; this
    keeps the claim check consistent with them.

    Audience *narrowing* is unaffected: different agents have different app
    ids, so a token minted for the peer still does not match the gateway.

    Fails closed on anything unexpected — an empty audience, or the list form
    the JWT spec permits and Entra does not emit.
    """
    if not isinstance(actual, str) or not actual or not expected:
        return False
    return actual.removeprefix("api://") == expected.removeprefix("api://")


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

    Fails closed: any failure raises. `expected_audience`, `allowed_callers`,
    and `required_role` are also validated up front — a misconfigured caller
    (e.g. an empty expected_audience, which would "match" a token with no
    `aud` claim at all) fails loudly instead of silently authorizing.
    """
    if not expected_audience:
        raise ValueError("verify_agent_claims: expected_audience must be non-empty")
    if not required_role:
        raise ValueError("verify_agent_claims: required_role must be non-empty")
    if not allowed_callers:
        raise ValueError("verify_agent_claims: allowed_callers must be a non-empty list")

    if not is_app_token(claims):
        raise AgentAuthError(
            "not_an_agent_token",
            "Authorization token is not a machine (app-only) token: no "
            "idtyp='app' claim was found. Configure the idtyp optional "
            "claim on this app registration — see "
            "docs/ENTRA_AGENT_SETUP.md §4.",
        )

    audience = claims.get("aud", "")
    if not _audience_matches(audience, expected_audience):
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

    Frozen, and the container fields are converted to immutable types in
    __post_init__: a downstream tier must not be able to escalate by
    mutating agent_roles (e.g. appending a role) or user_claims (e.g.
    rewriting `sub`) in place. `frozen=True` alone only blocks attribute
    *reassignment* — it does nothing to stop mutation of a mutable object a
    field points at.
    """

    principal_type: str              # DELEGATED | MACHINE
    agent_id: str                    # calling agent's app id (azp) — always present
    agent_roles: tuple[str, ...]     # calling agent's app roles
    user_claims: dict | None         # None when MACHINE; MappingProxyType otherwise
    user_token: str | None           # None when MACHINE

    def __post_init__(self):
        object.__setattr__(self, "agent_roles", tuple(self.agent_roles))
        if self.user_claims is not None:
            object.__setattr__(
                self, "user_claims", MappingProxyType(dict(self.user_claims))
            )

    @property
    def is_machine(self) -> bool:
        return self.principal_type == MACHINE

    @property
    def user_email(self) -> str:
        if not self.user_claims:
            return ""
        for claim in USER_IDENTITY_CLAIMS:
            value = self.user_claims.get(claim)
            if value:
                return value
        return self.user_claims.get("email", "")


def derive_principal(
    agent_claims: dict,
    user_claims: dict | None,
    user_token: str | None,
) -> Principal:
    """Derive the principal from the tokens actually presented.

    SECURITY WARNING: this function performs zero validation — it trusts
    whatever it is handed. Only pass claims from tokens whose signatures
    have already been verified (see `agent_common/jwt_validator.py`) and
    whose contents have already passed `verify_agent_claims`. Calling this
    on unverified claims provides no security whatsoever.

    Delegated when a validated user token rode along with matching verified
    user_claims; machine otherwise. If a user_token is present but
    user_claims is falsy (e.g. the token failed validation upstream, or a
    caller wired one through without validating it), the token is treated as
    dangling and discarded — it must not be trusted or echoed back, and the
    principal must not become DELEGATED on its account. The acting agent is
    preserved in both cases so delegation is auditable.
    """
    caller = agent_claims.get("azp") or agent_claims.get("appid", "")
    roles = tuple(agent_claims.get("roles", []))

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
