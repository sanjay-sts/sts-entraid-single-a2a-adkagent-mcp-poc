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
