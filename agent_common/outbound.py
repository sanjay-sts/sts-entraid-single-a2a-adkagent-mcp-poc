"""Building the headers for a call to the next agent.

One implementation, shared by every agent that calls another, because the rule
it enforces is easy to get wrong in a way nothing observable would catch: a
token is minted fresh for each hop, and an inbound user token is never
forwarded as-is.

See spec §4 — the wire contract is always:

    Authorization: Bearer <this agent's token, minted for the callee>
    X-Delegated-User-Token: <the user token, re-exchanged for the callee>

with the second header present only when a human is genuinely upstream.
"""
import logging

from .principal import Principal

logger = logging.getLogger("agent_common.outbound")


async def build_agent_headers(
    callee: str,
    principal: Principal | None,
    token_provider,
    exchanger,
) -> dict[str, str]:
    """Headers for calling `callee` on behalf of `principal`.

    `principal` is who is calling US, and may be None for a call this agent
    originates itself (an event trigger, a health probe) — in which case the
    call is machine-only, since there is no user to delegate.

    The user token is EXCHANGED for the callee, never forwarded. Forwarding the
    inbound one would hand the callee a token minted for us, which that callee
    could then replay at anywhere we can be called — the exact replay that
    per-hop audience narrowing exists to prevent. It also means a compromised
    callee cannot walk a user's token further than the one hop we granted.

    Delegation is derived from what we actually hold, not from what the
    principal claims to be: a delegated principal whose user token was
    discarded upstream (see `derive_principal`) gets a machine-only call rather
    than a header we cannot honestly fill in.
    """
    headers = {"Authorization": f"Bearer {await token_provider.get_agent_token(callee)}"}

    if principal is not None and principal.user_token:
        headers["X-Delegated-User-Token"] = await exchanger.exchange_for(
            principal.user_token, callee
        )
        logger.debug("Calling %s on behalf of a delegated user", callee)
    else:
        logger.debug("Calling %s as a machine principal", callee)

    return headers
