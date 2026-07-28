"""Peer agent — a minimal subagent that verifies who is calling it.

No LLM: the actions are deterministic. This exists to exercise the agent
identity contract, not to be clever. It is both a callee (from the orchestrator
and the gateway) and a caller (to the gateway), which is what makes the
peer-to-peer mutual verification scenario possible.

What it deliberately does NOT do is authorize the human. A subagent's own
authorization comes from its caller's app role; group membership is the
gateway's ACL, resolved from configuration this service does not have. It does
enforce the two properties of a rider token that hold everywhere — that it is
a user at all, and that the user is not blocked — via the shared
`verify_delegated_user`.
"""
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
from agent_common.config import load_blocked_users
from agent_common.jwt_validator import EntraJWTValidator, TokenVerificationError
from agent_common.outbound import build_agent_headers
from agent_common.principal import (
    AgentAuthError,
    Principal,
    derive_principal,
    verify_agent_claims,
    verify_delegated_user,
)
from agent_common.tokens import AgentTokenProvider, DelegatedTokenExchanger

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
A2A_SERVER_URL = os.getenv("A2A_SERVER_URL", "http://localhost:10000")
GATEWAY_CALL_TIMEOUT = 15.0

# Same blocklist the gateway reads. The *check* is duplicated deliberately: a
# subagent that trusted the gateway to have checked would be trusting a hop it
# cannot see. Only the parsing is shared.
BLOCKED_USERS = load_blocked_users()

app = FastAPI(title="Peer Agent")

_validator = EntraJWTValidator()

# Built lazily: constructing a CertificateCredential reads this agent's key off
# disk, which must not be a precondition for importing the module (or for
# serving /health).
_token_provider: AgentTokenProvider | None = None
_exchanger: DelegatedTokenExchanger | None = None


def _outbound_clients():
    global _token_provider, _exchanger
    me = registry.get_agent("peer")
    if _token_provider is None:
        _token_provider = AgentTokenProvider(me)
    if _exchanger is None:
        _exchanger = DelegatedTokenExchanger(me)
    return _token_provider, _exchanger


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
        verify_delegated_user(user_claims, BLOCKED_USERS)

    return derive_principal(agent_claims, user_claims, user_token or None)


async def _call_gateway(principal: Principal) -> dict:
    """Call the gateway's /me as this agent, carrying the principal forward.

    /me reports which principal the *gateway* resolved, which makes this the
    cheapest end-to-end proof that the identity survived the hop intact —
    and that the token was minted for the gateway, not replayed from ours.
    """
    provider, exchanger = _outbound_clients()
    headers = await build_agent_headers("gateway", principal, provider, exchanger)

    async with httpx.AsyncClient(timeout=GATEWAY_CALL_TIMEOUT) as client:
        response = await client.get(f"{A2A_SERVER_URL}/me", headers=headers)
        body = response.json() if response.status_code == 200 else None

    return {"gateway_status": response.status_code, "gateway_me": body}


ACTIONS = {"status", "echo", "call_gateway"}


@app.post("/invoke")
async def invoke(request: Request):
    """Run a deterministic action, reporting the principal that was resolved."""
    try:
        principal = await _authenticate(request)
    except AgentAuthError as e:
        logger.warning("Caller rejected (%s): %s", e.denial_reason, e.message)
        status = 401 if e.denial_reason in ("missing_token", "validation_failed") else 403
        return _deny(status, e.denial_reason, e.message)

    # Body parsed only after the caller is authenticated — an unauthenticated
    # request should never reach a parser.
    try:
        body = await request.json()
    except Exception:
        return Response(
            status_code=400,
            media_type="application/json",
            content=json.dumps({"error": "malformed_body"}),
        )

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
    elif action == "call_gateway":
        result = await _call_gateway(principal)
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
