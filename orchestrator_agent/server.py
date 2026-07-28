"""Orchestrator — fans out to two subagents, carrying identity to each.

Routing is deterministic on purpose. What is being tested is the identity
contract, not planning:

  - It mints a FRESH agent token per callee (audience-narrowed), never
    forwarding its own inbound token onward.
  - When a human is upstream, it OBO-exchanges the user token PER CALLEE, so a
    token captured at one hop cannot be replayed at another.
  - When no human is upstream (event-triggered), it sends no user token at all,
    and the subagents' machine-principal path applies.

Fan-out is what makes this hop different from every other one. Everywhere else
a single identity travels to a single callee; here one inbound principal
becomes N outbound calls, so the per-hop exchange rule has to hold N times and
a partial failure must not quietly change what a call is authorized as.
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
    handlers=[
        logging.FileHandler(LOG_DIR / "orchestrator.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("orchestrator")

ORCHESTRATOR_PORT = int(os.getenv("ORCHESTRATOR_PORT", 10004))
PEER_URL = f"http://localhost:{os.getenv('PEER_AGENT_PORT', 10005)}"
GATEWAY_URL = f"http://localhost:{os.getenv('A2A_SERVER_PORT', 10000)}"

# Same blocklist the gateway and the peer read. The *check* is duplicated
# deliberately: an agent that trusted an upstream hop to have checked would be
# trusting a hop it cannot see. Only the parsing is shared.
BLOCKED_USERS = load_blocked_users()

SUBAGENTS = ["peer", "gateway"]
CALL_TIMEOUT = 30.0

app = FastAPI(title="Orchestrator Agent")

_validator = EntraJWTValidator()

# Built lazily: constructing these reads this agent's private key off disk,
# which must not be a precondition for importing the module or serving /health.
_token_provider: AgentTokenProvider | None = None
_token_exchanger: DelegatedTokenExchanger | None = None


def _providers() -> tuple[AgentTokenProvider, DelegatedTokenExchanger]:
    global _token_provider, _token_exchanger
    me = registry.get_agent("orchestrator")
    if _token_provider is None:
        _token_provider = AgentTokenProvider(me)
    if _token_exchanger is None:
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
        verify_delegated_user(user_claims, BLOCKED_USERS)

    return derive_principal(agent_claims, user_claims, user_token or None)


def _payload_for(callee: str, task: str) -> tuple[str, dict]:
    """Where a subagent lives and what it expects to be sent."""
    if callee == "peer":
        return f"{PEER_URL}/invoke", {"action": "status", "params": {}}

    # The gateway speaks A2A JSON-RPC.
    return f"{GATEWAY_URL}/", {
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


async def _dispatch_to(callee: str, principal: Principal, task: str) -> dict:
    """One hop: this agent's own credentials, minted for this callee.

    `build_agent_headers` is shared with the peer agent rather than reimplemented
    here — the rule it encodes (exchange the user token, never forward it) is
    exactly the kind that drifts when each service writes its own version.

    Nothing here catches a minting or exchange failure. That is deliberate: a
    hop whose user token could not be obtained must FAIL, not proceed without
    one. Falling back would silently downgrade a delegated call to machine
    privileges — a different principal than the caller asked for, with nothing
    in the response to say so.
    """
    provider, exchanger = _providers()
    headers = await build_agent_headers(callee, principal, provider, exchanger)
    url, payload = _payload_for(callee, task)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            url, json=payload, headers=headers, timeout=CALL_TIMEOUT
        )

    try:
        body = response.json()
    except Exception:
        body = None

    # `ok` is explicit rather than inferred by the reader: this testbed exists
    # to show which layer refused what, and a denial flattened into a shape
    # indistinguishable from success defeats the whole point.
    return {
        "ok": 200 <= response.status_code < 300,
        "status": response.status_code,
        "response": body,
        "error": None,
    }


@app.post("/dispatch")
async def dispatch(request: Request):
    """Fan out to both subagents, carrying identity to each."""
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
        if isinstance(result, BaseException):
            # The detail goes to the log, not to the caller: exception text can
            # carry internal URLs and configuration, and the caller here is
            # another agent, not an operator.
            logger.error(
                "Subagent %s failed: %s: %s", callee, type(result).__name__, result
            )
            subagents[callee] = {
                "ok": False,
                "status": None,
                "response": None,
                "error": "subagent_call_failed",
            }
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
