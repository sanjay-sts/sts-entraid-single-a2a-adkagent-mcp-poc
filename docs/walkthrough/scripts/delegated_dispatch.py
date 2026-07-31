"""Send a human's identity through the orchestrator — a walkthrough helper (Act 06).

This reproduces the gateway->orchestrator delegated hop by hand, so you can watch
the orchestrator resolve a DELEGATED principal and see the exchanged token narrow
per hop. It mirrors the integration suite's fixtures exactly
(tests/test_multi_agent_integration.py: `event_trigger_token`, `obo_token`) —
same calls, same identities — so if the integration path works, this does too.

What it does:
  1. Reads a real user token from TEST_ADMIN_TOKEN (sign in to the frontend,
     copy it from the Token Inspector; it lasts ~1 hour, audienced to the gateway).
  2. Uses the GATEWAY's certificate to OBO-exchange that user token into one
     narrowed for the ORCHESTRATOR (DelegatedTokenExchanger — never forwarding
     the original).
  3. Mints the EVENT-TRIGGER's own agent token for the orchestrator (the allowed
     caller into it).
  4. POSTs /dispatch with both headers and prints the orchestrator's response.

    uv run python docs/walkthrough/scripts/delegated_dispatch.py

Exit codes: 0 dispatched and resolved DELEGATED; 1 could not run; 2 the
orchestrator refused; 3 dispatched but the principal was not delegated (a user
token failed to carry through — the interesting failure).
"""
import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import httpx
from dotenv import load_dotenv

from agent_common import registry
from agent_common.tokens import AgentTokenProvider, DelegatedTokenExchanger

load_dotenv()

ORCHESTRATOR_URL = f"http://localhost:{os.getenv('ORCHESTRATOR_PORT', 10004)}"
DISPATCH_TIMEOUT = 60.0

EXIT_OK = 0
EXIT_CANNOT_RUN = 1
EXIT_REFUSED = 2
EXIT_NOT_DELEGATED = 3


def _user_token_or_exit() -> str:
    token = os.getenv("TEST_ADMIN_TOKEN", "").strip()
    if not token:
        print("ERROR: TEST_ADMIN_TOKEN is not set. Sign in to the frontend, open the "
              "Token Inspector, and copy the raw token into .env.", file=sys.stderr)
        sys.exit(EXIT_CANNOT_RUN)
    import jwt
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        print(f"ERROR: TEST_ADMIN_TOKEN is not a JWT: {e}", file=sys.stderr)
        sys.exit(EXIT_CANNOT_RUN)
    if claims.get("exp", 0) <= time.time():
        print("ERROR: TEST_ADMIN_TOKEN has expired — sign in again and re-copy it.",
              file=sys.stderr)
        sys.exit(EXIT_CANNOT_RUN)
    return token


async def _run(task: str, show_token: bool) -> tuple[int, dict]:
    user_token = _user_token_or_exit()

    provider = AgentTokenProvider(registry.get_agent("event-trigger"))
    exchanger = DelegatedTokenExchanger(registry.get_agent("gateway"))
    try:
        agent_token = await provider.get_agent_token("orchestrator")
        delegated = await exchanger.exchange_for(user_token, "orchestrator")

        if show_token:
            import jwt
            print("--- exchanged X-Delegated-User-Token claims (aud narrowed, sub unchanged) ---")
            print(json.dumps(jwt.decode(delegated, options={"verify_signature": False}),
                             indent=2, default=str))
            print()

        headers = {
            "Authorization": f"Bearer {agent_token}",
            "X-Delegated-User-Token": delegated,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{ORCHESTRATOR_URL}/dispatch",
                                     json={"task": task}, headers=headers,
                                     timeout=DISPATCH_TIMEOUT)
        try:
            body = resp.json()
        except Exception:
            body = {"error": "invalid_response", "body": resp.text[:500]}
        return resp.status_code, body
    finally:
        await provider.close()
        await exchanger.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Dispatch through the orchestrator as a delegated human")
    parser.add_argument("--task", default="status", help="task to dispatch")
    parser.add_argument("--show-token", action="store_true",
                        help="also print the decoded exchanged user-token claims")
    args = parser.parse_args()

    try:
        registry.get_agent("event-trigger")
        registry.get_agent("gateway")
    except KeyError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("Configure the agent tier first - see docs/ENTRA_AGENT_SETUP.md.", file=sys.stderr)
        sys.exit(EXIT_CANNOT_RUN)

    try:
        status, body = asyncio.run(_run(args.task, args.show_token))
    except httpx.HTTPError as e:
        print(f"ERROR: could not reach the orchestrator at {ORCHESTRATOR_URL}: {e}",
              file=sys.stderr)
        sys.exit(EXIT_CANNOT_RUN)
    except Exception as e:
        print(f"ERROR: token minting or exchange failed: {type(e).__name__}: {e}",
              file=sys.stderr)
        sys.exit(EXIT_CANNOT_RUN)

    print(json.dumps(body, indent=2, default=str))

    if not 200 <= status < 300:
        print(f"ERROR: orchestrator returned {status}", file=sys.stderr)
        sys.exit(EXIT_REFUSED)
    if body.get("principal_type") != "delegated":
        print(f"ERROR: expected a delegated principal, got "
              f"{body.get('principal_type')!r}. The user token did not carry through.",
              file=sys.stderr)
        sys.exit(EXIT_NOT_DELEGATED)
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
