"""Event-triggered agent invocation — the machine-to-machine entry point.

There is no human here. This authenticates with its own certificate, calls the
orchestrator with an agent token and NO user token, and the whole downstream
chain therefore resolves a machine principal: the agents' own app roles decide
what they may do, and the Graph tools correctly refuse.

    uv run python event_trigger.py --task status

The absence of `X-Delegated-User-Token` is the entire point of this script.
Principal type is DERIVED from which tokens are present (spec §4) — nothing
here declares "I am a machine", and nothing downstream is told to expect one.
Adding a user token to this call would silently convert every machine-path
assertion in the testbed into a delegated-path one.

Exit codes, because this simulates a cron source and unattended callers can
only see the status:

    0  dispatched, and the chain resolved a machine principal
    1  could not run at all — not configured, or the orchestrator is unreachable
    2  the orchestrator refused or failed the dispatch
    3  dispatched and succeeded, but the principal was not a machine
"""
import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent))

from agent_common import registry
from agent_common.tokens import AgentTokenProvider

load_dotenv()

ORCHESTRATOR_URL = f"http://localhost:{os.getenv('ORCHESTRATOR_PORT', 10004)}"
DISPATCH_TIMEOUT = 60.0

EXIT_OK = 0
EXIT_CANNOT_RUN = 1
EXIT_REFUSED = 2
EXIT_NOT_A_MACHINE = 3


async def fire(task: str) -> tuple[int, dict]:
    """Mint our own agent token for the orchestrator and dispatch.

    Returns (http_status, body). Transport failures propagate — `main` turns
    them into a one-line message, because a stack trace in a cron log is
    strictly worse than the name of the service that was unreachable.
    """
    me = registry.get_agent("event-trigger")
    provider = AgentTokenProvider(me)
    try:
        agent_token = await provider.get_agent_token("orchestrator")

        # Note what is ABSENT: no X-Delegated-User-Token. No human.
        headers = {"Authorization": f"Bearer {agent_token}"}

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{ORCHESTRATOR_URL}/dispatch",
                json={"task": task},
                headers=headers,
                timeout=DISPATCH_TIMEOUT,
            )

        try:
            body = response.json()
        except Exception:
            body = {"error": "invalid_response", "body": response.text[:500]}

        return response.status_code, body
    finally:
        # The provider holds an azure-identity credential with a live HTTP
        # client; closing it matters even on the failure path.
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
        sys.exit(EXIT_CANNOT_RUN)

    try:
        status, body = asyncio.run(fire(args.task))
    except httpx.HTTPError as e:
        print(
            f"ERROR: could not reach the orchestrator at {ORCHESTRATOR_URL}: {e}",
            file=sys.stderr,
        )
        sys.exit(EXIT_CANNOT_RUN)

    print(json.dumps(body, indent=2))

    if not 200 <= status < 300:
        print(f"ERROR: orchestrator returned {status}", file=sys.stderr)
        sys.exit(EXIT_REFUSED)

    principal_type = body.get("principal_type")
    if principal_type != "machine":
        print(
            f"ERROR: expected a machine principal, got {principal_type!r}. "
            "A user token has entered a chain that is supposed to have no human in it.",
            file=sys.stderr,
        )
        sys.exit(EXIT_NOT_A_MACHINE)

    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
