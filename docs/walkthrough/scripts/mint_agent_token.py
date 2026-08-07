"""Mint an agent token for a chosen callee — a walkthrough helper (Acts 06, 07).

This does exactly what every agent does before an outbound call: use its own
certificate to mint an app-only token audience-narrowed to a specific callee.
It reuses the real `agent_common` code — no new logic — so reading it is also a
way to see how the library is meant to be called.

    uv run python docs/walkthrough/scripts/mint_agent_token.py --as event-trigger --for orchestrator --print-token

`--as`  the agent whose identity mints the token (must have a cert in pki/certs
        and its AGENT_*_CLIENT_ID set — or be the gateway, which reuses
        ENTRA_CLIENT_ID).
`--for` the callee the token is minted for (its audience). Entra will only mint
        this if `--as` holds Agent.Invoke on `--for` (ENTRA_AGENT_SETUP.md §5).

Without --print-token it prints only the decoded claims, so you can eyeball
`aud`, `azp`, `idtyp` and `roles` without pasting a live credential anywhere.

Exit codes: 0 minted; 1 could not run (unconfigured, or Entra refused).
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

# Repo root on sys.path, so `agent_common` imports the same way the services do.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from dotenv import load_dotenv

from agent_common import registry
from agent_common.tokens import AgentTokenProvider

load_dotenv()


def _decode_without_verifying(token: str) -> dict:
    """Decode claims for display only. We just received this over TLS from
    Entra; this is a convenience readout, not a security check."""
    import jwt

    return jwt.decode(token, options={"verify_signature": False})


async def _mint(caller: str, callee: str) -> str:
    provider = AgentTokenProvider(registry.get_agent(caller))
    try:
        return await provider.get_agent_token(callee)
    finally:
        await provider.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Mint an agent token for a callee")
    parser.add_argument("--as", dest="caller", required=True,
                        help="agent whose cert mints the token (e.g. event-trigger)")
    parser.add_argument("--for", dest="callee", required=True,
                        help="callee the token is audienced to (e.g. orchestrator)")
    parser.add_argument("--print-token", action="store_true",
                        help="print the raw JWT (a live credential) as well as its claims")
    args = parser.parse_args()

    try:
        registry.get_agent(args.caller)
        registry.get_agent(args.callee)
    except KeyError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("Configure the agent tier first - see docs/ENTRA_AGENT_SETUP.md.", file=sys.stderr)
        sys.exit(1)

    try:
        token = asyncio.run(_mint(args.caller, args.callee))
    except Exception as e:
        # Entra refused (bad cert, missing Agent.Invoke, unknown app). One line,
        # not a traceback — this is a hand-run helper, and the class of failure
        # is what matters, not the internal URL in the exception text.
        print(f"ERROR: could not mint a token as '{args.caller}' for "
              f"'{args.callee}': {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(_decode_without_verifying(token), indent=2, default=str))
    if args.print_token:
        print("\n--- raw token (a live credential; do not paste into logs) ---")
        print(token)


if __name__ == "__main__":
    main()
