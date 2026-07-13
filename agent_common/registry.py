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
