"""Policy evaluator for tool access control.

Implements a PolicyEvaluator interface that can be swapped for OPA or Cedar later.
Current implementation: TOML-based RBAC with group-to-role mapping.

Future swap points:
  - OPA: Replace TomlPolicyEvaluator with OpaPolicyEvaluator that calls OPA sidecar
  - Cedar: Replace with CedarPolicyEvaluator using cedar-py embedded engine
  - The interface (check_access, get_available_roles) stays the same — callers don't change.
"""

import tomllib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("mcp_server.policy")


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


@dataclass
class AccessDecision:
    """Result of a policy evaluation."""

    allowed: bool
    role: str  # Resolved role (for ContextVar/logging)
    reason: str  # Human-readable reason (for denial messages)


class PolicyEvaluator(ABC):
    """Interface for policy engines. Swap implementation for OPA/Cedar."""

    @abstractmethod
    def get_available_roles(
        self, email: str, provider: str, groups: list[str]
    ) -> list[str]:
        """Return ALL roles the user qualifies for (from groups + user overrides)."""
        ...

    @abstractmethod
    def get_agent_roles(self, agent_id: str, provider: str) -> list[str]:
        """Return the roles a machine principal (agent) qualifies for.

        Agents have no group claims and no email — their role comes from their
        app id alone.
        """
        ...

    @abstractmethod
    def check_access(
        self, request: AccessRequest, allowed_roles: list[str]
    ) -> AccessDecision:
        """Check if the user can access a tool. Full ABAC entry point."""
        ...


class TomlPolicyEvaluator(PolicyEvaluator):
    """TOML-based RBAC evaluator. Production swap: OPA or Cedar."""

    ROLE_PRIORITY = ["admin", "developer", "viewer"]

    def __init__(self, config_path: Path):
        self._config_path = config_path
        self._config: dict = {}
        self._mtime: float = 0.0
        self._load()

    def _load(self) -> None:
        if self._config_path.exists():
            mtime = self._config_path.stat().st_mtime
            if mtime != self._mtime:
                with open(self._config_path, "rb") as f:
                    self._config = tomllib.load(f)
                self._mtime = mtime
                logger.info("Permissions reloaded from %s", self._config_path)
        elif not self._config:
            logger.warning(
                "Permissions file not found: %s — no roles will be assigned. "
                "Copy permissions.example.toml to permissions.toml and configure.",
                self._config_path,
            )

    def get_available_roles(
        self, email: str, provider: str = "", groups: list[str] | None = None
    ) -> list[str]:
        """Return ALL roles the user qualifies for, ordered by priority."""
        self._load()
        roles: set[str] = set()

        # 1. Group-based roles (PRIMARY)
        if groups and provider:
            group_rules = self._config.get("group_rules", {}).get(provider, {})
            for g in groups:
                if g in group_rules:
                    roles.add(group_rules[g])

        # 2. Direct user override (case-insensitive lookup)
        users = self._config.get("users", {})
        email_lower = email.lower()
        # TOML preserves key case, so normalize both sides
        user_entry = next(
            (v for k, v in users.items() if k.lower() == email_lower), None
        )
        if user_entry is not None:
            if isinstance(user_entry, dict) and "role" in user_entry:
                roles.add(user_entry["role"])
            elif isinstance(user_entry, str):
                roles.add(user_entry)

        if not roles:
            default = self._config.get("defaults", {}).get("unknown_users", "none")
            return [default] if default != "none" else []

        # Return sorted by priority (highest first)
        return [r for r in self.ROLE_PRIORITY if r in roles]

    def get_agent_roles(self, agent_id: str, provider: str = "entra") -> list[str]:
        """Resolve a machine principal's roles from [agent_rules.<provider>].

        Deliberately separate from get_available_roles: an app id must never be
        usable as a group claim, nor a group guid as an app id.

        Fails closed. An unregistered agent gets no roles, and
        `defaults.unknown_users` does NOT apply — that fallback exists to give
        recognised humans in a tenant a baseline, and anyone can register an
        app in an Entra tenant. Extending it to agents would hand a role to
        every app id in the directory.
        """
        self._load()
        if not agent_id:
            return []

        # Entra app ids are RFC 4122 GUIDs — hex, and case-insensitive. Match
        # case-insensitively so an id pasted from the Portal in upper case does
        # not silently lock the agent out.
        agent_rules = self._config.get("agent_rules", {}).get(provider, {})
        agent_id_lower = agent_id.lower()
        role = next(
            (v for k, v in agent_rules.items() if k.lower() == agent_id_lower), None
        )
        if not role:
            return []
        if role not in self.ROLE_PRIORITY:
            logger.warning(
                "agent_rules.%s maps agent %s to unknown role '%s' — denying. "
                "Valid roles: %s",
                provider,
                agent_id,
                role,
                self.ROLE_PRIORITY,
            )
            return []
        return [role]

    def check_access(
        self, request: AccessRequest, allowed_roles: list[str]
    ) -> AccessDecision:
        """RBAC check: verify the assumed role is allowed for this tool.

        Identical for both principal types — what differs is where the role
        came from (groups for a human, app id for an agent), which the caller
        has already resolved. `allowed_roles` is the tool's requirement; the
        caller is responsible for having proved that `assumed_role` is one this
        principal actually holds.
        """
        role = request.assumed_role or "none"
        allowed = role in allowed_roles
        if allowed:
            return AccessDecision(allowed=True, role=role, reason="")

        # Name the agent in the denial: with machine callers there is no human
        # in the logs to correlate against, so the app id is the only handle an
        # operator has on which caller was refused.
        actor = (
            f"Agent '{request.agent_id}' with role '{role}'"
            if request.principal_type == "machine"
            else f"Role '{role}'"
        )
        reason = (
            f"{actor} cannot use '{request.tool_name}'. "
            f"Required: {allowed_roles}"
        )
        return AccessDecision(allowed=False, role=role, reason=reason)
