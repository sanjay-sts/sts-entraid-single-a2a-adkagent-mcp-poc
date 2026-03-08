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

    def check_access(
        self, request: AccessRequest, allowed_roles: list[str]
    ) -> AccessDecision:
        """RBAC check: verify assumed role is allowed for this tool."""
        role = request.assumed_role or "none"
        allowed = role in allowed_roles
        reason = (
            ""
            if allowed
            else (
                f"Role '{role}' cannot use '{request.tool_name}'. "
                f"Required: {allowed_roles}"
            )
        )
        return AccessDecision(allowed=allowed, role=role, reason=reason)
