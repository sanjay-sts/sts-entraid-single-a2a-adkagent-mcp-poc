"""Policy evaluator for tool access control.

Implements a PolicyEvaluator interface with two implementations:
  - TomlPolicyEvaluator: RBAC with group-to-role mapping (permissions.toml)
  - CedarPolicyEvaluator: ABAC using Cedar policies (cedar/ directory)

CedarPolicyEvaluator composes TomlPolicyEvaluator for role resolution
and uses cedarpy for policy evaluation. Cedar policies define which
roles/attributes can access which tools — replacing require_role() decorators.
"""

import json
import tomllib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from cedarpy import is_authorized

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
    context: dict = field(default_factory=dict)  # Cedar context (resource_path, environment)


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


class CedarPolicyEvaluator(PolicyEvaluator):
    """Cedar-based policy evaluator using cedarpy for in-process evaluation.

    Composes TomlPolicyEvaluator for role resolution (group-to-role mapping)
    and uses Cedar policies for access decisions. Cedar policies define which
    roles and attributes can access which tools — replacing require_role().
    """

    # ABAC attributes to extract from JWT claims into the Cedar User entity.
    # Add new custom claim names here as they are configured in IdPs.
    ABAC_CLAIM_KEYS = {
        "department": str,
        "archiver": bool,
    }

    def __init__(self, cedar_dir: Path, toml_evaluator: TomlPolicyEvaluator):
        self._cedar_dir = cedar_dir
        self._toml = toml_evaluator
        self._policies: str = ""
        self._entities: list = []
        self._policy_mtime: float = 0.0
        self._entities_mtime: float = 0.0
        self._load()

    def _load(self) -> None:
        """Load Cedar policies + static entities. Hot-reload on file change."""
        self._load_policies()
        self._load_entities()

    def _load_policies(self) -> None:
        """Concatenate all .cedar files from policies/ directory."""
        policies_dir = self._cedar_dir / "policies"
        if not policies_dir.exists():
            logger.warning("Cedar policies directory not found: %s", policies_dir)
            return

        # Check max mtime across all policy files
        cedar_files = sorted(policies_dir.glob("*.cedar"))
        if not cedar_files:
            logger.warning("No .cedar files found in %s", policies_dir)
            return

        max_mtime = max(f.stat().st_mtime for f in cedar_files)
        if max_mtime == self._policy_mtime:
            return  # No changes

        parts = []
        for f in cedar_files:
            parts.append(f.read_text(encoding="utf-8"))
        self._policies = "\n".join(parts)
        self._policy_mtime = max_mtime
        logger.info(
            "Cedar policies loaded: %d files from %s",
            len(cedar_files), policies_dir,
        )

    def _load_entities(self) -> None:
        """Load static entities (roles, tools) from entities.json."""
        entities_path = self._cedar_dir / "entities.json"
        if not entities_path.exists():
            logger.warning("Cedar entities not found: %s", entities_path)
            return

        mtime = entities_path.stat().st_mtime
        if mtime == self._entities_mtime:
            return  # No changes

        with open(entities_path, encoding="utf-8") as f:
            self._entities = json.load(f)
        self._entities_mtime = mtime
        logger.info(
            "Cedar entities loaded: %d entities from %s",
            len(self._entities), entities_path,
        )

    def _build_user_entity(
        self,
        email: str,
        provider: str,
        groups: list[str],
        roles: list[str],
        claims: dict,
    ) -> dict:
        """Build a Cedar User entity from JWT claims + resolved roles.

        The `parents` array connects the user to Role entities, enabling
        Cedar's `principal in Role::"admin"` checks.
        """
        attrs: dict = {
            "provider": provider,
            "email": email,
            "groups": groups,
        }

        # Extract ABAC attributes from JWT custom claims
        for claim_key, expected_type in self.ABAC_CLAIM_KEYS.items():
            if claim_key in claims:
                value = claims[claim_key]
                if isinstance(value, expected_type):
                    attrs[claim_key] = value

        return {
            "uid": {"__entity": {"type": "AgentAuth::User", "id": email}},
            "attrs": attrs,
            "parents": [
                {"__entity": {"type": "AgentAuth::Role", "id": role}}
                for role in roles
            ],
        }

    def get_available_roles(
        self, email: str, provider: str = "", groups: list[str] | None = None
    ) -> list[str]:
        """Delegate to TomlPolicyEvaluator — role resolution stays TOML-based."""
        return self._toml.get_available_roles(email, provider, groups)

    def check_access(
        self, request: AccessRequest, allowed_roles: list[str]
    ) -> AccessDecision:
        """Evaluate Cedar policies for access decision.

        The `allowed_roles` parameter is ignored — Cedar policies define
        which roles can access which tools. Kept for interface compatibility
        with TomlPolicyEvaluator.
        """
        self._load()  # Hot-reload if changed

        # Resolve roles for this user
        roles = self.get_available_roles(
            request.email, request.provider, request.groups
        )

        # Build dynamic user entity with role parents + ABAC attributes
        user_entity = self._build_user_entity(
            request.email,
            request.provider,
            request.groups,
            roles,
            request.claims,
        )

        # Merge static entities + dynamic user entity
        entities = self._entities + [user_entity]

        # Build Cedar authorization request
        cedar_request = {
            "principal": f'AgentAuth::User::"{request.email}"',
            "action": 'AgentAuth::Action::"call_tool"',
            "resource": f'AgentAuth::Tool::"{request.tool_name}"',
            "context": request.context,
        }

        result = is_authorized(
            request=cedar_request,
            policies=self._policies,
            entities=entities,
        )

        role = request.assumed_role or (roles[0] if roles else "none")
        if result.allowed:
            logger.info(
                "Cedar ALLOW: %s as %s → %s",
                request.email, role, request.tool_name,
            )
            return AccessDecision(allowed=True, role=role, reason="")
        else:
            reason = (
                f"Cedar denied: '{request.tool_name}' for "
                f"{request.email} as {role}"
            )
            logger.info("Cedar DENY: %s", reason)
            return AccessDecision(allowed=False, role=role, reason=reason)
