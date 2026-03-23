# MCP Multi-IdP: Implementation Plan

## Files Modified

| File | Change | Lines |
|------|--------|-------|
| `mcp_server/server.py` | Replace `TokenValidationMiddleware` with built-in auth + `UserContextMiddleware` | ~130 removed, ~80 added |
| `mcp_server/policy.py` (NEW) | PolicyEvaluator interface + TomlPolicyEvaluator | ~70 lines |
| `permissions.toml` (NEW, gitignored) | Agent-owned group-to-role mapping | ~25 lines |
| `permissions.example.toml` (NEW, committed) | Template | ~25 lines |
| `.gitignore` | Add `permissions.toml` | 1 line |

## Files NOT Modified

A2A server, ADK agent, frontend — adapt later.

---

## Step 1: Create Policy Evaluator (`mcp_server/policy.py`)

```python
"""Policy evaluator for tool access control.

Implements a PolicyEvaluator interface that can be swapped for OPA or Cedar later.
Current implementation: TOML-based RBAC with group-to-role mapping.

Future swap points:
  - OPA: Replace TomlPolicyEvaluator with OpaPolicyEvaluator that calls OPA sidecar
  - Cedar: Replace with CedarPolicyEvaluator using cedar-py embedded engine
  - The interface (check_access, get_available_roles) stays the same.
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
    provider: str          # "entra", "cognito", "auth0"
    groups: list[str]      # IdP group IDs/names from token claims
    tool_name: str         # The MCP tool being called
    claims: dict           # Full JWT claims (for ABAC extensibility)
    assumed_role: str = ""  # Role explicitly selected by user

@dataclass
class AccessDecision:
    """Result of a policy evaluation."""
    allowed: bool
    role: str              # Resolved role (for ContextVar/logging)
    reason: str            # Human-readable reason (for denial messages)


class PolicyEvaluator(ABC):
    """Interface for policy engines. Swap implementation for OPA/Cedar."""

    @abstractmethod
    def get_available_roles(self, email: str, provider: str, groups: list[str]) -> list[str]:
        """Return ALL roles the user qualifies for (from groups + user overrides)."""
        ...

    @abstractmethod
    def check_access(self, request: AccessRequest, allowed_roles: list[str]) -> AccessDecision:
        """Check if the user can access a tool. Full ABAC entry point."""
        ...


class TomlPolicyEvaluator(PolicyEvaluator):
    """TOML-based RBAC evaluator. Production swap: OPA or Cedar."""

    ROLE_PRIORITY = ["admin", "developer", "viewer"]

    def __init__(self, config_path: Path):
        self._config_path = config_path
        self._config = {}
        self._mtime = 0.0
        self._load()

    def _load(self):
        if self._config_path.exists():
            mtime = self._config_path.stat().st_mtime
            if mtime != self._mtime:
                with open(self._config_path, "rb") as f:
                    self._config = tomllib.load(f)
                self._mtime = mtime
                logger.info(f"Permissions reloaded from {self._config_path}")

    def get_available_roles(self, email: str, provider: str = "", groups: list[str] = None) -> list[str]:
        """Return ALL roles the user qualifies for, ordered by priority."""
        self._load()
        roles = set()

        # 1. Group-based roles (PRIMARY)
        if groups and provider:
            group_rules = self._config.get("group_rules", {}).get(provider, {})
            for g in groups:
                if g in group_rules:
                    roles.add(group_rules[g])

        # 2. Direct user override
        users = self._config.get("users", {})
        if email.lower() in users:
            roles.add(users[email.lower()].get("role", "none"))

        if not roles:
            default = self._config.get("defaults", {}).get("unknown_users", "none")
            return [default] if default != "none" else []

        # Return sorted by priority (highest first)
        return [r for r in self.ROLE_PRIORITY if r in roles]

    def check_access(self, request: AccessRequest, allowed_roles: list[str]) -> AccessDecision:
        """RBAC check: verify assumed role is allowed for this tool."""
        role = getattr(request, "assumed_role", "none")
        allowed = role in allowed_roles
        reason = "" if allowed else (
            f"Role '{role}' cannot use '{request.tool_name}'. "
            f"Required: {allowed_roles}"
        )
        return AccessDecision(allowed=allowed, role=role, reason=reason)
```

---

## Step 2: Create Permission Config (`permissions.toml`)

```toml
# permissions.toml — Agent-owned role assignments
# Groups-to-role mapping is the PRIMARY mechanism.
# User-level overrides are optional (for exceptions).

# PRIMARY: Map IdP group claims to roles (managed by agent, not IdP)
[group_rules.entra]
# Entra ID security group GUIDs → role
# "72460602-5251-4f2e-a4f2-611476cc984c" = "admin"
# "4baa4106-f6bf-4a10-9324-39f487b3eb6d" = "developer"
# "cde4fa16-7717-44e5-a502-ce2a17ef4385" = "viewer"

[group_rules.cognito]
# Cognito group names → role (for future use)
# "platform-admins" = "admin"
# "developers" = "developer"

[group_rules.auth0]
# Auth0 roles/groups → role (for future use)
# "admin" = "admin"

# OPTIONAL: Direct user overrides (for exceptions — e.g., demoting a user)
[users]
# "sanjay@company.com" = { role = "admin" }

[defaults]
# Role for authenticated users not matched by group rules or user overrides
unknown_users = "none"
```

---

## Step 3: Replace TokenValidationMiddleware with FastMCP Built-in Auth

**Delete** from `mcp_server/server.py`:
- `JWKS_URIS` list (5 lines)
- `VALID_ISSUERS` list (4 lines)
- `GROUP_TO_ROLE` dict (5 lines)
- `_jwks_cache` + `get_jwks()` (10 lines)
- `get_all_keys()` (13 lines)
- `TokenValidationMiddleware` class (80 lines)
- `require_scopes_from_token()` function (10 lines)
- `current_user_scopes` ContextVar (1 line)

**Add** to `mcp_server/server.py`:

```python
from fastmcp.server.auth import MultiAuth, RemoteAuthProvider
from fastmcp.server.auth.providers.azure import AzureJWTVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl
from mcp_server.policy import TomlPolicyEvaluator, PolicyEvaluator

def _build_auth():
    """Configure trusted IdP verifiers. Only tokens from these providers are accepted."""
    if is_auth_disabled("mcp"):
        return None

    verifiers = []

    if TENANT_ID and CLIENT_ID:
        verifiers.append(AzureJWTVerifier(
            client_id=CLIENT_ID,
            tenant_id=TENANT_ID,
            required_scopes=["access_as_user"],
        ))

    # Future: Add more verifiers for other IdPs
    # verifiers.append(JWTVerifier(
    #     jwks_uri="https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json",
    #     issuer="https://cognito-idp.{region}.amazonaws.com/{pool_id}",
    #     audience="your-cognito-client-id",
    # ))

    if not verifiers:
        logger.warning("No auth providers configured!")
        return None

    if len(verifiers) == 1:
        return RemoteAuthProvider(
            token_verifier=verifiers[0],
            authorization_servers=[AnyHttpUrl(f"https://login.microsoftonline.com/{TENANT_ID}/v2.0")],
            base_url=f"http://localhost:{os.getenv('MCP_SERVER_PORT', 10002)}",
        )

    return MultiAuth(
        verifiers=verifiers,
        base_url=f"http://localhost:{os.getenv('MCP_SERVER_PORT', 10002)}",
    )

mcp = FastMCP(name="Identity-Aware MCP Server", auth=_build_auth())
```

---

## Step 4: Add UserContextMiddleware

```python
# Keep only these ContextVars (remove current_user_scopes):
current_user_token: ContextVar[str] = ContextVar("current_user_token", default="")
current_user_role: ContextVar[str] = ContextVar("current_user_role", default="none")
current_user_email: ContextVar[str] = ContextVar("current_user_email", default="")

EMAIL_CLAIMS = {
    "entra": ["preferred_username", "unique_name", "upn", "email"],
    "cognito": ["email"],
    "auth0": ["email"],
    "default": ["email", "preferred_username", "sub"],
}

def _detect_provider(claims: dict) -> str:
    iss = claims.get("iss", "")
    if "login.microsoftonline.com" in iss or "sts.windows.net" in iss:
        return "entra"
    if "cognito-idp" in iss:
        return "cognito"
    if "auth0.com" in iss:
        return "auth0"
    return "default"

def _extract_email(claims: dict, provider: str) -> str:
    for claim_name in EMAIL_CLAIMS.get(provider, EMAIL_CLAIMS["default"]):
        if claim_name in claims:
            return claims[claim_name]
    return claims.get("sub", "")

def _extract_groups(claims: dict) -> list[str]:
    """Extract groups, handling Entra ID group overage (>150 groups)."""
    if "groups" in claims:
        return claims["groups"]
    claim_names = claims.get("_claim_names", {})
    if "groups" in claim_names:
        logger.warning("Group overage detected — falling back to user-level assignment")
        return []
    return []

class UserContextMiddleware(Middleware):
    """Resolves available roles, enforces role selection, sets ContextVars."""

    def __init__(self, policy_evaluator: PolicyEvaluator):
        self.policy_evaluator = policy_evaluator

    async def on_call_tool(self, context, call_next):
        if is_auth_disabled("mcp"):
            self._set_bypass_context()
            return await call_next(context)

        token = get_access_token()
        if token and token.claims:
            provider = _detect_provider(token.claims)
            email = _extract_email(token.claims, provider)
            groups = _extract_groups(token.claims)

            available_roles = self.policy_evaluator.get_available_roles(email, provider, groups)

            headers = get_http_headers()
            assumed_role = headers.get("x-assume-role", "")

            if not assumed_role:
                if not available_roles:
                    raise ToolError(
                        f"[TOOL_DENIAL] No roles available for {email}. "
                        f"Contact admin to assign group membership."
                    )
                raise ToolError(
                    f"[ROLE_SELECTION] Role selection required. "
                    f"Set X-Assume-Role header to one of: {available_roles}"
                )

            if assumed_role not in available_roles:
                raise ToolError(
                    f"[TOOL_DENIAL] Cannot assume role '{assumed_role}'. "
                    f"Available roles: {available_roles}"
                )

            current_user_token.set(token.token)
            current_user_email.set(email)
            current_user_role.set(assumed_role)
            logger.info(f"User {email} assumed role '{assumed_role}' (available: {available_roles})")

        return await call_next(context)

    def _set_bypass_context(self):
        dev_cfg = get_section("mcp")
        current_user_token.set("dev-bypass-token")
        current_user_role.set(dev_cfg.get("default_role", "admin"))
        current_user_email.set(dev_cfg.get("default_email", "dev@localhost"))

policy_evaluator = TomlPolicyEvaluator(Path(__file__).parent.parent / "permissions.toml")
mcp.add_middleware(UserContextMiddleware(policy_evaluator))
```

---

## Step 5: Update Tool Decorators

Remove `require_scopes_from_token` from all `auth=` lists:

```python
# Before:
@mcp.tool(auth=[require_role("admin", "developer", "viewer"), require_scopes_from_token("User.Read")])
# After:
@mcp.tool(auth=require_role("admin", "developer", "viewer"))

# Before:
@mcp.tool(auth=[require_role("admin", "developer"), require_scopes_from_token("Files.Read")])
# After:
@mcp.tool(auth=require_role("admin", "developer"))

# Before:
@mcp.tool(auth=[require_role("admin"), require_scopes_from_token("Mail.Send")])
# After:
@mcp.tool(auth=require_role("admin"))

# Before:
@mcp.tool(auth=[require_role("admin"), require_scopes_from_token("Files.ReadWrite.All")])
# After:
@mcp.tool(auth=require_role("admin"))

# Time tools — already correct (role-only):
@mcp.tool(auth=require_role("admin"))
```

Tool function bodies unchanged — they still read from ContextVars.
