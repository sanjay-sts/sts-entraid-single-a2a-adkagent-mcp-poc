# Cedar ABAC: Design

## Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   A2A Server    │     │   MCP Server    │     │   cedar/        │
│   (Gateway)     │     │   (Tools)       │     │   (Policy Store)│
│                 │     │                 │     │                 │
│  auth_middleware │──┐  │ UserContext     │──┐  │ schema.cedar    │
│  (protocol auth)│  │  │ Middleware      │  │  │ entities.json   │
│                 │  │  │ (protocol auth) │  │  │ policies/*.cedar│
│  Cedar PDP ─────┼──┘  │ Cedar PDP ─────┼──┘  │                 │
│  (agent-level)  │     │ (tool-level)   │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                       │                       │
         └───────────────────────┴───────────────────────┘
                    CedarPolicyEvaluator
                    (shared Python module)
```

Protocol auth (JWT validation) stays in each server. Business authorization moves to Cedar.

## cedarpy API

```python
from cedarpy import is_authorized, validate_policies, Decision

# Authorization check
result = is_authorized(
    request={
        "principal": 'AgentAuth::User::"sanjay@company.com"',
        "action": 'AgentAuth::Action::"call_tool"',
        "resource": 'AgentAuth::Tool::"delete_s3_object"',
        "context": {"resource_path": "archive/2024/report.csv"},
    },
    policies=policy_text,     # All .cedar files concatenated
    entities=entities_json,   # Static entities + dynamic user entity
)
# result.allowed → True/False
# result.decision → Decision.Allow / Decision.Deny

# Schema validation
validation = validate_policies(policy_text, schema_text)
# validation.validation_passed → True/False
# validation.errors → list of error strings
```

## Cedar Schema Design

### Namespace: `AgentAuth`

All types scoped under `AgentAuth` to avoid collisions in multi-agent/multi-MCP future.

### Entity Types

```cedar
namespace AgentAuth {

  // Roles — User membership via "in [Role]"
  entity Role;

  // User — human authenticated via Entra/Cognito
  // "in [Role]" means a User can be a member of Role entities
  entity User in [Role] {
    provider: String,        // "entra", "cognito"
    email: String,
    groups: Set<String>,     // IdP group IDs/names from token
    department?: String,     // custom JWT claim
    archiver?: Bool,         // custom JWT claim — ABAC attribute
  };

  // Tool — MCP tool being authorized
  entity Tool {
    sensitivity?: String,    // "public", "internal", "confidential"
    requires_provider?: String,  // "entra" for Graph tools
  };

  // S3Folder — sub-resource for path-based ABAC
  entity S3Folder;

  // Actions
  action call_tool appliesTo {
    principal: [User],
    resource: [Tool],
    context: {
      resource_path?: String,
      environment?: String,
    },
  };

  action list_tools appliesTo {
    principal: [User],
    resource: [Tool],
  };

} // end namespace
```

### Why These Choices

**`User in [Role]`**: Cedar's entity hierarchy models role membership. When a User entity has `parents: [Role::"admin"]`, policies can check `principal in AgentAuth::Role::"admin"`. This replaces the Python `require_role()` pattern.

**Tool attributes**: `sensitivity` and `requires_provider` enable policies like "only Entra users can use Graph tools" or "confidential tools require admin" — without hardcoding tool names in policies.

**Context vs Entity attributes**: Entity attributes are stable (user's email, tool's sensitivity). Context is per-request (the S3 path being accessed, the environment). This separation is a Cedar best practice.

**Optional attributes (`?`)**: `department`, `archiver` are optional because not all users will have custom claims configured. Cedar's `has` operator checks for existence: `principal has archiver && principal.archiver == true`.

## Entity Model

### Static Entities (loaded at startup from `cedar/entities.json`)

**Roles** (3):
```json
{"uid": {"__entity": {"type": "AgentAuth::Role", "id": "admin"}}, "attrs": {}, "parents": []}
{"uid": {"__entity": {"type": "AgentAuth::Role", "id": "developer"}}, "attrs": {}, "parents": []}
{"uid": {"__entity": {"type": "AgentAuth::Role", "id": "viewer"}}, "attrs": {}, "parents": []}
```

**Tools** (12 — includes new delete_s3_object):
```json
{"uid": {"__entity": {"type": "AgentAuth::Tool", "id": "get_user_profile"}},
 "attrs": {"sensitivity": "internal", "requires_provider": "entra"}, "parents": []}
```

### Dynamic Entities (built at runtime per request)

**User entity** — constructed from JWT claims:

```python
def _build_user_entity(email, provider, groups, roles, claims):
    return {
        "uid": {"__entity": {"type": "AgentAuth::User", "id": email}},
        "attrs": {
            "provider": provider,
            "email": email,
            "groups": groups,
            # Custom claims (ABAC attributes)
            "department": claims.get("department", ""),
            "archiver": claims.get("archiver", False),
        },
        "parents": [
            {"__entity": {"type": "AgentAuth::Role", "id": role}}
            for role in roles
        ],
    }
```

The `parents` array connects the user to their roles. `roles` comes from `TomlPolicyEvaluator.get_available_roles()` — the existing TOML-based group-to-role resolution stays. Cedar doesn't replace role resolution, it consumes the result.

## Integration with PolicyEvaluator Interface

```python
# mcp_server/policy.py (existing interface)
class PolicyEvaluator(ABC):
    def get_available_roles(self, email, provider, groups) -> list[str]: ...
    def check_access(self, request: AccessRequest, allowed_roles: list[str]) -> AccessDecision: ...
```

`CedarPolicyEvaluator` (implemented in `mcp_server/policy.py`):
- **Composes** `TomlPolicyEvaluator` for `get_available_roles()` — role resolution stays TOML-based
- **Replaces** `check_access()` with Cedar `is_authorized()` call
- `allowed_roles` parameter is **ignored** — Cedar policies define tool-to-role mapping
- `AccessRequest` extended with `context: dict` field for Cedar context (resource_path, environment)
- ABAC attributes extracted from JWT claims via `ABAC_CLAIM_KEYS` mapping
- Hot-reloads `.cedar` files and `entities.json` on file change (mtime-based)

### Key Design: Composition over Inheritance

```python
class CedarPolicyEvaluator(PolicyEvaluator):
    def __init__(self, cedar_dir: Path, toml_evaluator: TomlPolicyEvaluator):
        self._toml = toml_evaluator  # Delegates role resolution
        # ... loads cedar policies + entities

    def get_available_roles(self, email, provider, groups):
        return self._toml.get_available_roles(email, provider, groups)

    def check_access(self, request, allowed_roles):
        # 1. Resolve roles via TOML
        # 2. Build Cedar User entity with role parents + ABAC attrs
        # 3. Call cedarpy.is_authorized()
        # 4. Return AccessDecision
```

## How User Attributes Flow

```
JWT Token (Entra/Cognito)
  │
  ├── Standard claims: iss, sub, email, groups
  ├── Custom claims: department, archiver (from IdP config)
  │
  ▼
Token Validation (protocol auth — unchanged)
  │
  ▼
Principal Normalization (new)
  ├── _detect_provider() → provider
  ├── _extract_email() → email
  ├── _extract_groups() → groups
  ├── get_available_roles() → roles (TOML)
  ├── Extract custom claims → archiver, department
  │
  ▼
Build Cedar User Entity
  ├── uid: AgentAuth::User::"email"
  ├── attrs: {provider, email, groups, department, archiver}
  ├── parents: [Role::"admin", Role::"developer", ...]
  │
  ▼
Cedar is_authorized(user_entity + static_entities, policies, request)
  │
  ▼
AccessDecision (allowed/denied + reason)
```

## Policy Storage

```
cedar/
├── schema.cedarschema        # Entity type definitions
├── entities.json             # Static entities (roles, tools)
└── policies/
    ├── rbac.cedar            # Role-based policies (replaces require_role)
    ├── abac.cedar            # Attribute-based policies (archiver demo)
    └── guardrails.cedar      # Forbid policies (hard safety limits)
```

All `.cedar` files in `policies/` are concatenated and passed to `is_authorized()`. Cedar evaluates all policies together — if any `forbid` matches, access is denied regardless of `permit` policies.

## Two-Phase Authorization Pattern

Cedar policies need different data for RBAC vs ABAC:

```
Phase 1 (auth callable — require_cedar):
  ┌─────────────────────────────────────────────────────────┐
  │ Cedar check WITHOUT context                             │
  │ Question: "Can this role call this tool?"               │
  │ Data: email, provider, groups, role, tool_name          │
  │ Runs for: ALL 12 tools                                  │
  └─────────────────────────────────────────────────────────┘

Phase 2 (inside tool — cedar_check_with_context):
  ┌─────────────────────────────────────────────────────────┐
  │ Cedar check WITH context (resource_path, environment)   │
  │ Question: "Can this user do this specific operation?"   │
  │ Data: everything from Phase 1 + context dict            │
  │ Runs for: ABAC tools only (delete_s3_object)            │
  └─────────────────────────────────────────────────────────┘
```

For RBAC-only tools, Phase 1 is sufficient. For `delete_s3_object`, both phases run:
- Phase 1: Admin passes (blanket permit). Developer without archiver is denied.
- Phase 2: Developer with archiver passes only if `resource_path` starts with `archive/`.
  Admin passes unless path starts with `protected/` (forbid guardrail).

### ContextVars Added for Cedar

```python
current_user_groups: ContextVar[list]   # IdP groups from token
current_user_claims: ContextVar[dict]   # Full JWT claims (for ABAC attributes)
```

These are set in `UserContextMiddleware._resolve_context()` alongside existing ContextVars,
so `require_cedar()` and `cedar_check_with_context()` can build Cedar `AccessRequest`s.
