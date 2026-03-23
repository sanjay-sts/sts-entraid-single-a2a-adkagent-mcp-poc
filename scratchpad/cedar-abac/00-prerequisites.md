# Cedar ABAC: Prerequisites & Context

## Why Cedar for This Project

This is not an app — it's an AI agent system with headless agents, MCP servers exposing tools/skills, and an A2A gateway. Any caller (React frontend, CLI, another agent, a pipeline, another system) may invoke tools through the MCP server. The authorization model must work regardless of caller type.

### The Problem Today

Authorization logic **was** duplicated and scattered across the A2A and MCP layers. **All resolved by Cedar implementation:**

| Was Duplicated | Resolution |
|----------------|-----------|
| `GROUP_TO_ROLE` dict (A2A) vs `permissions.toml` (MCP) | Both use `CedarPolicyEvaluator` → `TomlPolicyEvaluator` |
| `TOOL_ROLES` dict (A2A) vs `require_role()` (MCP) | Both use Cedar policies in `cedar/policies/` |
| `ROLE_PRIORITY` in both servers | Lives only in `TomlPolicyEvaluator` now |
| `_detect_provider()` in both servers | Shared `detect_provider()` in `dev_config.py` |

Cedar is now the **single policy decision point** for both A2A and MCP servers.

### What Cedar Fixes

Cedar becomes a **single runtime PDP (Policy Decision Point)** that both A2A and MCP consult. Protocol auth stays where it is (FastMCP built-in for MCP, custom JWT validation for A2A). Cedar handles all business authorization decisions.

---

## Research Summary (ChatGPT + Claude Recommendations)

### Consensus: Cedar Over OPA for Runtime Authorization

Both ChatGPT and Claude independently recommended Cedar for this use case:

- **Cedar**: Embedded in-process via `cedarpy` (pip package). No sidecar. Readable policy language. Schema validation. Formal verification via `cedar-policy-cli`. AWS-backed (same engine as AWS Verified Permissions).
- **OPA**: Better suited for platform guardrails (K8s admission, service mesh, CI/CD) — not day-to-day tool authorization in a single system.

### Recommended Layered Architecture (2026)

```
Layer                    | Engine      | Purpose
-------------------------|-------------|--------------------------------------------
Identity / Transport     | Entra/Cognito + OAuth/OIDC | Protocol-level auth for MCP and A2A
Runtime Decision (PDP)   | Cedar       | Final allow/deny on agent/tool/skill actions
Relationship (future)    | OpenFGA     | Sharing, delegation, nested ownership
Platform Guardrails      | OPA         | K8s, mesh, CI/CD, infra compliance
```

**For this POC**: Only the first two layers. OpenFGA and OPA are deferred.

### Key Principles

1. **Protocol auth is separate from business authorization** — MCP's OAuth/JWT validation and A2A's token validation handle "is this caller authentic?" Cedar handles "is this action allowed?"
2. **IdPs authenticate, the app authorizes** — Entra and Cognito issue tokens with claims. Cedar evaluates those claims against policies. Don't let IdP groups/roles be the sole source of authorization truth.
3. **Normalize identity into one principal model** — Whether the caller authenticated via Entra or Cognito, Cedar sees one normalized principal with attributes.
4. **Don't duplicate policy logic across engines** — One policy store, one decision point. Eliminates the current duplication between A2A and MCP.
5. **Policy-as-code from day one** — Cedar policies in Git, validated in CI.

---

## Cedar Concepts for This Project

### Principal Types

| Type | Description | Example |
|------|-------------|---------|
| `User` | Human user authenticated via IdP | sanjay@company.com via Entra |
| `Agent` | AI agent acting on behalf of a user | ADK agent with delegated token |
| `Service` | System/pipeline calling MCP directly | CI pipeline with client credentials |

**POC scope**: Focus on `User` (human-via-agent path). `Agent` and `Service` principal types are future.

### Action Model

```
Action::"call_tool"          — invoke an MCP tool
Action::"list_tools"         — discover available tools
Action::"delegate_to_agent"  — (future) agent-to-agent delegation
Action::"read_memory"        — (future) access agent memory
```

### Resource Model

```
Tool::"get_user_profile"     — individual MCP tool
Tool::"delete_s3_object"     — the new ABAC demo tool
MCPServer::"identity-aware"  — the MCP server itself
S3Folder::"archive/"         — resource-level granularity
```

### Context Attributes

| Attribute | Source | Example |
|-----------|--------|---------|
| `principal.provider` | Token issuer claim | `"entra"`, `"cognito"` |
| `principal.role` | Resolved from groups via TOML | `"developer"` |
| `principal.groups` | Token group claims | `["platform-admins"]` |
| `principal.email` | Token email claim | `"sanjay@company.com"` |
| `principal.attributes` | Custom claims / policy store | `{ "archiver": true }` |
| `resource.sensitivity` | Tool/resource metadata | `"confidential"` |
| `resource.path` | S3 key prefix | `"archive/2024/"` |
| `context.environment` | Server config | `"dev"`, `"prod"` |

---

## POC Demo Scenario

**Use case**: A developer with the `archiver` attribute can delete S3 objects in the `archive/` folder. Regular developers cannot delete anything. Admins can delete anywhere.

This demonstrates ABAC beyond simple RBAC:
- Same role (`developer`) has **different permissions based on attributes**
- Access depends on **resource path** (not just tool name)
- Cannot be expressed with current `require_role()` — proves the need for Cedar

### Cedar Policy (conceptual)

```cedar
// Admins can delete any S3 object
permit(
  principal,
  action == Action::"call_tool",
  resource == Tool::"delete_s3_object"
) when {
  principal.role == "admin"
};

// Developers with archiver attribute can delete in archive/ only
permit(
  principal,
  action == Action::"call_tool",
  resource == Tool::"delete_s3_object"
) when {
  principal.role == "developer" &&
  principal has archiver &&
  principal.archiver == true &&
  context.resource_path like "archive/*"
};

// Hard guardrail: no one can delete in protected/ regardless of role
forbid(
  principal,
  action == Action::"call_tool",
  resource == Tool::"delete_s3_object"
) when {
  context.resource_path like "protected/*"
};
```

---

## Current Architecture (What Exists)

### Extension Point: PolicyEvaluator Interface

`mcp_server/policy.py` already defines a clean interface:

```python
class PolicyEvaluator(ABC):
    def get_available_roles(self, email, provider, groups) -> list[str]: ...
    def check_access(self, request: AccessRequest, allowed_roles: list[str]) -> AccessDecision: ...

@dataclass
class AccessRequest:
    email: str
    provider: str          # "entra", "cognito", "auth0"
    groups: list[str]
    tool_name: str
    claims: dict           # Full JWT claims (ABAC extensibility)
    assumed_role: str = ""

@dataclass
class AccessDecision:
    allowed: bool
    role: str
    reason: str
```

`TomlPolicyEvaluator` implements this for RBAC. `CedarPolicyEvaluator` will implement the same interface for ABAC.

### Auth Data Flow (Current)

```
Frontend (Bearer token + X-Assume-Role header)
  -> A2A Server (ContextVars: current_user_claims, current_access_token, current_assumed_role)
    -> ADK Agent (session state: user:access_token, user:role, user:email, user:groups)
      -> MCP Server (ContextVars: current_user_token, current_user_role, current_user_email, current_user_provider)
```

### Files Modified (Actual)

| File | Change |
|------|--------|
| `mcp_server/policy.py` | Added `CedarPolicyEvaluator` class + `AccessRequest.context` field |
| `mcp_server/server.py` | Replaced `require_role()` with `require_cedar()`, added `delete_s3_object` tool, added `cedar_check_with_context()` |
| `a2a_server/server.py` | Removed duplicated `GROUP_TO_ROLE`/`TOOL_ROLES`/`ROLE_PRIORITY`, uses shared `CedarPolicyEvaluator` |
| `dev_config.py` | Added shared `detect_provider()` function |
| `permissions.example.toml` | Added ABAC attribute source documentation |
| `requirements.txt` | Added `cedarpy>=4.0.0` |
| NEW: `cedar/schema.cedarschema` | Entity types: User, Role, Tool, S3Folder + actions |
| NEW: `cedar/entities.json` | Static entities: 3 roles + 11 tools |
| NEW: `cedar/policies/rbac.cedar` | RBAC permit policies for all tools |
| NEW: `cedar/policies/abac.cedar` | ABAC policy: archiver + archive/ path |
| NEW: `cedar/policies/guardrails.cedar` | Forbid: no delete in protected/ |
| NEW: `tests/test_cedar_smoke.py` | 28 Cedar tests (RBAC, ABAC, evaluator integration) |
| NEW: `scratchpad/cedar-abac/` | 4 documentation files (prerequisites, requirements, design, plan) |

---

## What We're NOT Doing (Deferred)

| Item | Why Deferred |
|------|-------------|
| OPA / Rego | Platform guardrails, not needed for single-system POC |
| OpenFGA | No sharing/delegation/relationship-graph needs yet |
| Permission Management API | Pairs with database-backed store (later) |
| Database-backed policies | TOML + Cedar files are sufficient for POC |
| Agent/Service principal types | Focus on human-via-agent path first |
| AWS Verified Permissions (AVP) | Use Cedar SDK directly to stay cloud-agnostic |
| OPAL | No need for real-time policy distribution in single-system POC |

---

## Dependencies

```
cedarpy          — Cedar policy evaluation engine (pip)
cedar-policy-cli — Policy validation and analysis (optional, for CI)
```

## References

- [Cedar Language Spec](https://docs.cedarpolicy.com/)
- [cedarpy on PyPI](https://pypi.org/project/cedarpy/)
- [Cedar Playground](https://www.cedarpolicy.com/en/playground)
- [FastMCP Auth Docs](https://gofastmcp.com/servers/auth/authentication)
- [MCP Authorization Spec](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
