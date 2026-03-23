# Cedar ABAC: Requirements

## Scope

Cedar as the single runtime PDP (Policy Decision Point) for the entire agent system.

## Functional Requirements

### R1: Authorize All 12 MCP Tools

Cedar policies must cover all tools currently using `require_role()` plus the new `delete_s3_object`:

| Tool | Current Auth | Cedar Replaces |
|------|-------------|----------------|
| get_user_profile | `require_role("admin", "developer", "viewer")` | Cedar permit policy |
| list_files | `require_role("admin", "developer")` | Cedar permit policy |
| send_email | `require_role("admin")` | Cedar permit policy |
| delete_resource | `require_role("admin")` | Cedar permit policy |
| list_s3_buckets | `require_role("admin", "developer")` | Cedar permit policy |
| list_s3_objects | `require_role("admin", "developer")` | Cedar permit policy |
| get_s3_object_info | `require_role("admin", "developer", "viewer")` | Cedar permit policy |
| get_current_time | `require_role("admin")` | Cedar permit policy |
| convert_timezone | `require_role("admin")` | Cedar permit policy |
| get_time_difference | `require_role("admin")` | Cedar permit policy |
| **delete_s3_object** (NEW) | N/A | Cedar ABAC policy (archiver demo) |
| delete_resource (existing) | `require_role("admin")` | Cedar permit policy |

### R2: Support Both IdPs

- Entra ID (Microsoft) — groups from `groups` claim, email from `preferred_username`
- AWS Cognito — groups from `cognito:groups` claim, email from `email` claim
- Cedar sees a normalized `User` entity regardless of IdP source
- `principal.provider` attribute enables provider-specific policies if needed

### R3: ABAC Demo Scenario

**Use case**: Developer with `archiver` attribute can delete S3 objects in `archive/` folder only.

This requires:
- User attributes beyond role (archiver: true/false)
- Resource path context (which S3 prefix)
- Cannot be expressed with simple RBAC

### R4: Single PDP for A2A + MCP

- MCP server tool-level checks (role-to-tool mapping) → Cedar (**DONE**)
- A2A server role resolution + `/me` permissions matrix → Cedar (**DONE**)
- Eliminated duplicated `GROUP_TO_ROLE`, `TOOL_ROLES`, `ROLE_PRIORITY` between servers (**DONE**)
- A2A server agent-level group membership check → **stays in Python** (coarse entry filter — "can this user access the agent at all?" is a different question from "can this user call this tool?"). Moving to Cedar requires a new `access_agent` action in the schema — deferred to future iteration.

### R5: Custom JWT Claims as Attribute Source

- User attributes (archiver, department, etc.) come from JWT custom claims
- Entra: via app roles or optional claims configuration
- Cognito: via pre-token generation Lambda
- Attributes are extracted from token claims and set on the Cedar User entity

### R6: Policy-as-Code in Git

- Cedar policies stored as `.cedar` files in `cedar/policies/`
- Schema in `cedar/schema.cedarschema`
- Static entities in `cedar/entities.json`
- Validated in CI with `cedarpy.validate_policies()`

## Non-Functional Requirements

- **Performance**: Cedar evaluation is in-process (no network hop). Policies and entities loaded at startup, cached.
- **Backward compatibility**: Existing RBAC behavior must be preserved — same tools accessible to same roles.
- **Dev bypass**: Must still work with `dev_config.toml` auth bypass mode.
- **Hot reload**: Policy files should be reloadable without server restart (nice-to-have for POC).

## Out of Scope

- OPA / Rego
- OpenFGA / relationship graphs
- Database-backed policy store
- Permission Management API
- Agent/Service principal types (only User for now)
- AWS Verified Permissions (AVP)
