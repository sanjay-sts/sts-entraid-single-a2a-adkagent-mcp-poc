# Cedar ABAC: Implementation Plan

## Overview

7 items in dependency order. Each item is planned, implemented, and verified before moving to the next.

## Item 1: Cedar Schema + Entity Model --- DONE

**Deliverables:**
- `cedar/schema.cedarschema` — entity types, actions, attributes
- `cedar/entities.json` — static role + tool entities
- `cedar/policies/` — empty directory (populated in item 2)
- Smoke test verifying cedarpy loads schema + entities

**Files created:**
- `cedar/schema.cedarschema`
- `cedar/entities.json`
- `tests/test_cedar_smoke.py`

**Depends on:** Nothing (foundation)

---

## Item 2: Cedar Policies --- DONE

**Deliverables:**
- `cedar/policies/rbac.cedar` — role-based permit policies for all 11 existing tools (replaces `require_role()`)
- `cedar/policies/abac.cedar` — attribute-based policies for `delete_s3_object` (archiver demo)
- `cedar/policies/guardrails.cedar` — forbid policies (e.g., no delete in `protected/`)

**Tests:** 9 file-based policy tests passing (TestCedarFilePolicies)

---

## Item 3: CedarPolicyEvaluator --- DONE

**Deliverables:**
- `CedarPolicyEvaluator` class in `mcp_server/policy.py`
- Composes `TomlPolicyEvaluator` for role resolution
- Loads `.cedar` files + `entities.json` at startup with hot-reload
- Builds dynamic User entity from JWT claims (ABAC attributes: archiver, department)
- Calls `cedarpy.is_authorized()` in `check_access()`
- `AccessRequest` extended with `context: dict` field for Cedar context

**Tests:** 11 CedarPolicyEvaluator tests passing (TestCedarPolicyEvaluator)

---

## Item 4: delete_s3_object MCP Tool

**Deliverables:**
- New `delete_s3_object` tool in MCP server
- Uses `_run_s3_operation()` existing helper
- Auth via Cedar (not `require_role()`)
- Passes `resource_path` context to Cedar for path-based ABAC

**Files modified:**
- `mcp_server/server.py` — add tool definition

**Depends on:** Item 3 (CedarPolicyEvaluator must be wired in)

---

## Item 5: MCP Server Migration

**Deliverables:**
- Replace `require_role()` auth callables with Cedar evaluation
- `UserContextMiddleware` calls `CedarPolicyEvaluator.check_access()` instead of just setting ContextVars
- All 12 tools authorized via Cedar
- Remove `require_role()` function (or keep as fallback)

**Files modified:**
- `mcp_server/server.py` — swap `policy_evaluator` to `CedarPolicyEvaluator`, update middleware + tool auth

**Depends on:** Items 3 + 4

---

## Item 6: A2A Server Migration

**Deliverables:**
- A2A auth middleware calls Cedar for agent-level access decisions
- Remove duplicated `GROUP_TO_ROLE`, `TOOL_ROLES`, `ROLE_PRIORITY`
- A2A server imports shared `CedarPolicyEvaluator`
- `/me` endpoint reads from Cedar evaluator instead of local dicts

**Files modified:**
- `a2a_server/server.py` — replace hardcoded auth logic with Cedar calls

**Depends on:** Item 5 (Cedar evaluator proven in MCP first)

---

## Item 7: Tests

**Deliverables:**
- Update `tests/test_access_control.py` with Cedar-based scenarios
- Add ABAC-specific tests (archiver attribute, path-based access)
- Add Cedar policy validation tests
- Verify backward compatibility (same roles, same tool access)

**Files modified:**
- `tests/test_access_control.py`
- `tests/conftest.py` (add Cedar fixtures if needed)

**Depends on:** Items 5 + 6

---

## Dependency Graph

```
Item 1 (Schema + Entities)
  └── Item 2 (Policies)
       └── Item 3 (CedarPolicyEvaluator)
            ├── Item 4 (delete_s3_object tool)
            │    └── Item 5 (MCP Migration)
            │         └── Item 6 (A2A Migration)
            │              └── Item 7 (Tests)
            └── Item 5 (MCP Migration)
```

## Dependencies to Install

```
cedarpy  — Cedar policy evaluation engine
```

Add to `requirements.txt`. Install via `uv pip install cedarpy`.
