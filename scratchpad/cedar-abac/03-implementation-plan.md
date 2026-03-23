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

## Item 4: delete_s3_object MCP Tool --- DONE

**Deliverables:**
- New `delete_s3_object` tool with two-phase Cedar authorization
- Phase 1: `require_cedar("delete_s3_object")` auth callable (RBAC)
- Phase 2: `cedar_check_with_context()` inside tool with `resource_path` (ABAC)
- Uses existing `_run_s3_operation()` helper

---

## Item 5: MCP Server Migration --- DONE

**Deliverables:**
- All 11 tools use `auth=require_cedar("tool_name")` (replaced `require_role()`)
- `require_role()` function removed entirely
- `CedarPolicyEvaluator` is the active policy evaluator (composes `TomlPolicyEvaluator`)
- Added `current_user_groups` and `current_user_claims` ContextVars
- Added `cedar_check_with_context()` helper for ABAC tools
- `UserContextMiddleware` type hint generalized for any `PolicyEvaluator`

**28 Cedar tests passing**

---

## Item 6: A2A Server Migration --- DONE

**Deliverables:**
- Removed duplicated `GROUP_TO_ROLE`, `TOOL_ROLES`, `ROLE_PRIORITY`, `_get_available_roles()`, `_determine_role()`
- A2A server imports shared `CedarPolicyEvaluator` from `mcp_server/policy.py`
- `/me` endpoint uses `cedar_evaluator.get_available_roles()` for role resolution
- `/me` endpoint builds permissions matrix via Cedar `check_access()` for each tool
- Agent-level group check in auth middleware stays (coarse entry filter)
- `TOOL_SCOPES` kept (informational, not authorization) — added `delete_s3_object`

---

## Item 7: Tests --- DONE

**28 Cedar tests passing** covering:
- Inline RBAC policies (5 tests)
- Inline ABAC policies (5 tests)
- File-based policies (9 tests)
- CedarPolicyEvaluator integration (11 tests)

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

## Dependencies

```
cedarpy>=4.0.0  — Cedar policy evaluation engine (added to requirements.txt)
```

## Post-Implementation Simplification

Code review identified and fixed 9 issues:

1. **`allowed_roles` made optional** (`None` default) — no more `[]` dummy values at call sites
2. **Extracted `_build_access_request()` helper** — eliminated duplicated ContextVar reads
3. **Added `check_access_batch()`** using `is_authorized_batch()` — `/me` reduced from 11 individual evals to 1 batch
4. **ALLOW log level → DEBUG** — only DENY logged at INFO
5. **`PolicyEvaluator` type annotation** on middleware `__init__`
6. **`ContextVar[list[str]]`** — proper generic type
7. **Removed dead tombstone comments** (`# _detect_provider removed`)
8. **Removed `group_names = group_roles` alias**
9. **Path constants** (`PERMISSIONS_PATH`, `CEDAR_DIR`) moved to shared `dev_config.py`
10. **Tool count corrected** — 11 tools, not 12 (was miscounted in all docs)
