# Cedar ABAC: Testing Strategy

**Date**: 2026-03-26
**Cedar Engine**: cedarpy >= 4.0.0
**Test File**: `tests/test_cedar_smoke.py`
**Prerequisite**: Cedar ABAC integration (Items 1-7 in `03-implementation-plan.md`) --- DONE

Companion to `05-frontend-testing-strategy.md` (frontend ABAC scenarios).

---

## Test Users

### Entra ID (RBAC testing)

| User | Email | Entra Group | Group GUID | Role |
|------|-------|-------------|------------|------|
| Adele Vance | AdeleV@2tdgcb.onmicrosoft.com | AI-Agent-Admins | f1c467f2-954d-4e9d-8949-53a3492b0c14 | admin |
| Diego Siciliani | DiegoS@2tdgcb.onmicrosoft.com | AI-Agent-Developers | c6097742-e961-405f-9a45-2ca9fc971bd7 | developer |
| Johanna Lorenz | JohannaL@2tdgcb.onmicrosoft.com | AI-Agent-Viewers | a0cd9a0a-da7e-457c-8ca2-237529bb130f | viewer |

### Cognito (ABAC testing)

| User | Email | Cognito Group | custom:archiver | Role |
|------|-------|---------------|-----------------|------|
| archiver | archiver@test.com | platform-developers | true | developer |
| (regular dev) | - | platform-developers | (none) | developer |

---

## Tool Permission Matrix (Cedar RBAC)

| Tool | admin | developer | viewer | Notes |
|------|-------|-----------|--------|-------|
| get_user_profile | Y | Y | Y | Graph OBO fallback |
| list_files | Y | Y | N | Graph OBO required |
| send_email | Y | N | N | Graph OBO required |
| delete_resource | Y | N | N | Simulated |
| get_current_time | Y | N | N | No external API |
| convert_timezone | Y | N | N | No external API |
| get_time_difference | Y | N | N | No external API |
| list_s3_buckets | Y | Y | N | Server-side AWS |
| list_s3_objects | Y | Y | N | Server-side AWS |
| get_s3_object_info | Y | Y | Y | Server-side AWS |
| delete_s3_object | Y* | ABAC** | N | Two-phase Cedar |

\* Admin denied in `protected/*` (guardrail forbid)
\** Developer requires `archiver=true` attribute AND `archive/*` path

---

## ABAC delete_s3_object Decision Matrix

| Role | archiver | Path | Phase 1 | Phase 2 | Final | Cedar Policy |
|------|----------|------|---------|---------|-------|--------------|
| admin | n/a | archive/* | ALLOW (rbac) | ALLOW | **ALLOW** | rbac.cedar blanket |
| admin | n/a | data/* | ALLOW (rbac) | ALLOW | **ALLOW** | rbac.cedar blanket |
| admin | n/a | protected/* | ALLOW (rbac) | FORBID | **DENY** | guardrails.cedar |
| developer | true | archive/* | PASSTHROUGH | ALLOW | **ALLOW** | abac.cedar |
| developer | true | data/* | PASSTHROUGH | DENY | **DENY** | abac.cedar (wrong path) |
| developer | true | protected/* | PASSTHROUGH | FORBID | **DENY** | guardrails.cedar |
| developer | false | archive/* | PASSTHROUGH | DENY | **DENY** | abac.cedar (no attr) |
| viewer | n/a | any | DENY | - | **DENY** | rbac.cedar (no permit) |

---

## Test Suite A: Cedar RBAC Smoke Tests (Inline Policies)

**Test class:** `TestCedarSmoke` (5 tests)

Tests basic Cedar authorization with inline policies (not file-based):

```
A1: Admin can call any tool → ALLOW
A2: Viewer denied send_email → DENY
A3: Developer can call list_files → ALLOW
A4: Viewer can call get_user_profile → ALLOW
A5: No role → DENY
```

**Run:** `uv run pytest tests/test_cedar_smoke.py::TestCedarSmoke -v`

---

## Test Suite B: Cedar ABAC Inline Tests

**Test class:** `TestCedarABAC` (5 tests)

Tests ABAC policies with inline policies and archiver attribute:

```
B1: Admin can delete anywhere → ALLOW
B2: Developer with archiver=true can delete in archive/ → ALLOW
B3: Developer with archiver=true denied outside archive/ → DENY
B4: Developer without archiver denied in archive/ → DENY
B5: Forbid overrides admin in protected/ → DENY
```

**Run:** `uv run pytest tests/test_cedar_smoke.py::TestCedarABAC -v`

---

## Test Suite C: File-Based Policy Tests

**Test class:** `TestCedarFilePolicies` (9 tests)

Tests actual `.cedar` files from `cedar/policies/`:

```
C1: Admin send_email → ALLOW (rbac.cedar)
C2: Developer send_email → DENY (rbac.cedar)
C3: Viewer get_s3_object_info → ALLOW (rbac.cedar)
C4: Viewer list_s3_buckets → DENY (rbac.cedar)
C5: Archiver delete in archive/ → ALLOW (abac.cedar)
C6: Archiver delete outside archive/ → DENY (abac.cedar)
C7: Admin delete in protected/ → DENY (guardrails.cedar)
C8: list_tools allowed for any user → ALLOW (rbac.cedar)
C9: (additional file policy test)
```

**Run:** `uv run pytest tests/test_cedar_smoke.py::TestCedarFilePolicies -v`

---

## Test Suite D: CedarPolicyEvaluator Integration

**Test class:** `TestCedarPolicyEvaluator` (12 tests)

Tests the full evaluator including TOML role resolution + Cedar authorization:

```
D1: Admin allowed → ALLOW
D2: Viewer denied admin tool → DENY
D3: Developer allowed list_files → ALLOW
D4: Archiver delete in archive/ → ALLOW
D5: Archiver delete wrong path → DENY
D6: Developer without archiver denied → DENY
D7: Protected forbid overrides admin → DENY
D8: get_available_roles delegates to TOML → roles list
D9: Cognito user works → ALLOW
D10: User override from TOML → role
D11: Assumed role enforced (check_access) → DENY if wrong role
D12: Assumed role enforced (batch) → DENY if wrong role
D13: Assumed admin still works → ALLOW
```

**Run:** `uv run pytest tests/test_cedar_smoke.py::TestCedarPolicyEvaluator -v`

---

## Test Suite E: Phase 1 Passthrough Verification

Verified via `TestCedarPolicyEvaluator` tests D4-D6. The passthrough logic in `require_cedar()` is code-level (not Cedar policy), tested indirectly through:
- D4: Developer+archiver+archive/ → Phase 1 passthrough → Phase 2 ALLOW
- D5: Developer+archiver+wrong path → Phase 1 passthrough → Phase 2 DENY
- D6: Developer without archiver → Phase 1 passthrough → Phase 2 DENY

**Direct unit test for passthrough:** The `_ABAC_PHASE1_PASSTHROUGH` dict is exercised when `check_access()` is called with `assumed_role="developer"` and `tool_name="delete_s3_object"`.

---

## Test Suite F: Auth Bypass Mode

Manual verification (not automated):

```
F1: Set dev_config.toml: disable_auth=true, default_role=developer, default_archiver=true
    → Start MCP server → Call delete_s3_object with archive/ path → ALLOW

F2: Set dev_config.toml: disable_auth=true, default_role=developer (no default_archiver)
    → Start MCP server → Call delete_s3_object → DENY

F3: Set X-Abac-Attrs: {"archiver": true} header (override config)
    → ALLOW even without default_archiver in config
```

---

## Expected Denial Messages

| Scenario | Error Pattern | Source |
|----------|--------------|--------|
| Viewer calls delete_s3_object | `[TOOL_DENIAL] Access denied: Cedar denied: ...` | Phase 1 `require_cedar()` |
| Developer (no archiver) delete | `[TOOL_DENIAL] Cedar denied: ...` | Phase 2 `cedar_check_with_context()` |
| Developer delete in data/ | `[TOOL_DENIAL] Cedar denied: ...` | Phase 2 (wrong path) |
| Admin delete in protected/ | `[TOOL_DENIAL] Cedar denied: ...` | Phase 2 (guardrail forbid) |
| No role header | `[ROLE_SELECTION] Role selection required...` | `UserContextMiddleware` |
| Invalid role assumption | `[TOOL_DENIAL] Cannot assume role '...'` | `UserContextMiddleware` |

---

## How to Run Tests

```bash
# All Cedar tests (31 tests)
uv run pytest tests/test_cedar_smoke.py -v

# Specific suite
uv run pytest tests/test_cedar_smoke.py::TestCedarSmoke -v
uv run pytest tests/test_cedar_smoke.py::TestCedarABAC -v
uv run pytest tests/test_cedar_smoke.py::TestCedarFilePolicies -v
uv run pytest tests/test_cedar_smoke.py::TestCedarPolicyEvaluator -v

# With coverage
uv run pytest tests/test_cedar_smoke.py -v --cov=mcp_server.policy
```
