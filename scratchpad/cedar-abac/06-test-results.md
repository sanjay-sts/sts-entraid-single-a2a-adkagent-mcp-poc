# Cedar ABAC: Test Results

**Date**: 2026-03-26
**Cedar Engine**: cedarpy >= 4.0.0
**Test Tool**: pytest + Security Testing Dashboard
**Prerequisite**: ABAC Frontend Testing Integration (Item 8 in `03-implementation-plan.md`) --- DONE
**Companion**: `04-testing-strategy.md` (unit/integration), `05-frontend-testing-strategy.md` (frontend)

---

## Unit/Integration Test Results

**Command:** `uv run pytest tests/test_cedar_smoke.py -v`

### Summary: 31/31 PASSED

| Suite | Class | Tests | Status |
|-------|-------|-------|--------|
| A | TestCedarSmoke | 5 | 5/5 PASSED |
| B | TestCedarABAC | 5 | 5/5 PASSED |
| C | TestCedarFilePolicies | 9 | 9/9 PASSED |
| D | TestCedarPolicyEvaluator | 12 | 12/12 PASSED |

### Suite A: Cedar RBAC Smoke (5/5)

| # | Test | Status |
|---|------|--------|
| A1 | test_admin_can_call_any_tool | PASS |
| A2 | test_viewer_denied_send_email | PASS |
| A3 | test_developer_can_call_list_files | PASS |
| A4 | test_viewer_can_call_get_user_profile | PASS |
| A5 | test_no_role_denied | PASS |

### Suite B: Cedar ABAC (5/5)

| # | Test | Status |
|---|------|--------|
| B1 | test_admin_can_delete_anywhere | PASS |
| B2 | test_archiver_can_delete_in_archive | PASS |
| B3 | test_archiver_denied_outside_archive | PASS |
| B4 | test_developer_without_archiver_denied | PASS |
| B5 | test_forbid_protected_overrides_admin | PASS |

### Suite C: File-Based Policies (9/9)

| # | Test | Status |
|---|------|--------|
| C1 | test_admin_send_email_allowed | PASS |
| C2 | test_developer_send_email_denied | PASS |
| C3 | test_viewer_get_s3_object_info_allowed | PASS |
| C4 | test_viewer_list_s3_buckets_denied | PASS |
| C5 | test_archiver_delete_in_archive_allowed | PASS |
| C6 | test_archiver_delete_outside_archive_denied | PASS |
| C7 | test_admin_delete_in_protected_denied | PASS |
| C8 | test_list_tools_allowed_for_any_user | PASS |

### Suite D: CedarPolicyEvaluator Integration (12/12)

| # | Test | Status |
|---|------|--------|
| D1 | test_admin_allowed | PASS |
| D2 | test_viewer_denied_admin_tool | PASS |
| D3 | test_developer_allowed_list_files | PASS |
| D4 | test_archiver_delete_allowed | PASS |
| D5 | test_archiver_delete_wrong_path_denied | PASS |
| D6 | test_developer_no_archiver_denied | PASS |
| D7 | test_protected_forbid_overrides_admin | PASS |
| D8 | test_get_available_roles_delegates_to_toml | PASS |
| D9 | test_cognito_user_works | PASS |
| D10 | test_user_override_from_toml | PASS |
| D11 | test_assumed_role_enforced_check_access | PASS |
| D12 | test_assumed_role_enforced_batch | PASS |
| D13 | test_assumed_admin_still_works | PASS |

---

## Frontend Test Results

**Mode**: (record auth bypass or real auth)
**Date**: (fill in when testing)

### ABAC Scenarios via Access Control Test Matrix

| # | Scenario | Role | archiver | Expected | Actual | Status | Latency |
|---|----------|------|----------|----------|--------|--------|---------|
| 1 | s3_delete_admin_archive | admin | off | ALLOW | | | |
| 2 | s3_delete_admin_protected | admin | off | DENY (guardrail) | | | |
| 3 | s3_delete_admin_normal | admin | off | ALLOW | | | |
| 4 | s3_delete_dev_archiver_archive | developer | on | ALLOW | | | |
| 5 | s3_delete_dev_archiver_protected | developer | on | DENY (guardrail) | | | |
| 6 | s3_delete_dev_archiver_normal | developer | on | DENY (ABAC) | | | |
| 7 | s3_delete_dev_no_archiver | developer | off | DENY (ABAC) | | | |
| 8 | s3_delete_viewer | viewer | off | DENY (RBAC) | | | |

### Security Context Panel Checks

| # | Check | Expected | Actual | Status |
|---|-------|----------|--------|--------|
| 1 | Archiver checkbox visible | Below role selector | | |
| 2 | Default state | Unchecked | | |
| 3 | Toggle sends header | `X-Abac-Attrs: {"archiver": true}` | | |
| 4 | Matrix resets on toggle | Results cleared | | |
| 5 | +archiver badge in matrix | Shows next to role badge | | |

### Chat Interface ABAC Checks

| # | Check | Role | archiver | Prompt | Expected Badge | Actual | Status |
|---|-------|------|----------|--------|----------------|--------|--------|
| 1 | Dev+archiver delete archive/ | developer | on | "Delete archive/old.csv from bucket sts-use1-mcp-poc-data" | (none) | | |
| 2 | Dev+archiver delete protected/ | developer | on | "Delete protected/critical.csv from bucket sts-use1-mcp-poc-data" | TOOL (orange) | | |
| 3 | Dev no archiver delete | developer | off | "Delete archive/old.csv from bucket sts-use1-mcp-poc-data" | TOOL (orange) | | |
| 4 | Admin delete protected/ | admin | off | "Delete protected/critical.csv from bucket sts-use1-mcp-poc-data" | TOOL (orange) | | |

---

## Bugs Found

| # | Title | Severity | Status | Description | Fix |
|---|-------|----------|--------|-------------|-----|
| (none yet) | | | | | |

---

## Observations

(Record interesting behavior, edge cases, or notes during testing)

1. ...
2. ...
3. ...
