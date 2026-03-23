# Frontend Manual Test Results — 2026-03-18

**User**: AdeleV@2tdgcb.onmicrosoft.com
**Role**: admin
**Date**: 2026-03-18
**Companion**: `09-frontend-testing-strategy.md`
**Previous**: `07-test-results.md` (MCP Inspector, 22/22 pass)

---

## A1: Admin role — Security Context Panel

**Scope preset**: destructive
**Result**: PASS (6/6)

| # | Check | Expected | Actual | Status |
|---|-------|----------|--------|--------|
| 1 | Role badge | ADMIN (green) | ADMIN | PASS |
| 2 | available_roles | ['admin'] | admin (only option in selector) | PASS |
| 3 | Permissions | all 7 tools checked | all 7 ✓ | PASS |
| 4 | Groups | f1c467f2... → admin | f1c467f2... → admin | PASS |
| 5 | Token Expiry | countdown running, green | 77:41, running | PASS |
| 6 | Token Scopes | access_as_user | access_as_user | PASS |

**Notes:**
- 4 groups shown (3 unknown + 1 admin). Unknown groups are Entra groups not mapped in permissions.toml — expected.
- Token scopes show `access_as_user` (custom API scope). Graph scopes (User.Read, Files.Read, etc.) go to a separate token for the Graph audience.

---

## A2: Admin role — RBAC Test Matrix (Run All, destructive scope)

**Scope preset**: destructive
**Result**: PASS (14/14)

| # | Scenario | Expected | Actual | Denial | Latency | Status |
|---|----------|----------|--------|--------|---------|--------|
| 1 | profile_basic | ALLOW | ALLOW | — | 15814ms | PASS |
| 2 | files_basic | RESOURCE | RESOURCE | graph_api_denied | 12050ms | PASS |
| 3 | files_correct | RESOURCE | RESOURCE | graph_api_denied | 11821ms | PASS |
| 4 | email_basic | RESOURCE | RESOURCE | graph_api_denied | 13696ms | PASS |
| 5 | email_correct | RESOURCE | RESOURCE | graph_api_denied | 12182ms | PASS |
| 6 | delete_basic | ALLOW | ALLOW | — | 10928ms | PASS |
| 7 | delete_destructive | ALLOW | ALLOW | — | 10781ms | PASS |
| 8 | time_current | ALLOW | ALLOW | — | 11287ms | PASS |
| 9 | time_convert | ALLOW | ALLOW | — | 16457ms | PASS |
| 10 | time_diff | ALLOW | ALLOW | — | 11803ms | PASS |
| 11 | viewer_files | RESOURCE | RESOURCE | graph_api_denied | 12135ms | PASS |
| 12 | viewer_email | RESOURCE | RESOURCE | graph_api_denied | 12900ms | PASS |
| 13 | dev_email | RESOURCE | RESOURCE | graph_api_denied | 13953ms | PASS |
| 14 | dev_time | ALLOW | ALLOW | — | 11829ms | PASS |

**Notes:**
- All Graph-dependent tools (list_files, send_email) correctly return RESOURCE denial due to Graph API 401 (OBO not implemented).
- delete_resource correctly returns ALLOW — simulated tool, no Graph call.
- Time tools correctly return ALLOW — no Graph dependency.
- get_user_profile correctly returns ALLOW — falls back to token claims on Graph 401.
- Classifier correctly detected `graph_api_unavailable` and `401.*graph` patterns in response text.
- Average latency: ~12.5s per scenario (includes LLM round-trip).
