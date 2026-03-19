# Frontend Manual Test Results — OBO Enabled

**Date:** 2026-03-19
**OBO:** Enabled (`GRAPH_OBO_ENABLED = true`, `ENTRA_CLIENT_SECRET` configured)
**LLM:** AWS Bedrock Claude Haiku 4.5
**Frontend:** http://localhost:10003

---

## Test Suite A: AdeleV (Admin)

**User:** AdeleV@2tdgcb.onmicrosoft.com
**Role:** admin

### A1: Security Context Panel

| Check | Result |
|-------|--------|
| Role badge: ADMIN (green) | PASS |
| available_roles includes admin | PASS |
| Permissions: all 7 tools checked | PASS |
| Groups: f1c467f2... → admin | PASS |
| Token Expiry: countdown running | PASS |
| Token Scopes: access_as_user | PASS |

### A2-OBO: RBAC Test Matrix (Run All, OBO enabled)

**Scope preset:** destructive
**Result:** 14/14 PASS

| # | Scenario | Expected | Actual | Denial | Latency | PASS |
|---|----------|----------|--------|--------|---------|------|
| 1 | profile_basic | ALLOW | ALLOW | — | 15856ms | PASS |
| 2 | files_basic | ALLOW | ALLOW | — | 14787ms | PASS |
| 3 | files_correct | ALLOW | ALLOW | — | 14742ms | PASS |
| 4 | email_basic | ALLOW | ALLOW | — | 14063ms | PASS |
| 5 | email_correct | ALLOW | ALLOW | — | 15568ms | PASS |
| 6 | delete_basic | ALLOW | ALLOW | — | 22881ms | PASS |
| 7 | delete_destructive | ALLOW | ALLOW | — | 12592ms | PASS |
| 8 | time_current | ALLOW | ALLOW | — | 12024ms | PASS |
| 9 | time_convert | ALLOW | ALLOW | — | 13250ms | PASS |
| 10 | time_diff | ALLOW | ALLOW | — | 13545ms | PASS |
| 11 | viewer_files | ALLOW | ALLOW | — | 16314ms | PASS |
| 12 | viewer_email | ALLOW | ALLOW | — | 14548ms | PASS |
| 13 | dev_email | ALLOW | ALLOW | — | 14101ms | PASS |
| 14 | dev_time | ALLOW | ALLOW | — | 12949ms | PASS |

**Key observations:**
- All Graph-dependent tools succeeded via OBO (`_obo_used: true`)
- `profile_basic` returned full Graph profile (displayName: Adele Vance, jobTitle: Retail Manager)
- `files_basic` succeeded despite `basic` scope (missing Files.Read) — OBO uses app registration permissions
- `email_basic` succeeded despite `basic` scope (missing Mail.Send) — OBO uses app registration permissions
- Average latency: ~14.2s per scenario

### A3-OBO: Admin — Graph tools succeed with OBO (basic scope)

**Scope preset:** basic (missing Files.Read, Mail.Send)
**Result:** 3/3 PASS — OBO bypasses frontend scope entirely

| Prompt | Expected | Actual | Badge | Latency |
|--------|----------|--------|-------|---------|
| List my OneDrive files | SUCCESS | SUCCESS (empty OneDrive) | — | 23297ms |
| Send email to xemex76g@gmail.com | SUCCESS | SUCCESS (sent) | — | 15493ms |
| What time is it in Tokyo? | SUCCESS | SUCCESS (06:31 JST) | — | 12914ms |

**Key observation:** `files` and `email` tools succeeded with `basic` scope preset.
Confirms OBO uses app registration permissions, not user token scopes.

---

## Test Suite B: DiegoS (Developer)

**User:** DiegoS@2tdgcb.onmicrosoft.com
**Role:** developer

### B1: Security Context Panel

| Check | Result |
|-------|--------|
| Role badge: DEVELOPER (blue) | PASS |
| available_roles includes developer | PASS |
| Permissions: get_user_profile ✓, list_files ✓, others ✗ | PASS |
| Groups: c6097742... → developer | PASS |
| Token Expiry: countdown running | PASS |
| Token Scopes: access_as_user | PASS |

### B2-OBO: Developer role — RBAC Test Matrix (Run All, OBO enabled)

**Scope preset:** full
**Result:** 14/14 PASS (confirmed across 2 consecutive runs)

| # | Scenario | Expected | Actual | Denial | Latency | PASS |
|---|----------|----------|--------|--------|---------|------|
| 1 | profile_basic | ALLOW | ALLOW | — | 15250ms | PASS |
| 2 | files_basic | ALLOW | ALLOW | — | 14310ms | PASS |
| 3 | files_correct | ALLOW | ALLOW | — | 13792ms | PASS |
| 4 | email_basic | TOOL | TOOL | tool_not_available | 8457ms | PASS |
| 5 | email_correct | TOOL | TOOL | tool_not_available | 7509ms | PASS |
| 6 | delete_basic | TOOL | TOOL | tool_not_available | 7938ms | PASS |
| 7 | delete_destructive | TOOL | TOOL | tool_not_available | 7159ms | PASS |
| 8 | time_current | TOOL | TOOL | tool_not_available | 7237ms | PASS |
| 9 | time_convert | TOOL | TOOL | tool_not_available | 8136ms | PASS |
| 10 | time_diff | TOOL | TOOL | tool_not_available | 8209ms | PASS |
| 11 | viewer_files | ALLOW | ALLOW | — | 13437ms | PASS |
| 12 | viewer_email | TOOL | TOOL | tool_not_available | 8934ms | PASS |
| 13 | dev_email | TOOL | TOOL | tool_not_available | 7627ms | PASS |
| 14 | dev_time | TOOL | TOOL | tool_not_available | 7928ms | PASS |

**Key observations:**
- `profile_basic` returned full Graph profile via OBO (displayName: Diego Siciliani, jobTitle: HR Manager)
- `files_basic` succeeded despite `basic` scope — OBO uses app registration permissions
- Tool denials (#4-10, 12-14) are "soft denials" — LLM reports tools not available rather than `[TOOL_DENIAL]` from MCP
- Denial classifier updated to catch LLM soft denials (`tool_not_available` reason)
- Average latency: ~9.8s (ALLOW ~14s, TOOL deny ~8s — denials faster since no tool call)

---

## Issues Found & Fixed During Testing

| # | Issue | Fix | File |
|---|-------|-----|------|
| 1 | AWS Bedrock bearer token expired | Refreshed `AWS_BEARER_TOKEN_BEDROCK` in `.env` | `.env` |
| 2 | `GRAPH_OBO_ENABLED` still `false` | Flipped to `true` | `frontend/src/utils/testScenarios.js` |
| 3 | `shouldSucceed` logic checked frontend scope with OBO | Removed `hasScope` check when OBO enabled — OBO uses app registration permissions | `frontend/src/utils/testScenarios.js` |
| 4 | `permissions.toml` developer group mapped to `"viewer"` | Changed `c6097742...` mapping from `"viewer"` to `"developer"` | `permissions.toml` |
| 5 | Denial classifier missed LLM soft denials | Added 4 regex patterns for `tool_not_available` | `frontend/src/utils/denialClassifier.js` |
| 6 | Denial classifier missed "restricted to admin users" | Broadened `/restricted to administrators/i` → `/restricted to admin/i`, added `/don't have permission to/i` | `frontend/src/utils/denialClassifier.js` |
| 7 | 403 error responses lacked CORS headers | Added `_cors_headers()` helper to auth middleware error responses | `a2a_server/server.py` |
| 8 | Classifier missed "Tool 'X' not found" and "functions" | Added `/Tool.*not found/i`, broadened to `.*(tool\|function)` | `frontend/src/utils/denialClassifier.js` |

---

## Test Suite C: JohannaL (Viewer)

**User:** JohannaL@2tdgcb.onmicrosoft.com
**Role:** viewer

### C1: Security Context Panel

| Check | Result |
|-------|--------|
| Role badge: VIEWER (yellow) | PASS |
| available_roles includes viewer | PASS |
| Permissions: only get_user_profile ✓, all others ✗ | PASS |
| Groups: a0cd9a0a... → viewer | PASS |
| Token Expiry: countdown running | PASS |
| Token Scopes: access_as_user | PASS |

### C2-OBO: Viewer role — RBAC Test Matrix (Run All, OBO enabled)

**Scope preset:** full
**Result:** 14/14 PASS

| # | Scenario | Expected | Actual | Denial | Latency | PASS |
|---|----------|----------|--------|--------|---------|------|
| 1 | profile_basic | ALLOW | ALLOW | — | 16957ms | PASS |
| 2 | files_basic | TOOL | TOOL | tool_not_available | 9571ms | PASS |
| 3 | files_correct | TOOL | TOOL | tool_not_available | 7332ms | PASS |
| 4 | email_basic | TOOL | TOOL | tool_not_available | 7927ms | PASS |
| 5 | email_correct | TOOL | TOOL | tool_not_available | 8957ms | PASS |
| 6 | delete_basic | TOOL | TOOL | tool_not_available | 7665ms | PASS |
| 7 | delete_destructive | TOOL | TOOL | tool_not_available | 6887ms | PASS |
| 8 | time_current | TOOL | TOOL | tool_not_available | 7288ms | PASS |
| 9 | time_convert | TOOL | TOOL | tool_not_available | 7702ms | PASS |
| 10 | time_diff | TOOL | TOOL | tool_not_available | 8384ms | PASS |
| 11 | viewer_files | TOOL | TOOL | tool_not_available | 8136ms | PASS |
| 12 | viewer_email | TOOL | TOOL | tool_not_available | 7799ms | PASS |
| 13 | dev_email | TOOL | TOOL | tool_not_available | 8544ms | PASS |
| 14 | dev_time | TOOL | TOOL | tool_not_available | 7621ms | PASS |

**Key observations:**
- `profile_basic` returned full Graph profile via OBO (displayName: Johanna Lorenz, jobTitle: Senior Engineer)
- All 13 other scenarios correctly denied as TOOL (viewer only has `get_user_profile`)
- All denials are "soft denials" — LLM reports tools not available for this role
- Average latency: ~8.1s (denials ~7.9s, profile ~17s)

---

## Test Suite D: No-Group User & Multi-Group User

### D1: PradeepG (No-Group User) — Agent-Level Denial

**User:** PradeepG@2tdgcb.onmicrosoft.com
**Groups:** Not in AI-Agent-Admins, Developers, or Viewers
**Result:** PASS — A2A gateway blocks with 403

| Check | Result |
|-------|--------|
| Security Context Panel: "Not a member of any authorized group" | PASS |
| Chat message → AGENT (red) badge | PASS |
| HTTP status: 403 in Audit Log | PASS |
| denial_reason: no_group_membership | PASS |

**Issue found:** 403 responses initially returned "Failed to fetch" (HTTP 0) due to missing CORS headers on auth middleware error responses. Fixed by adding `_cors_headers()` helper.

### D3: stsadmin (Multi-Group User) — Role Switching

**User:** stsadmin@2tdgcb.onmicrosoft.com
**Groups:** AI-Agent-Admins + AI-Agent-Developers + AI-Agent-Viewers (all 3)

**D3.1 Security Context Panel:**

| Check | Result |
|-------|--------|
| Role badge: ADMIN (green) — highest privilege wins | PASS |
| available_roles: admin, developer, viewer (all three) | PASS |
| Groups: f1c467f2→admin, c6097742→developer, a0cd9a0a→viewer | PASS |
| Permissions: all 7 tools checked (admin) | PASS |

**D3.1 Admin matrix:** 14/14 PASS
**D3.2 Developer matrix (role switch):** 14/14 PASS
**D3.3 Viewer matrix (role switch):** 14/14 PASS

**Key observations:**
- Role switching works without re-login — results clear on switch
- stsadmin's OneDrive has real files (amazonq, Apps, Attachments, etc.)
- `list_files` as admin/developer returns actual files; as viewer returns TOOL denial
- All 3 roles produce correct permissions and denials

---

## Summary

| Suite | User | Role | Matrix Result | Chat Tests |
|-------|------|------|---------------|------------|
| A | AdeleV | admin | 14/14 PASS | A3-OBO: 3/3 PASS |
| B | DiegoS | developer | 14/14 PASS | — |
| C | JohannaL | viewer | 14/14 PASS | — |
| D1 | PradeepG | none (no group) | AGENT 403 PASS | Chat: AGENT badge |
| D3 | stsadmin | admin/dev/viewer | 14/14 x3 PASS | Role switch verified |
