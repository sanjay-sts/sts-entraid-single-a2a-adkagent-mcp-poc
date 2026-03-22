# Manual Testing Guide

Detailed step-by-step procedures for manually testing the Security Testing Dashboard and three-tier access control system.

## 1. Prerequisites & Setup

### Services Running Checklist

Start all four services before testing:

| # | Service | Command | Port | Health Check |
|---|---------|---------|------|-------------|
| 1 | MCP Server | `uv run python mcp_server/server.py` | 10002 | `curl http://localhost:10002/health` |
| 2 | ADK Agent | `uv run python adk_agent/agent.py` | 10001 | `curl http://localhost:10001/health` |
| 3 | A2A Gateway | `uv run python a2a_server/server.py` | 10000 | `curl http://localhost:10000/health` |
| 4 | Frontend | `cd frontend && npm start` | 10003 | Open http://localhost:10003 |

### Test User Accounts

| Role | User | Email | Group |
|------|------|-------|-------|
| Admin | Adele Vance | AdeleV@2tdgcb.onmicrosoft.com | AI-Agent-Admins (`f1c467f2-954d-4e9d-8949-53a3492b0c14`) |
| Developer | Diego Siciliani | DiegoS@2tdgcb.onmicrosoft.com | AI-Agent-Developers (`c6097742-e961-405f-9a45-2ca9fc971bd7`) |
| Viewer | Johanna Lorenz | JohannaL@2tdgcb.onmicrosoft.com | AI-Agent-Viewers (`a0cd9a0a-da7e-457c-8ca2-237529bb130f`) |
| No-group | (any tenant user not in above groups) | - | (none) |

> **Note**: stsadmin@ is in all 3 groups and resolves to **admin** (highest privilege wins).

### Token Acquisition Methods

**Method A: Token Inspector (simplest)**
1. Start frontend at http://localhost:10003
2. Sign in as the test user
3. Select "destructive" scope preset in the dropdown
4. Expand **Token Inspector** in the sidebar
5. Copy the raw token string

**Method B: Browser DevTools**
1. Sign in to the frontend
2. Open DevTools (F12) > Network tab
3. Send a chat message
4. Find the POST request to `http://localhost:10000/`
5. Copy the `Authorization: Bearer <token>` header value

**Method C: Postman / MSAL**
1. Configure OAuth 2.0 with your app registration
2. Use authorization code flow with `api://{client-id}/access_as_user` scope
3. Copy the access token

---

## 2. Security Context Panel Tests

Test for **each role** (admin, developer, viewer):

### Admin (sign in as AdeleV@)

- [ ] Role badge shows **ADMIN** in green
- [ ] **Permissions** section shows all 10 tools checked:
  - [x] get_user_profile
  - [x] list_files
  - [x] send_email
  - [x] delete_resource
  - [x] get_current_time
  - [x] convert_timezone
  - [x] get_time_difference
  - [x] list_s3_buckets
  - [x] list_s3_objects
  - [x] get_s3_object_info
- [ ] **Groups** section shows group IDs with role name mappings
- [ ] **Token Scopes** lists scopes matching the selected scope preset
- [ ] **Token Expiry** countdown is running (green = > 5 min)

### Developer (sign in as DiegoS@)

- [ ] Role badge shows **DEVELOPER** in blue
- [ ] **Permissions** section:
  - [x] get_user_profile
  - [x] list_files
  - [ ] send_email (unchecked)
  - [ ] delete_resource (unchecked)
  - [ ] get_current_time (unchecked)
  - [ ] convert_timezone (unchecked)
  - [ ] get_time_difference (unchecked)
- [ ] Groups show developer group ID with "developer" mapping

### Viewer (sign in as JohannaL@)

- [ ] Role badge shows **VIEWER** in yellow
- [ ] **Permissions** section:
  - [x] get_user_profile
  - [ ] list_files (unchecked)
  - [ ] send_email (unchecked)
  - [ ] delete_resource (unchecked)
  - [ ] get_current_time (unchecked)
  - [ ] convert_timezone (unchecked)
  - [ ] get_time_difference (unchecked)
- [ ] Groups show viewer group ID with "viewer" mapping

### Token Expiry States

- [ ] **Green**: > 5 minutes remaining
- [ ] **Amber**: < 5 minutes remaining (wait or use a nearly-expired token)
- [ ] **Red**: Token expired (wait for expiry or use an expired token)

---

## 3. Token Inspector Tests

- [ ] Expand the Token Inspector panel in the sidebar
- [ ] **Header** section shows:
  - `alg` (e.g., RS256)
  - `typ` (e.g., JWT)
  - `kid` (key ID)
- [ ] **Payload** section shows all claims with highlighted fields:
  - `groups` - array of security group IDs
  - `scp` - space-separated scope string
  - `aud` - audience (client ID or `api://` URI)
  - `iss` - issuer URL (contains login.microsoftonline.com or sts.windows.net)
  - `exp` - expiration timestamp
- [ ] Cross-reference `groups` claim with Security Context Panel groups

---

## 4. Multi-Tab Conversation Tests

- [ ] Default tab opens with "basic" scope
- [ ] Click "+" to add a second tab with "files" scope
- [ ] Click "+" to add a third tab with "email" scope
- [ ] Click "+" to add a fourth tab with "destructive" scope
- [ ] Verify "+" button is disabled after 4 tabs (max enforced)
- [ ] Send "What is my email?" in tab 1 (basic) -- should succeed
- [ ] Send "List my files" in tab 2 (files) -- behavior depends on role
- [ ] Switch between tabs -- verify each has independent message history
- [ ] Close a tab -- verify it removes correctly

---

## 5. Chat Denial Badge Tests

### Success Scenarios (no badge expected)

| Sign in as | Scope | Prompt | Expected |
|-----------|-------|--------|----------|
| Admin | basic | "What's my email?" | Success, no badge |
| Admin | basic | "What time is it?" | Success, no badge (time tools need no scope) |
| Developer | basic | "What's my email?" | Success, no badge |
| Viewer | basic | "What's my email?" | Success, no badge |

### TOOL Denial Scenarios (orange badge expected)

| Sign in as | Scope | Prompt | Expected Badge |
|-----------|-------|--------|----------------|
| Developer | basic | "What time is it in Tokyo?" | TOOL (orange) |
| Viewer | files | "List my OneDrive files" | TOOL (orange) |
| Viewer | email | "Send email to test@example.com" | TOOL (orange) |
| Developer | email | "Send email to test@example.com" | TOOL (orange) |

### SCOPE Denial Scenarios (amber badge expected)

| Sign in as | Scope | Prompt | Expected Badge |
|-----------|-------|--------|----------------|
| Admin | basic | "List my OneDrive files" | SCOPE (amber) - missing Files.Read |
| Admin | basic | "Send email to test@example.com" | SCOPE (amber) - missing Mail.Send |
| Developer | basic | "List my OneDrive files" | SCOPE (amber) - missing Files.Read |

### AGENT Denial Scenarios (red badge expected)

| Sign in as | Scope | Prompt | Expected Badge |
|-----------|-------|--------|----------------|
| No-group user | any | Any prompt | AGENT (red) - 403 response |

---

## 6. RBAC Test Matrix - Expected Results per Role

### Admin User

| # | Scenario | Tool | Scope Preset | Expected | Denial Type |
|---|----------|------|-------------|----------|-------------|
| 1 | profile_basic | get_user_profile | basic | ALLOW | - |
| 2 | profile_full | get_user_profile | full | ALLOW | - |
| 3 | files_basic | list_files | basic | DENY | SCOPE |
| 4 | files_correct | list_files | files | ALLOW | - |
| 5 | email_basic | send_email | basic | DENY | SCOPE |
| 6 | email_correct | send_email | email | ALLOW | - |
| 7 | delete_basic | delete_resource | basic | DENY | SCOPE |
| 8 | delete_correct | delete_resource | destructive | ALLOW | - |
| 9 | time_basic | get_current_time | basic | ALLOW | - |
| 10 | time_convert | convert_timezone | basic | ALLOW | - |
| 11 | time_diff | get_time_difference | basic | ALLOW | - |
| 12 | files_email | list_files | email | DENY | SCOPE |
| 13 | email_files | send_email | files | DENY | SCOPE |
| 14 | profile_destructive | get_user_profile | destructive | ALLOW | - |

### Developer User

| # | Scenario | Tool | Scope Preset | Expected | Denial Type |
|---|----------|------|-------------|----------|-------------|
| 1 | profile_basic | get_user_profile | basic | ALLOW | - |
| 2 | profile_full | get_user_profile | full | ALLOW | - |
| 3 | files_basic | list_files | basic | DENY | SCOPE |
| 4 | files_correct | list_files | files | ALLOW | - |
| 5 | email_basic | send_email | basic | DENY | TOOL |
| 6 | email_correct | send_email | email | DENY | TOOL |
| 7 | delete_basic | delete_resource | basic | DENY | TOOL |
| 8 | delete_correct | delete_resource | destructive | DENY | TOOL |
| 9 | time_basic | get_current_time | basic | DENY | TOOL |
| 10 | time_convert | convert_timezone | basic | DENY | TOOL |
| 11 | time_diff | get_time_difference | basic | DENY | TOOL |
| 12 | files_email | list_files | email | DENY | SCOPE |
| 13 | email_files | send_email | files | DENY | TOOL |
| 14 | profile_destructive | get_user_profile | destructive | ALLOW | - |

### Viewer User

| # | Scenario | Tool | Scope Preset | Expected | Denial Type |
|---|----------|------|-------------|----------|-------------|
| 1 | profile_basic | get_user_profile | basic | ALLOW | - |
| 2 | profile_full | get_user_profile | full | ALLOW | - |
| 3 | files_basic | list_files | basic | DENY | TOOL |
| 4 | files_correct | list_files | files | DENY | TOOL |
| 5 | email_basic | send_email | basic | DENY | TOOL |
| 6 | email_correct | send_email | email | DENY | TOOL |
| 7 | delete_basic | delete_resource | basic | DENY | TOOL |
| 8 | delete_correct | delete_resource | destructive | DENY | TOOL |
| 9 | time_basic | get_current_time | basic | DENY | TOOL |
| 10 | time_convert | convert_timezone | basic | DENY | TOOL |
| 11 | time_diff | get_time_difference | basic | DENY | TOOL |
| 12 | files_email | list_files | email | DENY | TOOL |
| 13 | email_files | send_email | files | DENY | TOOL |
| 14 | profile_destructive | get_user_profile | destructive | ALLOW | - |

---

## 7. Audit Log Tests

- [ ] Send a chat message -- verify a new entry appears in the Audit Log
- [ ] Entry shows: row number, timestamp, prompt (truncated), scope, HTTP status, denial level, latency
- [ ] Click on a row to expand -- verify full request/response JSON is shown
- [ ] Click **Copy JSON** -- paste into a text editor, verify valid JSON
- [ ] Click **Clear** -- verify all entries are removed

---

## 8. Multi-Account Tests

- [ ] Sign in with primary account (e.g., admin)
- [ ] Click **Add Account** in the header
- [ ] Sign in with a different account (e.g., viewer) via the popup
- [ ] Use the account dropdown to switch between accounts
- [ ] After switching, verify:
  - Security Context Panel shows the new account's role/groups/permissions
  - Token Inspector shows the new account's token claims
  - Chat messages are sent with the new account's token

---

## 9. Results Recording Instructions

### Markdown Format

1. Copy the checklist sections above
2. Fill in pass/fail marks (`[x]` for pass, `[ ]` for fail, add notes)
3. Save as `test_results/YYYY-MM-DD_<role>_manual.md`
   - Example: `test_results/2026-03-08_admin_manual.md`

### JSON Format (from Audit Log)

1. Run test scenarios through the Chat or RBAC Test Matrix
2. Click **Copy JSON** in the Audit Log
3. Save as `test_results/YYYY-MM-DD_<role>_audit.json`
   - Example: `test_results/2026-03-08_admin_audit.json`

### File Naming Convention

```
test_results/
  YYYY-MM-DD_admin_manual.md
  YYYY-MM-DD_admin_audit.json
  YYYY-MM-DD_developer_manual.md
  YYYY-MM-DD_developer_audit.json
  YYYY-MM-DD_viewer_manual.md
  YYYY-MM-DD_viewer_audit.json
```

See `test_results/README.md` for templates and JSON schema.
