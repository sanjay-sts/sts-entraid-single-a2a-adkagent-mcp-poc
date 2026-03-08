# Testing Documentation

This document provides step-by-step instructions for setting up and testing the Identity-Aware AI Agent System locally.

## Prerequisites

- Python 3.10+
- Node.js 18+
- [uv](https://docs.astral.sh/uv/) - Fast Python package installer (recommended)
- Microsoft Entra ID app registration (see [Entra ID Setup](#entra-id-app-registration-setup))
- Anthropic API Key (for Claude via LiteLLM)

### Installing uv

```bash
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Windows (winget)
winget install --id=astral-sh.uv -e

# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

> **Note**: `uv` is 10-100x faster than pip. If you prefer pip, see [Alternative: Using pip](#alternative-using-pip) section.

---

## Entra ID App Registration Setup

### Creating the App Registration

1. Go to [Microsoft Entra admin center](https://entra.microsoft.com)
2. Navigate to **Identity** > **Applications** > **App registrations**
3. Click **New registration**
4. Set name: `AI-Agent-System` (or your preferred name)
5. Select: **Accounts in this organizational directory only**
6. Click **Register**

### Recording Essential Values

After registration, note these values from the **Overview** page:

| Value | Description | Example |
|-------|-------------|---------|
| Application (client) ID | Your `ENTRA_CLIENT_ID` | `12345678-abcd-1234-abcd-123456789abc` |
| Directory (tenant) ID | Your `ENTRA_TENANT_ID` | `87654321-dcba-4321-dcba-987654321fed` |

### Configuring Redirect URIs (Critical for Frontend)

1. Go to **Authentication** blade
2. Click **Add a platform**
3. Select **Single-page application** (NOT "Web")
4. Add these Redirect URIs:
   - `http://localhost:10003`
   - `http://localhost:10003/redirect`
5. Click **Configure**

> **Important**: If you previously configured this as a "Web" platform, you need to add it as "Single-page application" for MSAL.js to work correctly.

### Configuring API Permissions

1. Go to **API permissions** blade
2. Click **Add a permission** > **Microsoft Graph** > **Delegated permissions**
3. Add these permissions:
   - `openid` (Sign users in)
   - `profile` (View basic profile)
   - `email` (View email address)
   - `User.Read` (Read user profile)
   - `Files.Read` (Read user files) - optional, for file operations
   - `Mail.Send` (Send mail) - optional, for email operations
4. Click **Grant admin consent for [tenant]** (requires admin)

### Configuring Group Claims (For Role-Based Access)

1. Go to **Token configuration** blade
2. Click **Add groups claim**
3. Select **Security groups**
4. Under **ID token**, check **Group ID**
5. Under **Access token**, check **Group ID**
6. Click **Add**

### Creating Security Groups

Create these security groups in Entra ID and note their Object IDs:

| Group Name | Purpose | Environment Variable |
|------------|---------|---------------------|
| AI-Agent-Admins | Full access to all tools | `ADMIN_GROUP_ID` |
| AI-Agent-Developers | Access to profile and files | `DEVELOPER_GROUP_ID` |
| AI-Agent-Viewers | Access to profile only | `VIEWER_GROUP_ID` |

To create groups:
1. Go to **Identity** > **Groups** > **All groups**
2. Click **New group**
3. Set Group type: **Security**
4. Enter name and create
5. Copy the **Object ID** from the group's overview page

---

## Environment Configuration

### Understanding the Environment Files

This project uses **ONE Entra ID app registration** shared between frontend and backend. The same Client ID and Tenant ID are used in both `.env` files with different prefixes:

| File | Variable | Purpose |
|------|----------|---------|
| `.env` (root) | `ENTRA_CLIENT_ID` | Backend token validation |
| `.env` (root) | `ENTRA_TENANT_ID` | Backend token validation |
| `frontend/.env` | `REACT_APP_ENTRA_CLIENT_ID` | Frontend authentication |
| `frontend/.env` | `REACT_APP_ENTRA_TENANT_ID` | Frontend authentication |

> **Note**: The `REACT_APP_` prefix is required by React to expose variables to the browser.

### Backend Environment Setup

```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc

# Copy the template
copy .env.example .env
```

Edit `.env` with your values:

```bash
# Microsoft Entra ID (from App Registration)
ENTRA_CLIENT_ID=your-application-client-id
ENTRA_TENANT_ID=your-directory-tenant-id

# Access Control Group IDs (from Security Groups)
ADMIN_GROUP_ID=your-admin-group-object-id
DEVELOPER_GROUP_ID=your-developer-group-object-id
VIEWER_GROUP_ID=your-viewer-group-object-id

# Blocked Users (comma-separated user object IDs, optional)
BLOCKED_USERS=

# Server Ports
A2A_SERVER_PORT=10000
ADK_SERVER_PORT=10001
MCP_SERVER_PORT=10002
FRONTEND_PORT=10003

# LLM API Key (for Claude via LiteLLM)
# Set either CLAUDE_API_KEY or ANTHROPIC_API_KEY
CLAUDE_API_KEY=your-anthropic-api-key
```

### Frontend Environment Setup

```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc\frontend

# Copy the template
copy .env.example .env
```

Edit `frontend/.env` with the **same** Entra ID values:

```bash
# Microsoft Entra ID (SAME values as backend, with REACT_APP_ prefix)
REACT_APP_ENTRA_CLIENT_ID=your-application-client-id
REACT_APP_ENTRA_TENANT_ID=your-directory-tenant-id

# Backend Server URL
REACT_APP_A2A_SERVER_URL=http://localhost:10000
```

---

## Backend Setup

### 1. Create Virtual Environment and Install Dependencies

```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc

# Create virtual environment
uv venv

# Install dependencies
uv pip install -r requirements.txt
```

### 2. Activate Virtual Environment

```bash
# Windows (Command Prompt)
.venv\Scripts\activate

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Linux/macOS
source .venv/bin/activate
```

> **Note**: `uv` creates the virtual environment in `.venv` (not `venv`).

### 3. Start Backend Services

Open **3 separate terminal windows** and run each service:

**Terminal 1 - MCP Server (port 10002):**
```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc
.venv\Scripts\activate
python mcp_server/server.py

# Or run directly with uv (no activation needed):
uv run python mcp_server/server.py
```

Expected output:
```
INFO:     Started server process [xxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:10002
```

**Terminal 2 - ADK Agent (port 10001):**
```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc
.venv\Scripts\activate
python adk_agent/agent.py

# Or run directly with uv (no activation needed):
uv run python adk_agent/agent.py
```

Expected output:
```
INFO:     Started server process [xxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:10001
```

**Terminal 3 - A2A Gateway (port 10000):**
```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc
.venv\Scripts\activate
python a2a_server/server.py

# Or run directly with uv (no activation needed):
uv run python a2a_server/server.py
```

Expected output:
```
INFO:     Started server process [xxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:10000
```

---

## Frontend Setup

### 1. Install Dependencies

```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc\frontend
npm install
```

### 2. Start Frontend

**Terminal 4:**
```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc\frontend
npm start
```

This will automatically open http://localhost:10003 in your browser.

---

## Verifying the Setup

### Health Check Endpoints

Test that all services are running:

```bash
# Check A2A Gateway
curl http://localhost:10000/health
# Expected: {"status":"healthy","service":"a2a-gateway"}

# Check ADK Agent
curl http://localhost:10001/health
# Expected: {"status":"healthy","agent":"identity_aware_agent"}

# Check Agent Card (A2A discovery)
curl http://localhost:10000/.well-known/agent.json
# Expected: JSON with agent name, skills, and security schemes
```

### Frontend Verification

1. Open http://localhost:10003
2. You should see the login page with "Sign In with Microsoft" button
3. Click the button - a Microsoft login popup should appear
4. After login, you should see the chat interface

---

## Running Automated Tests

### Prerequisites

Ensure all backend services are running before running tests.

### Run Tests

```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc

# Option 1: With activated environment
.venv\Scripts\activate
pytest tests/test_access_control.py -v

# Option 2: Using uv run (no activation needed)
uv run pytest tests/test_access_control.py -v
```

### Test Categories

| Test Class | What It Tests |
|------------|---------------|
| `TestAgentLevelAccess` | A2A gateway authentication and group-based access |
| `TestToolLevelAccess` | Role-based tool permissions (admin/developer/viewer) |
| `TestResourceLevelAccess` | OAuth scope enforcement |
| `TestHealthEndpoints` | Service health checks |

---

## Troubleshooting

### Common Issues

#### 1. "AADSTS50011: The redirect URI specified in the request does not match"

**Cause**: Redirect URI not configured correctly in Entra ID.

**Solution**:
1. Go to App Registration > Authentication
2. Ensure platform is **Single-page application** (not Web)
3. Add `http://localhost:10003` as a redirect URI

#### 2. "Module not found" errors when starting Python services

**Cause**: Dependencies not installed or virtual environment not activated.

**Solution**:
```bash
# Reinstall dependencies with uv
uv sync

# Or activate and install manually
.venv\Scripts\activate
uv pip install -r requirements.txt
```

#### 3. "CORS error" in browser console

**Cause**: Frontend trying to access backend on different port.

**Solution**: Ensure A2A server is running on port 10000 and `REACT_APP_A2A_SERVER_URL=http://localhost:10000` in `frontend/.env`.

#### 4. "401 Unauthorized" when chatting

**Cause**: Token validation failing.

**Solution**:
- Verify `ENTRA_CLIENT_ID` and `ENTRA_TENANT_ID` match between backend and frontend
- Check that API permissions are granted admin consent

#### 5. "403 Forbidden - not a member of any authorized group"

**Cause**: User not in any allowed security group.

**Solution**:
- Add your user to one of the security groups (Admin, Developer, or Viewer)
- Verify group Object IDs in `.env` match the actual groups

#### 6. Frontend shows blank page

**Cause**: Environment variables not loaded.

**Solution**:
- Ensure `frontend/.env` exists with correct values
- Restart the frontend server after changing `.env`

---

## Service Ports Summary

| Service | Port | URL |
|---------|------|-----|
| Frontend (React) | 10003 | http://localhost:10003 |
| A2A Gateway | 10000 | http://localhost:10000 |
| ADK Agent | 10001 | http://localhost:10001 |
| MCP Server | 10002 | http://localhost:10002 |

---

## Testing Different User Roles

To test role-based access control:

1. **Admin User**: Add user to Admin security group
   - Can use all tools: profile, files, email, delete

2. **Developer User**: Add user to Developer security group
   - Can use: profile, files
   - Cannot use: email, delete

3. **Viewer User**: Add user to Viewer security group
   - Can use: profile only
   - Cannot use: files, email, delete

4. **Blocked User**: Add user's Object ID to `BLOCKED_USERS` in `.env`
   - Cannot access the agent at all (403 at gateway)

---

## Security Testing Dashboard

The frontend includes a full Security Testing Dashboard that provides comprehensive tools for testing and visualizing the three-tier access control system.

### Dashboard Layout

After signing in, the dashboard shows:
- **Left Sidebar** (collapsible): Security Context Panel, Token Inspector, RBAC Test Matrix
- **Main Content**: Multi-tab chat interface with per-tab scope selection, Audit Log

### Security Context Panel

Displays real-time security information by calling the `GET /me` endpoint on the A2A server:
- **Role Badge**: Color-coded role (green=admin, blue=developer, yellow=viewer, red=none)
- **Groups**: Entra ID security group IDs with mapped role names
- **Token Scopes**: OAuth scopes present in the current token
- **Token Expiry**: Live countdown timer (amber when < 5 minutes, red when expired)
- **Permissions**: Checkmarks showing which tools the current role can access

### Testing the `/me` Endpoint

The A2A server exposes a `GET /me` endpoint that returns the authenticated user's security context:

```bash
# Test with a valid Bearer token
curl -H "Authorization: Bearer <access-token>" http://localhost:10000/me
```

Expected response:
```json
{
  "user": { "email": "user@domain.com", "name": "User Name", "oid": "..." },
  "security": {
    "role": "developer",
    "groups": ["group-id-1"],
    "group_names": { "group-id-1": "developer" },
    "token_scopes": ["User.Read", "Files.Read"],
    "token_expiry": 1741363200,
    "issuer": "https://login.microsoftonline.com/{tenant}/v2.0"
  },
  "permissions": {
    "get_user_profile": true, "list_files": true, "send_email": false,
    "delete_resource": false, "get_current_time": false,
    "convert_timezone": false, "get_time_difference": false
  },
  "tool_scopes": {
    "get_user_profile": ["User.Read"], "list_files": ["Files.Read"],
    "send_email": ["Mail.Send"], "delete_resource": ["Files.ReadWrite.All"],
    "get_current_time": [], "convert_timezone": [], "get_time_difference": []
  }
}
```

### Token Inspector

The sidebar includes a collapsible Token Inspector that decodes the JWT access token client-side (display only, never used for authorization):
- **Header**: Shows algorithm, token type, key ID
- **Payload**: Shows all claims with highlighted fields: `groups`, `scp`, `aud`, `iss`, `exp`, `oid`, `sub`, `preferred_username`

### Multi-Tab Conversations

The main area supports up to 4 conversation tabs, each with its own scope preset:

| Scope Preset | Scopes Requested | Use Case |
|-------------|-------------------|----------|
| `basic` | `api://...`, `User.Read` | Profile operations |
| `files` | `api://...`, `User.Read`, `Files.Read` | File listing |
| `email` | `api://...`, `User.Read`, `Mail.Send` | Email sending |
| `full` | `api://...`, `User.Read`, `Files.Read`, `Mail.Send` | All read + email |
| `destructive` | `api://...`, `User.Read`, `Files.Read`, `Files.ReadWrite.All`, `Mail.Send` | Delete operations |

**How to test scope differences:**
1. Open a "basic" tab and ask "List my OneDrive files" → Should fail (scope denial)
2. Open a "files" tab and ask "List my OneDrive files" → Should succeed (if role allows)

### RBAC Test Matrix

The sidebar includes a one-click test grid that automatically runs predefined test scenarios:

1. Click **Run** next to any scenario to test it individually
2. Click **Run All** to execute all scenarios sequentially (2s delay between each)
3. Each row shows:
   - **Tool**: The MCP tool being tested
   - **Scope**: Which scope preset the test uses
   - **Expected**: ALLOW or DENY (based on current role + scope)
   - **Result**: PASS/FAIL with denial badge and latency

**Test Scenarios by Role:**

| Scenario | Admin | Developer | Viewer |
|----------|-------|-----------|--------|
| `get_user_profile` (basic) | ALLOW | ALLOW | ALLOW |
| `list_files` (basic) | SCOPE DENY | SCOPE DENY | SCOPE DENY |
| `list_files` (files) | ALLOW | ALLOW | TOOL DENY |
| `send_email` (basic) | SCOPE DENY | TOOL DENY | TOOL DENY |
| `send_email` (email) | ALLOW | TOOL DENY | TOOL DENY |
| `delete_resource` (basic) | SCOPE DENY | TOOL DENY | TOOL DENY |
| `delete_resource` (destructive) | ALLOW | TOOL DENY | TOOL DENY |
| `get_current_time` (basic) | ALLOW | TOOL DENY | TOOL DENY |

### Denial Classification

The dashboard classifies denials into four tiers, shown as color-coded badges:

| Tier | Badge Color | Meaning | Example |
|------|------------|---------|---------|
| **AGENT** | Red | A2A gateway blocked the request | User not in any group (403) |
| **TOOL** | Orange | MCP tool denied by role check | Viewer trying `list_files` |
| **SCOPE** | Amber | Token missing required OAuth scopes | Using `basic` scope for `list_files` |
| **RESOURCE** | Purple | Microsoft Graph API rejected the call | Insufficient Graph permissions |

**Detection mechanism:**
- HTTP 401/403 → `AGENT` (reads `denial_reason` from response body)
- Response contains `[TOOL_DENIAL]` → `TOOL`
- Response contains `[SCOPE_DENIAL]` → `SCOPE`
- Response mentions Graph API 403 or `insufficient_scope` → `RESOURCE`

### Audit Log

The bottom of the main content area shows a collapsible audit log:
- **Columns**: #, Time, Prompt (truncated), Scope, HTTP Status, Denial Level, Latency
- **Expandable rows**: Click to see full request/response JSON
- **Copy JSON**: Export entire audit log to clipboard
- **Clear**: Reset the log

### Multi-Account Testing

To test different roles without signing out:

1. Sign in with your primary account (e.g., admin)
2. Click **Add Account** in the header
3. Sign in with a different account (e.g., viewer) via the popup
4. Use the account dropdown to switch between accounts
5. The Security Context Panel and RBAC Test Matrix update automatically

### Testing Walkthrough

#### Step 1: Verify Security Context
1. Sign in as an admin user
2. Check the Security Context Panel shows role=ADMIN (green badge)
3. Verify all 7 tool permissions show checkmarks
4. Confirm token expiry countdown is running

#### Step 2: Test Scope Differences
1. Open a "basic" tab → Ask "List my OneDrive files" → Expect scope denial
2. Open a "files" tab → Ask "List my OneDrive files" → Expect success
3. Compare the denial badges in both chat messages

#### Step 3: Run RBAC Matrix
1. Click "Run All" in the RBAC Test Matrix
2. Wait for all scenarios to complete
3. All rows should show PASS (green) — meaning the actual result matches the expected outcome
4. Check the Audit Log for detailed request/response data

#### Step 4: Test Role Restrictions
1. Switch to a viewer account (or sign in as viewer)
2. Verify Security Context shows role=VIEWER (yellow badge)
3. Only `get_user_profile` should have a checkmark
4. Run the RBAC Matrix — viewer-denied scenarios should show PASS (correctly denied)

#### Step 5: Inspect Tokens
1. Expand the Token Inspector
2. Verify `groups` claim contains your security group IDs
3. Verify `scp` claim shows the scopes for the current tab's scope preset
4. Check `aud` matches your app's client ID or `api://` URI

---

## Alternative: Using pip

If you prefer to use pip instead of uv:

### Create Virtual Environment

```bash
cd C:\WorkSpace\Sanjay\github\sts-entraid-single-a2a-adkagent-mcp-poc

# Create virtual environment
python -m venv venv

# Activate (Windows Command Prompt)
venv\Scripts\activate

# Activate (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Activate (Linux/macOS)
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Services

```bash
# Each in a separate terminal (after activating venv)
python mcp_server/server.py
python adk_agent/agent.py
python a2a_server/server.py
```

---

## Manual Dashboard Testing

For detailed manual testing of the Security Testing Dashboard with step-by-step procedures, role-specific expected results, and result recording instructions, see **[MANUAL_TESTING.md](./MANUAL_TESTING.md)**.

### Quick Start

1. Sign in as **admin** (AdeleV@2tdgcb.onmicrosoft.com)
2. Verify Security Context Panel shows green **ADMIN** badge with all 7 permissions checked
3. Click **Run All** in the RBAC Test Matrix
4. All rows should show **PASS** (green)
5. Switch to **developer** and **viewer** accounts and repeat

### Saving Test Results

Save results to `test_results/` in both formats:
- **Markdown**: `test_results/YYYY-MM-DD_<role>_manual.md` (copy checklist from MANUAL_TESTING.md)
- **JSON**: `test_results/YYYY-MM-DD_<role>_audit.json` (use Audit Log "Copy JSON" button)

See `test_results/README.md` for templates and JSON schema.

### Automated Security Dashboard Tests

```bash
# Full suite with HTML report
uv run pytest --html=reports/test_report.html --self-contained-html -v

# Only security dashboard tests (real Entra ID tokens required)
uv run pytest tests/test_security_dashboard.py -v

# Skip slow LLM pipeline tests (~3-4 min total)
uv run pytest tests/test_security_dashboard.py -m "not slow" -v

# Only mock-token tests (no real tokens needed)
uv run pytest tests/test_access_control.py -v
```

Set `TEST_ADMIN_TOKEN`, `TEST_DEVELOPER_TOKEN`, `TEST_VIEWER_TOKEN`, and `TEST_NOGROUP_TOKEN` in `.env` before running. See `.env.example` for instructions.

---

## Next Steps

After successful local testing:

1. Review the [CLAUDE.md](./CLAUDE.md) for development patterns and code conventions
2. Use the Security Testing Dashboard to verify role-based access control
3. Run the RBAC Test Matrix for each role (admin, developer, viewer)
4. Customize tool permissions in `mcp_server/server.py`
5. Add additional tools as needed
6. Configure production environment variables
