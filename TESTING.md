# Testing Documentation

This document provides step-by-step instructions for setting up and testing the Identity-Aware AI Agent System locally.

## Prerequisites

- Python 3.10+
- Node.js 18+
- [uv](https://docs.astral.sh/uv/) - Fast Python package installer (recommended)
- Microsoft Entra ID app registration (see [Entra ID Setup](#entra-id-app-registration-setup))
- Google API Key for Gemini (for ADK agent)

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
ENTRA_AUTHORITY=https://login.microsoftonline.com/your-tenant-id

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

# Google AI API Key (for ADK agent)
# Get from https://aistudio.google.com/app/apikey
GOOGLE_API_KEY=your-google-api-key
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

## Next Steps

After successful local testing:

1. Review the [claude.md](./claude.md) for development patterns
2. Customize tool permissions in `mcp_server/server.py`
3. Add additional tools as needed
4. Configure production environment variables
