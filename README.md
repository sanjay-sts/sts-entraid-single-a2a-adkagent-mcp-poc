# Identity-Aware AI Agent System

A secure, multi-tier AI agent system where user identity propagates from frontend authentication through the agent layer down to resource APIs.

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  React Frontend │───▶│   A2A Server    │───▶│   Google ADK    │───▶│   FastMCP       │
│  (MSAL.js)      │    │   (Gateway)     │    │   Agent         │    │   Tools         │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
        │                      │                      │                      │
        │  Entra ID Token      │  Token Validation    │  User Context        │  Token Access
        │  (Authorization)     │  + Agent-Level ACL   │  + Tool-Level ACL    │  + Resource ACL
        ▼                      ▼                      ▼                      ▼
   ┌─────────────────────────────────────────────────────────────────────────────────────┐
   │                              Microsoft Graph API                                      │
   │                         (Resource-Level Scope Enforcement)                           │
   └─────────────────────────────────────────────────────────────────────────────────────┘
```

## Three-Tier Security Model

| Level | Location | Mechanism | Denies Access When |
|-------|----------|-----------|-------------------|
| **Agent** | A2A Server | Group membership, blocklist | User blocked or not in allowed group |
| **Tool** | FastMCP | Role-based permissions | User role lacks tool permission |
| **Resource** | Graph API | OAuth scopes | Token missing required scope |

## Prerequisites

- Python 3.10+
- Node.js 18+
- Microsoft Entra ID tenant with app registration
- Google Cloud account with Gemini API access

## Setup

### 1. Microsoft Entra ID Configuration

1. Create an app registration in [Microsoft Entra admin center](https://entra.microsoft.com)
2. Configure Single-page application redirect URIs:
   - `http://localhost:10003`
   - `http://localhost:10003/redirect`
3. Add API permissions: `openid`, `profile`, `User.Read`, `Files.Read`, `Mail.Send`
4. Enable group claims in Token configuration
5. Create security groups for Admin, Developer, and Viewer roles

### 2. Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# - ENTRA_CLIENT_ID: Your app registration client ID
# - ENTRA_TENANT_ID: Your directory tenant ID
# - ADMIN_GROUP_ID, DEVELOPER_GROUP_ID, VIEWER_GROUP_ID: Security group Object IDs
# - GOOGLE_API_KEY: Your Google AI API key
```

### 3. Backend Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 4. Frontend Setup

```bash
cd frontend
npm install

# Copy environment template
cp .env.example .env
# Edit .env with your Entra ID configuration
```

## Running the Application

Start each service in a separate terminal:

```bash
# Terminal 1: MCP Server (Tools)
python mcp_server/server.py

# Terminal 2: ADK Agent
python adk_agent/agent.py

# Terminal 3: A2A Gateway
python a2a_server/server.py

# Terminal 4: Frontend
cd frontend && npm start
```

The application will be available at:
- Frontend: http://localhost:10003
- A2A Gateway: http://localhost:10000
- ADK Agent: http://localhost:10001
- MCP Server: http://localhost:10002

## Testing

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests (with services running)
pytest tests/test_access_control.py -v
```

## Role Permissions

| Role | get_user_profile | list_files | send_email | delete_resource |
|------|-----------------|------------|------------|-----------------|
| admin | Yes | Yes | Yes | Yes |
| developer | Yes | Yes | No | No |
| viewer | Yes | No | No | No |

## Project Structure

```
├── a2a_server/
│   └── server.py          # A2A gateway with auth middleware
├── adk_agent/
│   └── agent.py           # Google ADK agent with MCP integration
├── mcp_server/
│   └── server.py          # FastMCP tools with token validation
├── frontend/
│   ├── src/
│   │   ├── App.js         # Main React component
│   │   ├── authConfig.js  # MSAL configuration
│   │   └── index.js       # MSAL provider setup
│   └── package.json
├── tests/
│   └── test_access_control.py
├── .env.example
├── requirements.txt
├── README.md
└── claude.md              # Development guide
```

## Documentation

- [FastMCP Documentation](https://gofastmcp.com)
- [Google ADK Documentation](https://google.github.io/adk-docs/)
- [A2A Protocol Specification](https://github.com/a2aproject/A2A)
- [MSAL.js Documentation](https://learn.microsoft.com/en-us/entra/msal/overview)

## License

MIT
