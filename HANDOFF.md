# System Handoff — Identity-Aware AI Agent

A complete, self-contained description of what this repository currently does, how it does it, and where the seams are. Written so an engineer (or model) with no prior exposure can pick the system up and extend it without reverse-engineering the source first.

Everything below reflects the code as of branch `docs/system-handoff` (forked from `main` at `fc041d6`). Where the code and the older docs (`README.md`, `TESTING.md`) disagree, **this document follows the code**.

---

## 1. What the system is

A four-tier AI agent stack that carries a **human user's identity** from browser sign-in all the way down to the resource APIs the agent's tools call. The point of the project is the identity plumbing and the access control, not the agent's capabilities — the tools themselves (Graph profile, OneDrive listing, S3 browsing, timezone math) are deliberately mundane. They exist to be *denied* at different tiers so the denial can be observed.

Two identity providers are supported side by side: **Microsoft Entra ID** and **AWS Cognito**. The provider is detected per-token from the `iss` claim; nothing else in the stack is provider-aware except a handful of claim-name lookups.

Access control is enforced at three independent points, so a bypass at one tier is still caught by the next:

| Tier | Enforced in | What it checks | Denial looks like |
|---|---|---|---|
| **Agent** | A2A gateway middleware | JWT signature/issuer/audience/expiry, blocklist, group membership | HTTP 401/403 + JSON `denial_reason` |
| **Tool** | MCP server middleware + per-tool `auth=` callables | Token validity again (independently), role resolution, role→tool permission | `ToolError` string prefixed `[TOOL_DENIAL]` / `[ROLE_SELECTION]` |
| **Resource** | Microsoft Graph / AWS S3 | OAuth scopes on the Graph token; IAM policy on the AWS credential | Graph 403 / `insufficient_scope` / S3 `AccessDenied` |

---

## 2. Runtime topology

```
┌──────────────────┐   Bearer + X-Assume-Role    ┌──────────────────┐
│ React Frontend   │ ──────────────────────────▶ │ A2A Gateway      │
│ MSAL / Amplify   │      A2A JSON-RPC           │ FastAPI+a2a-sdk  │
│ :10003           │                             │ :10000           │
└──────────────────┘                             └────────┬─────────┘
                                                          │ HTTP  Bearer +
                                                          │ {user_id, session_id, role}
                                                          ▼
                                                 ┌──────────────────┐
                                                 │ ADK Agent        │
                                                 │ Google ADK       │
                                                 │ +LiteLLM/Bedrock │
                                                 │ :10001           │
                                                 └────────┬─────────┘
                                                          │ MCP streamable-HTTP
                                                          │ Bearer + X-Assume-Role
                                                          ▼
                                                 ┌──────────────────┐
                                                 │ FastMCP Server   │
                                                 │ 10 tools         │
                                                 │ :10002 (stateless)│
                                                 └────┬────────┬────┘
                                        OBO-exchanged │        │ server-side
                                          user token  │        │ AWS creds
                                                      ▼        ▼
                                          MS Graph API      AWS S3
```

Every hop is plain HTTP on localhost. There is no service mesh, no mTLS, no gateway in front. All four processes are started by hand (§10).

**Versions:** Python ≥3.10; `fastmcp>=3.0.0`, `google-adk>=1.25.0`, `a2a-sdk[http-server]>=0.3.20`, `litellm>=1.30.0`, `PyJWT>=2.8.0`, `azure-identity>=1.19.0`. Frontend: React 18, `@azure/msal-browser` ^3.6, `aws-amplify` ^6.16.

**LLM:** `bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0` via LiteLLM (`adk_agent/agent.py:158`). Authenticated with `AWS_BEARER_TOKEN_BEDROCK`, a **12-hour** token that must be regenerated — an expired one surfaces as a generic agent error, which is a common and confusing local failure.

---

## 3. Repository map

```
a2a_server/server.py     822 lines  Gateway: JWT validation, agent-tier ACL, A2A protocol, /me
adk_agent/agent.py       452 lines  ADK agent: sessions, MCP toolset wiring, LLM, streaming
mcp_server/server.py     845 lines  FastMCP: auth, middleware, 10 tools
mcp_server/graph_obo.py  113 lines  Entra On-Behalf-Of token exchange (singleton)
mcp_server/policy.py     134 lines  PolicyEvaluator ABC + TomlPolicyEvaluator
dev_config.py             56 lines  Shared auth-bypass config loader

frontend/src/
  AuthProvider.js              Unified useAuth() over MSAL + Amplify
  authConfig.js                MSAL config + scope presets
  cognitoConfig.js             Amplify config
  App.js / App.css             Dashboard shell (dark theme)
  components/
    AuthStatus.js              Multi-account switcher
    LoginPrompt.js             Provider selection + sign-in
    SecurityContextPanel.js    Role selector, groups, scopes, expiry countdown
    TokenInspector.js          JWT header/payload decoder (display only)
    ConversationTabs.js        Up to 4 chat tabs, each with its own scope preset
    ChatInterface.js           Chat + denial tagging + latency
    RBACTestMatrix.js          One-click test grid, pass/fail per scenario
    AuditLog.js                Request history incl. role + denial tier
    DenialIndicator.js         Color-coded denial badge
  utils/
    a2aClient.js               JSON-RPC call + buildAuditEntry()
    constants.js               A2A_SERVER_URL, PROVIDER_LABELS
    denialClassifier.js        Response → denial tier
    testScenarios.js           Predefined prompts + expected outcomes
    tokenDecoder.js            base64url JWT decode

tests/
  conftest.py                  271 lines  Mock-token fixtures, Cognito helpers
  test_access_control.py       399 lines  Three-tier ACL tests
  test_security_dashboard.py   658 lines  Dashboard/E2E tests (needs real tokens)

Config templates (all real files are gitignored):
  .env.example                 Backend env vars
  frontend/.env.example        Frontend env vars
  permissions.example.toml     Group→role mapping
  dev_config.example.toml      Per-server auth bypass

Docs:
  README.md (914)  TESTING.md (720)  MANUAL_TESTING.md (287)  CLAUDE.md  claude.md (stale duplicate)
  scratchpad/      Design notes from prior workstreams (multi-IdP, role switching, frontend testing)
  test_results/    Recorded manual test runs
```

---

## 4. End-to-end request trace

Follow one chat message from browser to Graph API. This is the single most important section; the rest of the document elaborates on it.

**1. Browser → A2A gateway.** `a2aClient.js:36` POSTs A2A JSON-RPC (`method: "message/send"`) to `http://localhost:10000/` with `Authorization: Bearer <idp-token>` and, if a role is selected in the UI, `X-Assume-Role: <role>`.

**2. A2A auth middleware** (`a2a_server/server.py:553`). Runs on every request except `OPTIONS` and `PUBLIC_PATHS` (`/health`, `/.well-known/agent-card.json`, `/.well-known/agent.json`, `/docs`, `/openapi.json`). It:
   - short-circuits to mock claims if `dev_config.toml` has `[a2a] disable_auth = true` (`:569`);
   - requires `Bearer ` prefix, then `TokenValidator.validate()` (`:191`) — decode-unverified to read `iss`, match against `IDP_CONFIGS`, fetch that IdP's JWKS, verify signature/issuer/audience/expiry;
   - rejects if `sub` ∈ `BLOCKED_USERS` → 403 `blocked_user`;
   - reads groups (`cognito:groups` for Cognito, `groups` for Entra) and requires at least one to be in the configured allowed set → else 403 `no_group_membership` (`:626`);
   - stashes the result in three `ContextVar`s: `current_user_claims`, `current_access_token`, `current_assumed_role` (`:637-639`).

**3. A2A executor** (`IdentityAwareAgentExecutor.execute`, `:313`). Reads the ContextVars, emits a `working` task event, then calls `_ensure_session()` (`:372`) which — if this `user_id` has no cached session — POSTs `/session` to the ADK agent with `{user_id, user_info: {email, name, groups, assumed_role}}` and the same Bearer token. Sessions are cached in a module-level `user_sessions` dict guarded by an `asyncio.Lock`. It then POSTs `/chat` with `{message, user_id, session_id, role}` (60s timeout) and wraps the reply in a `completed` task event.

**4. ADK agent** (`adk_agent/agent.py`). `/session` (`:363`) validates that the body's `user_id` matches the token's `sub` (`_validate_user_id`, `:343` — anti-impersonation) and creates an ADK session whose initial state carries the `user:`-prefixed keys: `user:access_token`, `user:email`, `user:name`, `user:groups`, `user:role`. `/chat` (`:399`) refreshes `access_token` and `role` in `session_service.user_state` on every call — that is how a token refresh or a role switch reaches an already-created session — then runs the LLM turn under `RunConfig(max_llm_calls=4)` with 3 retries on `RateLimitError` (30/60/90s backoff).

**5. ADK → MCP.** When the LLM calls a tool, `McpToolset` invokes `mcp_header_provider()` (`:99`), a **sync** function that reads the session state and returns `{"Authorization": "Bearer <token>", "X-Assume-Role": "<role>"}`. This is the only channel by which identity reaches the MCP server — there is no session there to hold it.

**6. MCP server** (`mcp_server/server.py`). FastMCP's built-in `MultiAuth` (`_build_auth`, `:126`) independently re-validates the token against the configured verifiers. Then `UserContextMiddleware` (`:191`) detects the provider, extracts the email, extracts groups, asks the policy evaluator for **all** roles the principal qualifies for, and reconciles that with `X-Assume-Role`:
   - `on_call_tool` is **strict**: no `X-Assume-Role` → `ToolError("[ROLE_SELECTION] …")`; an unavailable role → `[TOOL_DENIAL] Cannot assume role …`;
   - `on_list_tools` is **lenient**: falls back to the highest-priority available role so the tool list isn't empty.
   It sets four ContextVars: `current_user_token`, `current_user_role`, `current_user_email`, `current_user_provider` (`:284-287`).

**7. Per-tool authorization.** Each `@mcp.tool()` carries `auth=require_role(...)` (`:313`). The callable reads `current_user_role` and raises `[TOOL_DENIAL] Access denied: Role 'X' cannot use this tool` if it isn't in the allow-list. This doubles as **visibility** control — tools the role can't use are hidden from listing.

**8. Resource call.** For Graph tools, `_get_effective_graph_token()` (`:371`) asks `GraphOBOExchanger` to trade the user's custom-audience token for a Graph-scoped one, then calls `https://graph.microsoft.com/v1.0/...`. Graph itself enforces the OAuth scope — a token without `Mail.Send` gets a 403 back from Microsoft, which is the third tier. S3 tools skip the user token entirely and use the server's AWS credentials.

---

## 5. Identity in detail

### 5.1 Token validation happens twice, differently

The gateway and the MCP server each validate the token independently, using **different machinery**. This is intentional (defense in depth) but means a change to token handling must be made in both places.

**A2A gateway** — hand-rolled. `IdPConfig` dataclass (`:96`) + `TokenValidator` (`:149`):

| | Entra | Cognito |
|---|---|---|
| JWKS | 3 URIs tried in order: v2.0 discovery, v1.0 discovery, `common` | `{issuer}/.well-known/jwks.json` |
| Issuers accepted | `https://login.microsoftonline.com/{tenant}/v2.0` and `https://sts.windows.net/{tenant}/` | `https://cognito-idp.{region}.amazonaws.com/{pool}` |
| Audience claim | `aud` | **`client_id`** — non-standard, so PyJWT's `verify_aud` is disabled and the check is done by hand (`:242`) |
| Valid audiences | `{client_id}`, `api://{client_id}` | `{client_id}` |

JWKS responses are cached in a plain dict with **no TTL**. The only invalidation is: if the token's `kid` isn't found, clear the whole cache and retry once (`:215`).

**MCP server** — FastMCP's own verifiers (`_build_auth`, `:126`), composed with `MultiAuth`:
- `AzureJWTVerifier(client_id, tenant_id, required_scopes=["access_as_user"])` — Entra v2.0.
- `JWTVerifier(jwks_uri=…/discovery/keys, issuer=sts.windows.net/…, audience=[client_id, api://client_id], required_scopes=["access_as_user"])` — Entra v1.0 fallback.
- `JWTVerifier(jwks_uri=cognito jwks, issuer=cognito, required_scopes=["ai-agent-api/access_as_user"])` — Cognito, **audience deliberately omitted** because of the `client_id` quirk; `client_id` is instead checked inside the middleware (`:243`).

Note the `required_scopes` on all three: a token that reaches the MCP server without `access_as_user` (or the Cognito equivalent) is rejected by FastMCP before any middleware runs.

### 5.2 Provider detection

Duplicated in both servers (`a2a_server/server.py:710`, `mcp_server/server.py:75`) — a substring match on `iss`:

- `login.microsoftonline.com` or `sts.windows.net` → `entra`
- `cognito-idp` → `cognito`
- `auth0.com` → `auth0` (MCP only)
- otherwise → `unknown` (A2A) / `default` (MCP). The two servers disagree on the fallback string.

### 5.3 Claim extraction

Email, per provider (`mcp_server/server.py:67` `EMAIL_CLAIMS`; A2A has its own copy at `:720`):
- Entra: `preferred_username` → `unique_name` → `upn` → `email`
- Cognito: `email` (A2A also falls back to `cognito:username`)
- fallback: `sub`

Groups (`mcp_server/server.py:95`): `cognito:groups`, else `groups`, else — if `_claim_names.groups` is present (Entra's **group overage** indicator, emitted past ~150 groups) — log a warning and return `[]`. The Graph `/me/memberOf` call that would resolve overage is a documented `TODO`, not implemented. A user in >150 groups therefore silently loses all group-derived roles.

### 5.4 How identity propagates

Each tier moves the identity across a different transport. There is no shared library; the contract is by convention.

```
Browser
  Authorization: Bearer <token>          (HTTP header)
  X-Assume-Role: <role>                  (HTTP header)
    │
A2A gateway
  current_user_claims / current_access_token / current_assumed_role   (ContextVar)
    │
    │  POST /session  body: {user_id, user_info:{email,name,groups,assumed_role}}   + Bearer
    │  POST /chat     body: {message, user_id, session_id, role}                    + Bearer
    ▼
ADK agent
  session state, "user:" prefix:  user:access_token, user:role, user:email, user:name, user:groups
    │
    │  mcp_header_provider() → Authorization + X-Assume-Role       (HTTP header)
    ▼
MCP server (stateless_http=True — no session, so ContextVars only)
  current_user_token / current_user_role / current_user_email / current_user_provider
```

Two things worth internalizing:

- **The MCP server is stateless** (`stateless_http=True`, `server.py:844`). `ctx.get_state()` is unavailable; ContextVars set by the middleware are the *only* way tool functions see the caller. Anything a tool needs must be set there first.
- **`mcp_header_provider` is synchronous** and is called on every MCP request. It cannot await, so anything it needs (a fresh token, a role) must already be sitting in session state.

---

## 6. Authorization in detail

### 6.1 Role model

Three roles, fixed priority `admin > developer > viewer`, plus the implicit `none`.

| Tool | admin | developer | viewer | Backing resource |
|---|:--:|:--:|:--:|---|
| `get_user_profile` | ✅ | ✅ | ✅ | Graph `/me` (`User.Read`) |
| `list_files` | ✅ | ✅ | ❌ | Graph `/me/drive` (`Files.Read`) |
| `send_email` | ✅ | ❌ | ❌ | Graph `/me/sendMail` (`Mail.Send`) |
| `delete_resource` | ✅ | ❌ | ❌ | **simulated — logs only, deletes nothing** |
| `get_current_time` | ✅ | ❌ | ❌ | local `zoneinfo` |
| `convert_timezone` | ✅ | ❌ | ❌ | local `zoneinfo` |
| `get_time_difference` | ✅ | ❌ | ❌ | local `zoneinfo` |
| `list_s3_buckets` | ✅ | ✅ | ❌ | S3 (server creds) |
| `list_s3_objects` | ✅ | ✅ | ❌ | S3 (server creds) |
| `get_s3_object_info` | ✅ | ✅ | ✅ | S3 (server creds) |

The source of truth is the `auth=require_role(...)` argument on each `@mcp.tool()` in `mcp_server/server.py`. **This matrix is duplicated in three other places** and they must be kept in sync by hand:
- `a2a_server/server.py:683` `TOOL_ROLES` (+ `TOOL_SCOPES` at `:696`) — powers `GET /me`.
- `adk_agent/agent.py:59` `PERMISSION_MAP` — powers the `check_my_permissions` local tool.
- `frontend/src/utils/testScenarios.js` — expected outcomes in the RBAC matrix.

### 6.2 Where roles come from

**Agent tier (A2A)** maps groups → role from environment variables (`GROUP_TO_ROLE`, `:672`): `ADMIN_GROUP_ID` / `DEVELOPER_GROUP_ID` / `VIEWER_GROUP_ID` for Entra, plus the three `COGNITO_*_GROUP` names.

**Tool tier (MCP)** maps groups → role from **`permissions.toml`** (gitignored; template in `permissions.example.toml`), evaluated by `TomlPolicyEvaluator` (`mcp_server/policy.py:60`):

```toml
[group_rules.entra]
"<group-guid>" = "admin"

[group_rules.cognito]
"platform-admins" = "admin"

[users]                                  # optional per-user override, case-insensitive email
# "user@company.com" = { role = "admin" }

[defaults]
unknown_users = "none"
```

The file is **hot-reloaded** on mtime change — no restart needed after editing (`policy.py:71`). If it doesn't exist, nobody gets a role and every tool call is denied.

So the two tiers use two different stores for the same mapping (env vars vs. TOML). They are expected to agree; nothing enforces that they do.

### 6.3 Role selection (`X-Assume-Role`)

A user in several groups qualifies for several roles. Rather than always taking the highest, the system makes the caller **choose**, so privilege reduction is testable from the UI:

- Frontend sends `X-Assume-Role` (set by the dropdown in `SecurityContextPanel.js`).
- A2A stores it in `current_assumed_role` and forwards it in the `/session` and `/chat` bodies.
- ADK writes it to `user:role` and `mcp_header_provider` re-emits it as a header.
- MCP validates it against the roles the principal actually qualifies for, and **rejects a tool call that arrives without it** (`[ROLE_SELECTION]`).

`GET /me` on the gateway (`:762`) returns `available_roles`, the active role, groups, token scopes, expiry, and the full permission matrix for the active role — this is what drives the dashboard.

### 6.4 The `PolicyEvaluator` seam

`mcp_server/policy.py` defines an ABC (`get_available_roles`, `check_access`) with `AccessRequest` / `AccessDecision` dataclasses. `AccessRequest` already carries `claims: dict` — full JWT claims — specifically so an attribute-based (ABAC) or external engine (OPA, Cedar) can be dropped in without touching callers. `TomlPolicyEvaluator` is the only implementation today, and only `get_available_roles` is actually wired into the request path; `check_access` is defined but **not currently called** (the per-tool `require_role` callables do that job instead).

---

## 7. Resource access

### 7.1 Graph API via On-Behalf-Of

The frontend acquires a token whose audience is the app itself (`api://{ENTRA_CLIENT_ID}`), not Graph. To call Graph, the MCP server exchanges it: `GraphOBOExchanger` (`mcp_server/graph_obo.py:23`) wraps `azure.identity.aio.OnBehalfOfCredential`, keyed by a SHA-256 hash of the user assertion, with a **128-entry LRU** of credentials (each `OnBehalfOfCredential` is bound to one user's assertion, so they can't be shared).

Initialized as a module singleton via `init_obo_exchanger()` (`server.py:385`). It requires `ENTRA_CLIENT_SECRET`; **without that secret, OBO is silently disabled** and the system degrades:

| Tool | No OBO available |
|---|---|
| `get_user_profile` | Falls back to token claims, returns `{"source": "token_claims", "_obo_used": false}` |
| `list_files` | `{"error": "graph_api_unavailable", …}` |
| `send_email` | Graph rejects the wrong-audience token |
| any Graph tool, non-Entra user | `{"error": "provider_not_supported"}` (`_require_entra_provider`, `:359`) |

Every Graph tool response carries an `_obo_used` boolean so you can tell which path produced it. OBO failures are logged and swallowed (`graph_obo.py:73`) — they return `None`, never raise.

### 7.2 S3

S3 tools do **not** use the user's identity at all. They call boto3 with the server's own AWS credentials (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), wrapped in `asyncio.to_thread` by `_run_s3_operation` (`:517`), which normalizes `NoCredentialsError` / `ClientError` into error dicts. The user's role only gates *whether the tool may be invoked* (tier 2); AWS IAM gates *what the server may see* (tier 3). There is no per-user S3 authorization.

---

## 8. Frontend

Single-page dashboard, dark theme, built for demonstrating and testing the security model rather than for end users.

`AuthProvider.js` hides both IdPs behind one hook:

```javascript
const { provider, isAuthenticated, user, getAccessToken, login, logout, switchProvider } = useAuth();
```

The chosen provider persists in `localStorage`. `a2aClient.js` is the single egress point: it builds the JSON-RPC envelope, attaches `Authorization` and (conditionally) `X-Assume-Role`, measures latency, and hands the response to `classifyDenial()`.

`denialClassifier.js` sorts every response into one of four tiers — this is what colors the badges and populates the audit log:

1. HTTP 401/403 → **agent** (reads `denial_reason` from the body)
2. `[TOOL_DENIAL]` in the response text → **tool**
3. `[SCOPE_DENIAL]` in the response text → **scope** — *note: no server emits this marker any more.* Scope enforcement was deliberately moved out of the MCP tier and left to Graph, so this branch (`denialClassifier.js:41`) is unreachable and the scope tier is now only ever reached via rule 4.
4. Graph 403 / `insufficient_scope` / S3 errors → **resource**

Notable UI pieces: a **role selector** that re-issues `/me` and clears the RBAC matrix on change; **up to 4 conversation tabs**, each pinned to its own OAuth scope preset (from `authConfig.js`), so you can hold a least-privilege and an over-privileged session side by side; a **token inspector** that decodes the JWT locally; and an **RBAC test matrix** that fires the scenarios in `testScenarios.js` and marks each pass/fail against the expected outcome.

---

## 9. Configuration

All real config files are gitignored; every one has a committed `.example` template.

**`.env`** (backend). Entra: `ENTRA_CLIENT_ID`, `ENTRA_TENANT_ID`, `ENTRA_CLIENT_SECRET` (OBO). Cognito: `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID`, `COGNITO_REGION`, `COGNITO_{ADMIN,DEVELOPER,VIEWER}_GROUP`. ACL: `{ADMIN,DEVELOPER,VIEWER}_GROUP_ID`, `BLOCKED_USERS` (comma-separated `sub` values). Ports: `A2A_SERVER_PORT=10000`, `ADK_SERVER_PORT=10001`, `MCP_SERVER_PORT=10002`, `FRONTEND_PORT=10003`. AWS: `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_BEARER_TOKEN_BEDROCK`. Test tokens: `TEST_{ADMIN,DEVELOPER,VIEWER,NOGROUP}_TOKEN` (real tokens, ~1h life; tests skip when unset).

**`frontend/.env`**: `REACT_APP_ENTRA_CLIENT_ID`, `REACT_APP_ENTRA_TENANT_ID`, `REACT_APP_A2A_SERVER_URL`, and optional `REACT_APP_COGNITO_*`.

**`permissions.toml`**: group→role mapping for the MCP tier (§6.2). Hot-reloaded.

**`dev_config.toml`**: per-server auth bypass, loaded by the shared `dev_config.py`.

```toml
[a2a]
disable_auth = false
[adk]
disable_auth = false
[mcp]
disable_auth = false
default_role = "admin"          # identity assumed when bypassed
default_email = "dev@localhost"
default_provider = "entra"
```

When a section is bypassed, that server injects mock claims and the sentinel token `"dev-bypass-token"` (`dev_config.py:19`). Downstream code checks for that sentinel explicitly — e.g. `_get_graph_token` refuses to OBO-exchange it (`server.py:349`), and `_validate_user_id` skips the impersonation check (`agent.py:348`). Bypass is cached at first load, so **restart the server after editing**. Each bypassed server logs a loud warning banner.

---

## 10. Running it

Four terminals:

```bash
uv run python mcp_server/server.py     # :10002
uv run python adk_agent/agent.py       # :10001
uv run python a2a_server/server.py     # :10000
cd frontend && npm start               # :10003
```

Health checks: `GET :10000/health`, `GET :10001/health`, and `GET :10000/.well-known/agent-card.json` for A2A discovery (all unauthenticated).

Tests:

```bash
uv run pytest tests/test_access_control.py -v      # mock tokens, always runs
uv run pytest tests/ -v                            # dashboard tests need real TEST_*_TOKENs
```

Logs (all under `logs/`, created on startup): `a2a_server.log` (DEBUG), `adk_agent.log` (DEBUG), `mcp_server.log` (INFO).

---

## 11. API surface

**A2A gateway :10000**

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/` | Bearer | A2A JSON-RPC, `message/send` |
| GET | `/me` | Bearer | Security context: user, provider, active + available roles, groups, token scopes, expiry, permission matrix, tool→scope map |
| GET | `/.well-known/agent-card.json` | none | Agent card: 10 declared skills, `security: [{bearer: []}]` |
| GET | `/health` | none | |

Agent-tier denials (`_auth_error`, `:524`) return `{error, message, denial_level: "agent", denial_reason}`:

| Status | `denial_reason` |
|---|---|
| 401 | `missing_token`, `invalid_format`, `token_expired`, `validation_failed` |
| 403 | `blocked_user`, `no_group_membership`, `no_group_configuration` |

**ADK agent :10001** — `POST /session`, `POST /chat` (buffered), `POST /chat/stream` (SSE), `GET /health`. All except `/health` require Bearer.

**MCP server :10002** — `POST /mcp`, streamable HTTP, stateless. Tool errors are `ToolError` strings prefixed `[ROLE_SELECTION]` or `[TOOL_DENIAL]`.

---

## 12. Design assumptions baked into the code

These are not bugs; they are load-bearing premises. Anything that violates one of them will be rejected somewhere in the chain, and knowing where saves a lot of debugging.

1. **Every principal is a human end user.** The gateway requires a group claim (`no_group_membership`, `:626`), the MCP policy store resolves roles only from group claims or an email override, and email extraction assumes a user-shaped claim set (`preferred_username`, `upn`, `cognito:username`). A token that carries none of these has no path to a role.
2. **Every token is a delegated (user) token.** The OBO exchange in `graph_obo.py` needs a user assertion by definition. There is no app-only credential path to Graph.
3. **One agent, one gateway, one hop.** The A2A executor's only downstream is the local ADK agent (`ADK_SERVER_URL`, hardcoded to localhost). The agent card is static and advertises this server's own skills. Nothing in the code discovers, calls, or authenticates *to* another agent.
4. **The caller's token is the tool's token.** The token that arrives at the gateway is forwarded verbatim to the ADK agent and again to the MCP server; each tier re-validates the *same* JWT. There is no token exchange, downscoping, or re-minting between tiers — the sole exception is the Graph OBO swap at the very last hop.
5. **Sessions are keyed by user.** `user_sessions` (`a2a_server/server.py:274`) and ADK's `InMemorySessionService` are both keyed on `user_id` = the token's `sub`. Two concurrent principals with the same `sub` would share a session.
6. **Role is chosen by the caller, validated by the server.** `X-Assume-Role` is a request, not an assertion; the MCP middleware is what decides whether it's honored.

---

## 13. Known limitations and sharp edges

| # | Issue | Where | Consequence |
|---|---|---|---|
| 1 | Tool→role matrix duplicated in 4 places | MCP `auth=` / A2A `TOOL_ROLES` / ADK `PERMISSION_MAP` / frontend `testScenarios.js` | Silent drift; `/me` can promise a permission the MCP server denies |
| 2 | Group→role mapping lives in two stores | A2A env vars vs. MCP `permissions.toml` | Same drift risk across tiers |
| 3 | ADK's `GROUP_TO_ROLE` (`agent.py:50`) has **only Entra** group vars | `adk_agent/agent.py` | `_determine_role` returns `none` for Cognito users. Masked today because A2A always sends `assumed_role`, but a caller that omits it silently loses its role |
| 4 | JWKS cache has no TTL (A2A) | `server.py:155` | Rotated keys only refresh on a `kid` miss |
| 5 | `user_sessions` is an unbounded in-memory dict | `server.py:274` | Leaks per unique user; all sessions lost on restart |
| 6 | ADK session service is in-memory | `agent.py:122` | Same |
| 7 | Entra group overage (>150 groups) not resolved | `mcp_server/server.py:110` | Warns and returns `[]` → user loses all roles. `TODO` for the Graph `/me/memberOf` call |
| 8 | New `httpx.AsyncClient()` per request everywhere | all three servers | No connection pooling |
| 9 | No rate limiting on any endpoint | all | |
| 10 | `delete_resource` is simulated | `mcp_server/server.py:501` | Returns `{"status": "deleted"}` having deleted nothing |
| 11 | Frontend uses buffered `/chat`, not `/chat/stream` | `a2aClient.js` | The SSE endpoint exists and works but nothing calls it; responses appear all at once |
| 12 | `max_llm_calls=4` | `agent.py:190` | A turn needing >1 tool round-trip can be truncated |
| 13 | `AWS_BEARER_TOKEN_BEDROCK` expires every 12h | `.env` | Presents as an opaque agent error |
| 14 | CORS origin list hardcodes `:10003` alongside the env-var port | `server.py:499` | Changing `FRONTEND_PORT` alone leaves a stale entry |
| 15 | `policy.check_access()` defined but never called | `mcp_server/policy.py:120` | The ABAC entry point is dead code today |
| 16 | `claude.md` (lowercase) is a stale duplicate of `CLAUDE.md` | repo root | Two files, one is out of date |
| 17 | `_detect_provider` fallback differs between servers (`"unknown"` vs `"default"`) | both | Cosmetic, but a shared-code refactor must reconcile it |
| 18 | Frontend still classifies a `[SCOPE_DENIAL]` marker no server emits | `denialClassifier.js:41` | Dead branch; the "scope" tier is now only reachable via the Graph-403 path |

---

## 14. Extension points

If you need to change behavior, these are the intended seams — in rough order of how cleanly they're cut.

- **Policy / authorization logic** → implement `PolicyEvaluator` (`mcp_server/policy.py:42`) and swap the instance at `server.py:184`. `AccessRequest.claims` gives you the whole JWT, so ABAC is reachable without changing callers. `check_access` is already declared and unused — it's the intended home for anything richer than a role check.
- **A new identity provider** → add an `IdPConfig` in `_build_idp_configs()` (`a2a_server/server.py:110`), add a verifier in `_build_auth()` (`mcp_server/server.py:126`), add a branch to both `_detect_provider`s, add an entry to `EMAIL_CLAIMS`, and add a `[group_rules.<provider>]` table. Five touch points; there is no single registry.
- **A new tool** → `@mcp.tool(auth=require_role(...))` in `mcp_server/server.py`, then update the four duplicated matrices in §13 #1, and add it to `tool_filter` in `McpToolset` (`agent.py:139`) — a tool missing from that list is invisible to the LLM even if the MCP server exposes it.
- **A new auth predicate** → `require_role` (`mcp_server/server.py:313`) is just a closure returning `check(ctx: AuthContext) -> bool` that raises `ToolError` on denial. Any other `auth=` callable with that shape works.
- **Changing what identity reaches the tools** → the choke point is `UserContextMiddleware._resolve_context` (`:227`) and the four ContextVars it sets. Nothing downstream reads the raw token except the Graph tools.
- **Changing what the gateway forwards** → `IdentityAwareAgentExecutor._ensure_session` (`:372`) and `.execute` (`:313`) build the two JSON bodies sent to the ADK agent. Both are hand-rolled dicts; there's no schema.
- **Changing what the agent sends to MCP** → `mcp_header_provider` (`agent.py:99`). Sync, called per request, reads session state only.

---

## 15. Branch and history context

Current branch `docs/system-handoff`, cut from `main` @ `fc041d6` ("Merge pull request #1 from sanjay-sts/obo-graph-api"). `main` is clean.

Other branches in the repo, which indicate where prior work went and what may return:

| Branch | Subject |
|---|---|
| `obo-graph-api` (merged) | The Entra OBO exchange described in §7.1 |
| `multi-idp-mcp-auth` | Cognito as a second IdP; FastMCP `MultiAuth` |
| `abac-access-controls` | Attribute-based access control |
| `origin/feature/servicenow-obo-hybrid` | ServiceNow as an additional OBO resource |
| `origin/mcp-skills-as-resources-abac-rbac` | Exposing skills as MCP resources under ABAC/RBAC |
| `origin/test-integration-servicenow` | ServiceNow integration testing |
| `upgrade-deps-fastmcp3-adk126` | FastMCP 3.x / ADK 1.26 upgrade |
| `#10_local_testing` | Local testing setup |

`scratchpad/mcp-multiidp/` holds the design notes from the multi-IdP and role-switching work (requirements → design → implementation plan → test results), and `scratchpad/singleagent/` holds the original single-agent design. `test_results/` holds recorded manual runs. These are historical; where they contradict this document, this document is current.
