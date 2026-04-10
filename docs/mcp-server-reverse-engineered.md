# MCP Server — Reverse Engineering Guide

A deep-dive into how the FastMCP server is built, how Cedar enforces RBAC and ABAC authorization, and how the supporting files (policies, entities, permissions, OBO exchange) fit together.

---

## 1. MCP Server Overview

**File:** `mcp_server/server.py` (956 lines)

The MCP server is built with the [FastMCP](https://github.com/jlowin/fastmcp) framework, running as a stateless HTTP service.

### Server Configuration

```python
# server.py:948-955
mcp = FastMCP(name="Identity-Aware MCP Server", auth=_build_auth())
mcp.add_middleware(UserContextMiddleware(policy_evaluator))

mcp.run(
    transport="streamable-http",
    host="0.0.0.0",
    port=10002,           # MCP_SERVER_PORT env var
    path="/mcp",          # Endpoint: http://localhost:10002/mcp
    stateless_http=True,  # No server-side session — everything per-request
)
```

### Key Design Choices

| Choice | Why |
|--------|-----|
| `stateless_http=True` | No server-side session state. Every request carries its own auth context via headers. ContextVars provide per-request isolation. |
| `streamable-http` transport | Modern MCP transport over standard HTTP POST |
| `MultiAuth` | Accepts tokens from multiple Identity Providers (Entra ID + Cognito) |
| `UserContextMiddleware` | Sits between token validation and tool execution — resolves roles, sets ContextVars |

### Authentication Setup (`_build_auth()`)

```
server.py:117-170

Entra ID:
  ├── AzureJWTVerifier (v2.0 tokens) — auto-configures JWKS, issuer, audience
  └── JWTVerifier (v1.0 fallback) — handles sts.windows.net issuer tokens

Cognito:
  └── JWTVerifier — User Pool JWT validation (audience omitted; client_id validated in middleware)

Result: MultiAuth([entra_v2, entra_v1, cognito])
```

### ContextVars — Per-Request Auth State

Six `ContextVar` declarations provide async-safe, per-request auth propagation:

```python
# server.py:36-41
current_user_token    # The raw JWT string
current_user_role     # The assumed role ("admin", "developer", "viewer")
current_user_email    # Extracted email
current_user_provider # "entra", "cognito", "auth0"
current_user_groups   # List of IdP group IDs/names
current_user_claims   # Full JWT claims dict (with ABAC attrs merged in)
```

These are set by `UserContextMiddleware` and read by `require_cedar()`, `cedar_check_with_context()`, and tool functions.

---

## 2. The 11 MCP Tools

Every tool is decorated with `@mcp.tool(auth=require_cedar("tool_name"))`, which wires Cedar authorization into FastMCP's auth pipeline.

### Tool Inventory

| # | Tool | Category | Cedar Auth | Role Access | Description |
|---|------|----------|------------|-------------|-------------|
| 1 | `get_user_profile` | Graph API | `require_cedar` | admin, developer, viewer | Fetch Microsoft Graph user profile |
| 2 | `list_files` | Graph API | `require_cedar` | admin, developer | List files in user's OneDrive |
| 3 | `send_email` | Graph API | `require_cedar` | admin only | Send email via Microsoft Graph |
| 4 | `delete_resource` | Admin | `require_cedar` | admin only | Delete a resource (simulated) |
| 5 | `list_s3_buckets` | S3 | `require_cedar` | admin, developer | List all accessible S3 buckets |
| 6 | `list_s3_objects` | S3 | `require_cedar` | admin, developer | List objects in an S3 bucket |
| 7 | `get_s3_object_info` | S3 | `require_cedar` | admin, developer, viewer | Get S3 object metadata |
| 8 | `delete_s3_object` | S3 (ABAC) | `require_cedar` + Phase 2 | archiver attr only | Delete S3 object (ABAC-controlled) |
| 9 | `get_current_time` | Utility | `require_cedar` | admin only | Get current time in any timezone |
| 10 | `convert_timezone` | Utility | `require_cedar` | admin only | Convert time between timezones |
| 11 | `get_time_difference` | Utility | `require_cedar` | admin only | Time difference between two zones |

### Tool Categories Explained

**Graph API Tools** (tools 1-3): Call Microsoft Graph API on behalf of the user. Require Entra ID provider (non-Entra users get `provider_not_supported` error). Use OBO token exchange when available (see Section 8).

**S3 Tools** (tools 5-8): Use server-side AWS credentials (not user tokens). Wrapped in `_run_s3_operation()` which runs boto3 calls via `asyncio.to_thread()` for async compatibility.

**ABAC Tool** (tool 8 — `delete_s3_object`): The only tool using two-phase authorization. Phase 1 always passes through (ABAC-only), Phase 2 checks `archiver=true` attribute + `archive/*` path.

**Utility/Admin Tools** (tools 4, 9-11): Administrative tools that don't require external API calls.

---

## 3. Cedar Authorization — How It Works

### What is Cedar?

[Cedar](https://www.cedarpolicy.com/) is an open-source policy language by AWS. Policies are evaluated in-process via the `cedarpy` Python package. Cedar uses three types of policy effects:

- **`permit`** — Grants access when conditions are met
- **`forbid`** — Denies access when conditions are met (**always overrides permit**)
- **Default deny** — If no permit matches, access is denied

### The Cedar Directory (`cedar/`)

```
cedar/
├── schema.cedarschema     # Entity type definitions
├── entities.json          # Static entity instances (roles + tools)
└── policies/
    ├── rbac.cedar         # Role-based permits
    ├── abac.cedar         # Attribute-based permits
    └── guardrails.cedar   # Forbid guardrails (override all permits)
```

### 3.1 Schema (`cedar/schema.cedarschema`)

Defines the authorization model in the `AgentAuth` namespace:

```cedar
namespace AgentAuth {

  // Principals
  entity Role;                        // Role entity for hierarchy
  entity User in [Role] {             // User inherits from Role
    provider: String,                 // "entra", "cognito"
    email: String,
    groups: Set<String>,              // IdP group IDs from token
    department?: String,              // Optional ABAC attribute
    archiver?: Bool,                  // Optional ABAC attribute
  };

  // Resources
  entity Tool {
    sensitivity?: String,             // "public", "internal", "confidential"
    requires_provider?: String,       // "entra" for Graph tools, "" for any
  };
  entity S3Folder;                    // Future use: path-based resources

  // Actions
  action call_tool appliesTo {
    principal: [User],
    resource: [Tool],
    context: {
      resource_path?: String,         // S3 key, OneDrive path
      environment?: String,           // "dev", "staging", "prod"
    },
  };
  action list_tools appliesTo { ... };
}
```

**Key design:** `User in [Role]` enables role hierarchy. A user with `parents: [Role::"developer"]` satisfies `principal in AgentAuth::Role::"developer"` in policies.

### 3.2 Static Entities (`cedar/entities.json`)

Contains 13 static entities (3 roles + 10 tools). **User entities are NOT here** — they are built dynamically at request time.

**Roles:**
```json
{ "uid": { "__entity": { "type": "AgentAuth::Role", "id": "admin" } } }
{ "uid": { "__entity": { "type": "AgentAuth::Role", "id": "developer" } } }
{ "uid": { "__entity": { "type": "AgentAuth::Role", "id": "viewer" } } }
```

**Tools (example):**
```json
{
  "uid": { "__entity": { "type": "AgentAuth::Tool", "id": "delete_s3_object" } },
  "attrs": { "sensitivity": "confidential", "requires_provider": "" }
}
```

Each tool has `sensitivity` (public/internal/confidential) and `requires_provider` (entra or empty for any provider).

### 3.3 RBAC Policies (`cedar/policies/rbac.cedar`)

Role-based permits using Cedar's entity hierarchy:

```cedar
// Admin: all tools EXCEPT delete_s3_object
permit(
  principal in AgentAuth::Role::"admin",
  action == AgentAuth::Action::"call_tool",
  resource
) when {
  resource != AgentAuth::Tool::"delete_s3_object"
};

// Developer: 5 specific tools
permit(
  principal in AgentAuth::Role::"developer",
  action == AgentAuth::Action::"call_tool",
  resource
) when {
  resource == AgentAuth::Tool::"get_user_profile" ||
  resource == AgentAuth::Tool::"list_files" ||
  resource == AgentAuth::Tool::"list_s3_buckets" ||
  resource == AgentAuth::Tool::"list_s3_objects" ||
  resource == AgentAuth::Tool::"get_s3_object_info"
};

// Viewer: 2 tools only
permit(
  principal in AgentAuth::Role::"viewer",
  ...
) when {
  resource == AgentAuth::Tool::"get_user_profile" ||
  resource == AgentAuth::Tool::"get_s3_object_info"
};

// All users can discover tools
permit(principal, action == AgentAuth::Action::"list_tools", resource);
```

**Note:** `delete_s3_object` is deliberately excluded from ALL RBAC permits. It is ABAC-only.

### 3.4 ABAC Policy (`cedar/policies/abac.cedar`)

Single attribute-based permit for `delete_s3_object`:

```cedar
permit(
  principal,
  action == AgentAuth::Action::"call_tool",
  resource == AgentAuth::Tool::"delete_s3_object"
) when {
  principal has archiver &&
  principal.archiver == true &&
  context has resource_path &&
  context.resource_path like "archive/*"
};
```

**Key points:**
- **Role is irrelevant** — admin, developer, viewer all need `archiver=true`
- **Path-restricted** — only `archive/*` prefix allowed
- **Attribute source** — `archiver` comes from JWT custom claims (Cognito token customization or Entra optional claims)

### 3.5 Guardrail Policy (`cedar/policies/guardrails.cedar`)

Forbid policy — the ultimate safety net:

```cedar
forbid(
  principal,
  action == AgentAuth::Action::"call_tool",
  resource == AgentAuth::Tool::"delete_s3_object"
) when {
  context has resource_path &&
  context.resource_path like "protected/*"
};
```

**Cedar rule:** `forbid` always overrides `permit`. Even a user with `archiver=true` cannot delete in `protected/`. No exceptions.

### 3.6 Role Access Summary

```
Tool                    admin   developer   viewer   archiver attr
─────────────────────   ─────   ─────────   ──────   ─────────────
get_user_profile          Y         Y          Y
list_files                Y         Y
send_email                Y
delete_resource           Y
list_s3_buckets           Y         Y
list_s3_objects           Y         Y
get_s3_object_info        Y         Y          Y
delete_s3_object                                          Y (archive/* only)
get_current_time          Y
convert_timezone          Y
get_time_difference       Y
```

---

## 4. Two-Phase Authorization Pattern

This is the core authorization design. Tool access is checked in two phases:

### Phase 1: RBAC Check (Decorator Level)

**Where:** `require_cedar()` function — `server.py:355-376`
**When:** Before the tool function executes (FastMCP calls the auth callable)

```python
def require_cedar(tool_name: str):
    def check(ctx: AuthContext) -> bool:
        decision = policy_evaluator.check_access(_build_access_request(tool_name))
        if not decision.allowed:
            if tool_name in _ABAC_ONLY_TOOLS:     # {"delete_s3_object"}
                return True                        # Pass through to Phase 2
            raise ToolError(f"[TOOL_DENIAL] Access denied: {decision.reason}")
        return True
    return check
```

**How it works:**
1. Reads ContextVars (email, role, groups, claims) via `_build_access_request()`
2. Calls `policy_evaluator.check_access()` — Cedar evaluates **without runtime context**
3. If denied AND tool is ABAC-only → **passthrough** (let Phase 2 decide)
4. If denied AND tool is NOT ABAC-only → raise `ToolError` (hard deny)

### Phase 2: ABAC Check (Inside Tool Function)

**Where:** `cedar_check_with_context()` — `server.py:379-385`
**When:** Inside the tool function body, with actual runtime data

```python
# Inside delete_s3_object tool (server.py:721-723):
decision = cedar_check_with_context("delete_s3_object", {"resource_path": key})
if not decision.allowed:
    return {"error": "abac_denied", "message": f"[TOOL_DENIAL] {decision.reason}"}
```

**How it works:**
1. Same `_build_access_request()` but **with context** (e.g., `resource_path: "archive/file.txt"`)
2. Cedar re-evaluates with full context → ABAC policy checks `archiver` attribute + path
3. Guardrail policy checks `protected/*` path (forbid overrides)
4. Returns `AccessDecision` — tool handles denial (returns error dict, doesn't raise)

### Why Two Phases?

```
Standard tool (e.g., list_files):
  Phase 1: Cedar checks "can developer call list_files?" → YES → tool runs
  (No Phase 2 needed)

ABAC tool (delete_s3_object):
  Phase 1: Cedar checks "can developer call delete_s3_object?" → NO (no RBAC permit)
  BUT: tool is in _ABAC_ONLY_TOOLS → PASSTHROUGH
  Phase 2: Cedar checks "can this user (archiver=true) delete archive/old.txt?" → YES
  Phase 2: Cedar checks "can this user (archiver=true) delete protected/secret.txt?" → NO (forbid)
```

Without the passthrough, ABAC-only tools would always be denied at Phase 1 because the ABAC policy needs runtime context (the `resource_path`) which doesn't exist yet.

### Authorization Flow Diagram

```
Request arrives at MCP Server
        │
        ▼
┌─────────────────────────┐
│  FastMCP MultiAuth      │  JWT signature, issuer, audience, expiry
│  (Token Validation)     │
└────────┬────────────────┘
         │ token.claims
         ▼
┌─────────────────────────┐
│  UserContextMiddleware  │  Provider detection, email/groups extraction,
│  (_resolve_context)     │  role resolution, X-Assume-Role validation,
│                         │  X-Abac-Attrs merge, set 6 ContextVars
└────────┬────────────────┘
         │ ContextVars set
         ▼
┌─────────────────────────┐
│  Phase 1: require_cedar │  Cedar RBAC check (no context)
│  (auth callable)        │  Standard tools: deny or allow
│                         │  ABAC-only tools: passthrough
└────────┬────────────────┘
         │ passed
         ▼
┌─────────────────────────┐
│  Tool Function Executes │
│                         │
│  (ABAC tools only):     │
│  Phase 2: cedar_check   │  Cedar ABAC check (with context)
│  _with_context()        │  archiver + path check + guardrails
└────────┬────────────────┘
         │
         ▼
      Response
```

---

## 5. CedarPolicyEvaluator Internals (`mcp_server/policy.py`)

**File:** `mcp_server/policy.py` (380 lines)

### Class Hierarchy

```
PolicyEvaluator (ABC)
├── TomlPolicyEvaluator    — Group-to-role mapping from permissions.toml
└── CedarPolicyEvaluator   — Cedar policy evaluation (composes TomlPolicyEvaluator)
```

### Data Structures

```python
@dataclass
class AccessRequest:
    email: str              # User's email
    provider: str           # "entra", "cognito", "auth0"
    groups: list[str]       # IdP group IDs/names
    tool_name: str          # MCP tool being called
    claims: dict            # Full JWT claims (for ABAC)
    assumed_role: str = ""  # Role selected via X-Assume-Role
    context: dict = {}      # Cedar context (resource_path, environment)

@dataclass
class AccessDecision:
    allowed: bool           # True = access granted
    role: str               # Resolved role (for logging)
    reason: str             # Human-readable denial reason
```

### CedarPolicyEvaluator — How `check_access()` Works

```python
# policy.py:265-326
def check_access(self, request: AccessRequest) -> AccessDecision:
    self._load()  # Hot-reload policies/entities if files changed

    # 1. Resolve roles via TOML (group → role mapping)
    roles = self.get_available_roles(request.email, request.provider, request.groups)

    # 2. Enforce assumed role (only grant the selected role)
    if request.assumed_role and request.assumed_role in roles:
        effective_roles = [request.assumed_role]
    else:
        effective_roles = roles

    # 3. Build dynamic User entity
    user_entity = self._build_user_entity(
        request.email, request.provider, request.groups,
        effective_roles, request.claims
    )

    # 4. Merge static entities (roles + tools) + dynamic user entity
    entities = self._entities + [user_entity]

    # 5. Build Cedar authorization request
    cedar_request = {
        "principal": f'AgentAuth::User::"{request.email}"',
        "action": 'AgentAuth::Action::"call_tool"',
        "resource": f'AgentAuth::Tool::"{request.tool_name}"',
        "context": request.context,
    }

    # 6. Evaluate Cedar policies
    result = is_authorized(request=cedar_request, policies=self._policies, entities=entities)
    return AccessDecision(allowed=result.allowed, ...)
```

### Dynamic User Entity Construction

User entities are built **at request time** from JWT claims + resolved roles:

```python
# policy.py:221-257
def _build_user_entity(self, email, provider, groups, roles, claims):
    attrs = {
        "provider": provider,
        "email": email,
        "groups": groups,
    }

    # Extract ABAC attributes from JWT claims
    for claim_key, expected_type in ABAC_CLAIM_KEYS.items():
        if claim_key in claims:
            value = claims[claim_key]
            # Handle Cognito boolean-as-string: "true" → True
            if expected_type is bool and isinstance(value, str):
                value = value.lower() == "true"
            attrs[claim_key] = value

    return {
        "uid": {"__entity": {"type": "AgentAuth::User", "id": email}},
        "attrs": attrs,
        "parents": [
            {"__entity": {"type": "AgentAuth::Role", "id": role}}
            for role in roles  # ← Role hierarchy connection
        ],
    }
```

**ABAC Claim Keys** (what gets extracted from JWT):

```python
ABAC_CLAIM_KEYS = {
    "department": str,    # Custom JWT claim
    "archiver": bool,     # Custom JWT claim — controls delete_s3_object access
}
```

### Hot-Reload Mechanism

Cedar policies and entities are reloaded when files change on disk:

```python
# policy.py:175-219
def _load_policies(self):
    cedar_files = sorted(policies_dir.glob("*.cedar"))
    max_mtime = max(f.stat().st_mtime for f in cedar_files)
    if max_mtime == self._policy_mtime:
        return  # No changes — skip reload
    # ... concatenate all .cedar files into self._policies string

def _load_entities(self):
    mtime = entities_path.stat().st_mtime
    if mtime == self._entities_mtime:
        return  # No changes
    # ... reload entities.json
```

No server restart needed. Edit a `.cedar` file or `entities.json`, and the next request picks up the changes.

### Batch Evaluation (`check_access_batch`)

Used by the A2A server's `/me` endpoint to check all 11 tools at once:

```python
# policy.py:328-379
def check_access_batch(self, email, provider, groups, tool_names, claims, assumed_role=""):
    # Build user entity ONCE
    # Build 11 Cedar requests
    # Call is_authorized_batch() ONCE (instead of 11 individual calls)
    # Return {tool_name: allowed} dict
```

---

## 6. Permissions File — Role Resolution (`permissions.toml`)

**Template:** `permissions.example.toml` (copy to `permissions.toml`, which is gitignored)

**Used by:** `TomlPolicyEvaluator` (composed inside `CedarPolicyEvaluator`)

### Structure

```toml
# PRIMARY: Group-to-role mapping (per Identity Provider)
[group_rules.entra]
"72460602-5251-4f2e-a4f2-611476cc984c" = "admin"      # Entra group GUID → role
"4baa4106-f6bf-4a10-9324-39f487b3eb6d" = "developer"
"cde4fa16-7717-44e5-a502-ce2a17ef4385" = "viewer"

[group_rules.cognito]
"platform-admins" = "admin"         # Cognito group name → role
"platform-developers" = "developer"
"platform-viewers" = "viewer"

[group_rules.auth0]
# "admin" = "admin"                 # Future use

# OPTIONAL: Direct user overrides (for exceptions)
[users]
# "sanjay@company.com" = { role = "admin" }

# FALLBACK: Default role for unmatched users
[defaults]
unknown_users = "none"              # "none" means no access
```

### Resolution Logic (`TomlPolicyEvaluator.get_available_roles()`)

```
1. GROUP MAPPING (primary):
   For each group in user's token claims:
     Look up in group_rules[provider] → add matching role

2. USER OVERRIDE (secondary):
   Look up email (case-insensitive) in [users] → add role

3. DEFAULT (tertiary):
   If no roles matched → use defaults.unknown_users
   If "none" → return empty list (no access)

4. SORT by priority: admin > developer > viewer
   Return: ["admin", "developer"] (highest first)
```

### How Roles Become Cedar Entities

The resolved roles are passed to `_build_user_entity()` which creates the `parents` array:

```
permissions.toml: "platform-admins" = "admin"
        ↓
TomlPolicyEvaluator: roles = ["admin"]
        ↓
_build_user_entity: parents = [{"__entity": {"type": "AgentAuth::Role", "id": "admin"}}]
        ↓
Cedar: principal in AgentAuth::Role::"admin" → TRUE
```

### ABAC Attributes Are NOT in This File

ABAC attributes (`archiver`, `department`) come from JWT custom claims, not from `permissions.toml`. They are configured in:
- **Entra ID:** App Registration > Token Configuration > Optional Claims
- **Cognito:** User Pool > Triggers > Pre Token Generation Lambda

---

## 7. UserContextMiddleware — Request Processing

**File:** `mcp_server/server.py:181-331`

### Two Modes of Operation

| Hook | Mode | When Role Missing |
|------|------|-------------------|
| `on_list_tools()` | Lenient | Auto-selects highest-priority role |
| `on_call_tool()` | Strict | Raises `ToolError` requiring `X-Assume-Role` |

### Complete Resolution Flow (`_resolve_context()`)

```
1. GET TOKEN
   token = get_access_token()  ← From FastMCP's validated auth
   If no token → raise ToolError (strict) or return defaults (lenient)

2. DETECT PROVIDER
   provider = detect_provider(token.claims)  ← Check 'iss' claim
   "login.microsoftonline.com" → "entra"
   "cognito-idp" → "cognito"
   "auth0.com" → "auth0"

3. COGNITO CLIENT_ID VALIDATION (manual — Cognito uses client_id not aud)
   if provider == "cognito": validate token.claims.client_id == COGNITO_CLIENT_ID

4. EXTRACT EMAIL
   _extract_email(claims, provider)
   Entra: preferred_username → unique_name → upn → email
   Cognito: email
   Fallback: sub

5. EXTRACT GROUPS
   _extract_groups(claims)
   Cognito: cognito:groups claim
   Entra: groups claim (with overage detection for >150 groups)

6. RESOLVE ROLES
   available_roles = policy_evaluator.get_available_roles(email, provider, groups)
   Returns sorted list: ["admin", "developer"] (highest first)

7. VALIDATE X-ASSUME-ROLE HEADER
   If header present: must be in available_roles → else ToolError
   If header absent + strict mode: raise ToolError (require selection)
   If header absent + lenient mode: use available_roles[0]

8. SET CONTEXTVARS
   current_user_token.set(token.token)
   current_user_email.set(email)
   current_user_role.set(assumed_role)
   current_user_provider.set(provider)
   current_user_groups.set(groups)

9. MERGE X-ABAC-ATTRS INTO CLAIMS
   abac_attrs = parse_abac_attrs(headers.get("x-abac-attrs", ""))
   claims.update(abac_attrs)  ← Header overrides token claims
   current_user_claims.set(claims)
```

### Dev Bypass Mode (`_set_bypass_context()`)

When `dev_config.toml` has `[mcp] disable_auth = true`:

```python
# server.py:198-239
- Sets mock email from dev_config.toml (default: "dev@localhost")
- Sets mock provider (default: "entra")
- Respects X-Assume-Role and X-Abac-Attrs header overrides
- Builds mock claims with ABAC attributes from config + headers
- Logs "AUTH BYPASSED" warning
```

---

## 8. Graph OBO Token Exchange (`mcp_server/graph_obo.py`)

**File:** `mcp_server/graph_obo.py` (114 lines)

### What It Does

OBO (On-Behalf-Of) exchanges the user's custom-audience JWT (`api://{CLIENT_ID}`) for a Microsoft Graph-scoped token. This allows MCP tools to call Graph API **as the user** — not as the application.

### Why It's Needed

The user's token has audience `api://{CLIENT_ID}` (custom API). Graph API requires tokens with audience `https://graph.microsoft.com`. OBO bridges this gap.

### Architecture

```
User's JWT (audience: api://CLIENT_ID)
        │
        ▼
GraphOBOExchanger.get_graph_token()
        │
        ├── Get/create OnBehalfOfCredential (cached by assertion hash)
        ├── credential.get_token("https://graph.microsoft.com/.default")
        │
        ▼
Graph-scoped token (audience: https://graph.microsoft.com)
        │
        ▼
Graph API call (GET /me, GET /me/drive, POST /me/sendMail)
```

### GraphOBOExchanger Class

```python
class GraphOBOExchanger:
    def __init__(self, tenant_id, client_id, client_secret):
        self._credentials = {}  # LRU cache, max 128 entries
        self._max_cache = 128

    def _get_credential(self, user_assertion):
        cache_key = sha256(user_assertion)
        if cache_key not in self._credentials:
            # Evict oldest if at capacity
            self._credentials[cache_key] = OnBehalfOfCredential(
                tenant_id, client_id, client_secret, user_assertion
            )
        return self._credentials[cache_key]

    async def get_graph_token(self, user_assertion, scopes=None):
        credential = self._get_credential(user_assertion)
        token = await credential.get_token(*scopes)
        return token.token  # or None on failure
```

### Singleton Pattern

```python
# Module-level singleton
_exchanger: GraphOBOExchanger | None = None

def init_obo_exchanger():     # Called once at server startup
    # Requires: ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET
    _exchanger = GraphOBOExchanger(tenant_id, client_id, client_secret)

def get_obo_exchanger():      # Returns singleton or None
    return _exchanger
```

### Token Fallback Chain

When Graph API tools execute, they use `_get_effective_graph_token()`:

```python
# server.py:428-435
async def _get_effective_graph_token(scope):
    graph_token = await _get_graph_token([scope])    # Try OBO first
    effective_token = graph_token or current_user_token.get()  # Fallback to original
    return effective_token, graph_token is not None   # (token, obo_used)
```

```
Priority:
1. OBO-exchanged Graph token (if ENTRA_CLIENT_SECRET is set + Entra user)
2. Original user token (may lack Graph scopes → Graph API returns error)
3. Token claims fallback (for get_user_profile only — shows email/role from JWT)
```

### When OBO Is Unavailable

| Scenario | Behavior |
|----------|----------|
| `ENTRA_CLIENT_SECRET` not set | OBO disabled at startup, tools use original token |
| Non-Entra user (Cognito/Auth0) | `_require_entra_provider()` returns error before token exchange |
| OBO exchange fails | Returns None, falls back to original token, logs warning |
| Dev bypass mode | `DEV_BYPASS_TOKEN` sentinel → OBO skipped |

---

## 9. How Everything Connects — End-to-End Request

```
USER BROWSER (React + MSAL.js)
  │
  │  POST http://localhost:10000/
  │  Authorization: Bearer <JWT>
  │  X-Assume-Role: developer
  │  X-Abac-Attrs: {"archiver": true}
  │
  ▼
A2A SERVER (port 10000)
  ├── TokenValidator: JWKS validation
  ├── auth_middleware: blocklist + group check
  ├── Sets ContextVars
  └── POST http://localhost:10001/session + /chat
        │
        ▼
ADK AGENT (port 10001)
  ├── Creates session: user:access_token, user:role, user:abac_attrs
  ├── LLM decides to call MCP tool
  └── mcp_header_provider() builds headers from session state
        │
        │  POST http://localhost:10002/mcp
        │  Authorization: Bearer <JWT>
        │  X-Assume-Role: developer
        │  X-Abac-Attrs: {"archiver": true}
        │
        ▼
MCP SERVER (port 10002)
  ├── FastMCP MultiAuth: JWT validation
  ├── UserContextMiddleware:
  │     ├── detect_provider() → "cognito"
  │     ├── _extract_email() → "user@example.com"
  │     ├── _extract_groups() → ["platform-developers"]
  │     ├── get_available_roles() → ["developer"]
  │     ├── validate X-Assume-Role → "developer" OK
  │     ├── parse X-Abac-Attrs → {"archiver": true}
  │     └── Set 6 ContextVars
  │
  ├── Phase 1: require_cedar("delete_s3_object")
  │     ├── _build_access_request() from ContextVars
  │     ├── Cedar evaluates (no context) → DENIED (no RBAC permit)
  │     ├── tool in _ABAC_ONLY_TOOLS → PASSTHROUGH
  │     └── return True
  │
  ├── Tool function: delete_s3_object(bucket, key="archive/old.txt")
  │     ├── Phase 2: cedar_check_with_context("delete_s3_object", {"resource_path": "archive/old.txt"})
  │     ├── Cedar evaluates with context:
  │     │     ├── ABAC policy: archiver=true + archive/* → PERMIT
  │     │     ├── Guardrail: not protected/* → no forbid
  │     │     └── Result: ALLOWED
  │     └── s3.delete_object(Bucket=bucket, Key=key)
  │
  └── Response: {"status": "deleted", "key": "archive/old.txt"}
```
