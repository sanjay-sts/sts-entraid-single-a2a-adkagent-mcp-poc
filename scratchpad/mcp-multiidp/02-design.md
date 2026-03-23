# MCP Multi-IdP: Architecture & Design

## How Trusted Provider Validation Works

FastMCP's `JWTVerifier` and `AzureJWTVerifier` provide the trust model:

```
Token arrives → FastMCP auth system
  1. Fetch JWKS from CONFIGURED provider endpoint (cached, auto-rotated)
  2. Validate JWT SIGNATURE against provider's public keys
  3. Check ISSUER matches configured trusted issuer
  4. Check AUDIENCE matches configured expected audience
  5. Check EXPIRY (not expired)
  → Only tokens signed by keys from trusted providers pass
  → Unknown issuers, forged signatures, wrong audiences → rejected
```

A `JWTVerifier(jwks_uri=X, issuer=Y, audience=Z)` creates a **trust anchor**.

`MultiAuth(verifiers=[...])` tries each configured verifier in order. If none accepts → rejected.

## Separation of Concerns

```
┌─────────────────────────────────────────────────────────┐
│  IdP's WORLD (not yours)                                 │
│  Scopes: User.Read, Files.Read (Microsoft defined)      │
│  Groups: GUIDs / names (org IT admin created)            │
│  Job: PROVE who this person is                           │
└─────────────────────────────────────────────────────────┘
              │ Token (proves identity)
              ▼
┌─────────────────────────────────────────────────────────┐
│  YOUR WORLD (you define this)                            │
│  Roles: admin, developer, viewer (you defined)          │
│  Group→Role mapping: permissions.toml (you manage)      │
│  Tool permissions: auth= callables (you enforce)        │
│  Job: DECIDE what they can do                            │
└─────────────────────────────────────────────────────────┘
```

## Component Architecture

```
Token (any IdP)
  │
  ▼
FastMCP Built-in Auth (AzureJWTVerifier / JWTVerifier / MultiAuth)
  │  Validates signature, issuer, audience, expiry
  │  Creates AccessToken with .claims, .token, .scopes
  ▼
UserContextMiddleware
  │  _detect_provider(claims)  → "entra", "cognito", "auth0"
  │  _extract_email(claims)    → provider-specific claim name
  │  _extract_groups(claims)   → handles Entra group overage
  │  policy_evaluator.get_available_roles(email, provider, groups)
  │  Validates X-Assume-Role header against available roles
  │  Sets ContextVars: current_user_role, current_user_email, current_user_token
  ▼
auth= callables (require_role)
  │  Reads current_user_role ContextVar
  │  Checks against tool's allowed roles
  ▼
Tool Function
  │  Reads ContextVars for email, token
  │  Executes tool logic
```

## Policy Evaluator Interface

Abstract interface that can be swapped for OPA or Cedar:

```
PolicyEvaluator (ABC)
  ├── get_available_roles(email, provider, groups) → list[str]
  └── check_access(AccessRequest, allowed_roles) → AccessDecision

TomlPolicyEvaluator (current)
  ├── Reads permissions.toml
  ├── Hot-reloads on file change
  └── RBAC: group rules → user overrides → default

OpaPolicyEvaluator (future)
  ├── Queries OPA sidecar HTTP API
  └── Full ABAC with Rego policies

CedarPolicyEvaluator (future)
  ├── Embedded cedar-py engine
  └── Entity-based policies with formal verification
```

## Data Flow: Role Selection

```
1. Token validated by FastMCP → AccessToken available
2. Middleware reads claims:
   email = "sanjay@company.com"
   provider = "entra" (from issuer)
   groups = ["72460602...", "4baa4106..."] (from claims or Graph API)

3. PolicyEvaluator resolves available roles:
   group_rules.entra: "72460602..." = "admin", "4baa4106..." = "developer"
   → available_roles = ["admin", "developer"]

4. User sends: X-Assume-Role: developer
   → Validated: "developer" is in available_roles ✓
   → current_user_role.set("developer")

5. Tool auth: require_role("admin")
   → current_user_role = "developer"
   → DENIED: "Role 'developer' cannot use this tool"

6. User sends: X-Assume-Role: admin
   → Validated: "admin" is in available_roles ✓
   → current_user_role.set("admin")
   → Tool auth passes ✓
```

## Provider Detection

| Issuer Pattern | Provider |
|----------------|----------|
| `login.microsoftonline.com` or `sts.windows.net` | `entra` |
| `cognito-idp.{region}.amazonaws.com` | `cognito` |
| `{domain}.auth0.com` | `auth0` |
| anything else | `default` |

## Email Claim Mapping

| Provider | Claims tried (in order) |
|----------|------------------------|
| entra | `preferred_username`, `unique_name`, `upn`, `email` |
| cognito | `email` |
| auth0 | `email` |
| default | `email`, `preferred_username`, `sub` |

## Group Overage (Entra ID)

| User groups | Token behavior |
|-------------|---------------|
| <150 | Groups in `groups` claim as array |
| >150 | No `groups` claim; `_claim_names.groups` points to Graph API URL |

Detection:
```python
if "groups" in claims:
    return claims["groups"]  # Normal
elif "_claim_names" in claims and "groups" in claims["_claim_names"]:
    # Overage! Log warning, fall back to user-level assignment
    return []
```

## RBAC vs ABAC Progression

| Stage | Mechanism | Config | Policy Engine |
|-------|-----------|--------|---------------|
| **Now** | RBAC | `permissions.toml` | `TomlPolicyEvaluator` |
| **Tier 2** | RBAC + per-tool policies | `permissions.toml` [policies] section | `TomlPolicyEvaluator` with policy checks |
| **Tier 3** | Full ABAC | OPA Rego / Cedar policies | `OpaPolicyEvaluator` or `CedarPolicyEvaluator` |

The `PolicyEvaluator` interface is the same at all tiers — only the implementation changes.

## What "Agent Owns Permissions" Means

```
BEFORE (IdP-dictated):
  Token scp: "User.Read" → require_scopes_from_token("User.Read") → allowed
  Token groups: ["72460602..."] → GROUP_TO_ROLE env var → role
  Problem: Cognito has no User.Read scope; Auth0 has different group format

AFTER (agent-owned):
  Token groups: [...] → permissions.toml group_rules → available roles
  User selects: X-Assume-Role: admin → require_role("admin") → allowed
  Works with ANY IdP that provides group claims
  IdP scopes (User.Read, Files.Read) removed from tool auth
```
