# MCP Multi-IdP: Identity Provider Comparison

## What All OIDC Providers Share

1. **Issue JWTs** — signed tokens with claims
2. **Expose discovery endpoint** — `/.well-known/openid-configuration` → JWKS URI, issuer
3. **Publish signing keys** — JWKS endpoint with RSA/EC public keys
4. **Standard claims** — `sub`, `iss`, `aud`, `exp`, `iat` are universal

## Detailed Comparison

| Concept | Entra ID | AWS Cognito | Auth0 |
|---------|----------|-------------|-------|
| **Email claim** | `preferred_username` or `unique_name` or `upn` | `email` | `email` |
| **Groups/roles** | `groups` claim (GUIDs) | `cognito:groups` (names) | Custom namespace or `permissions` |
| **Scopes claim** | `scp` (space-separated) | `scope` (space-separated) | `scope` or `permissions` |
| **User ID** | `oid` or `sub` | `sub` | `sub` |
| **Audience format** | `api://{client-id}` | User pool app client ID | Custom API identifier |
| **Issuer format** | `https://login.microsoftonline.com/{tenant}/v2.0` or `https://sts.windows.net/{tenant}/` | `https://cognito-idp.{region}.amazonaws.com/{poolId}` | `https://{domain}.auth0.com/` |
| **JWKS discovery** | Via OIDC discovery or direct URL | Via OIDC discovery | Via OIDC discovery |
| **Resource API** | Microsoft Graph API | No equivalent | Auth0 Management API |
| **Token exchange (OBO)** | Yes — native OBO flow | No OBO — use Identity Pools | No native OBO — use token exchange |
| **Frontend SDK** | MSAL.js (`@azure/msal-browser`) | Amplify or `amazon-cognito-identity-js` | Auth0 SPA SDK (`@auth0/auth0-spa-js`) |
| **Group limit in token** | ~150 (overage indicator) | No hard limit | Custom claims (you control) |
| **Group format** | GUIDs | String names | Custom namespace |

## FastMCP Verifier Configuration Per Provider

### Entra ID
```python
from fastmcp.server.auth.providers.azure import AzureJWTVerifier

AzureJWTVerifier(
    client_id="647e61a7-...",
    tenant_id="8f691e3d-...",
    required_scopes=["access_as_user"],
)
# Auto-configures: JWKS URI, issuer, audience
```

### AWS Cognito
```python
from fastmcp.server.auth.providers.jwt import JWTVerifier

JWTVerifier(
    jwks_uri="https://cognito-idp.us-east-1.amazonaws.com/{pool_id}/.well-known/jwks.json",
    issuer="https://cognito-idp.us-east-1.amazonaws.com/{pool_id}",
    audience="{app_client_id}",
)
```

### Auth0
```python
from fastmcp.server.auth.providers.jwt import JWTVerifier

JWTVerifier(
    jwks_uri="https://{domain}.auth0.com/.well-known/jwks.json",
    issuer="https://{domain}.auth0.com/",
    audience="{api_identifier}",
)
```

### Generic OIDC
```python
from fastmcp.server.auth.providers.jwt import JWTVerifier

# Any OIDC provider — just need JWKS URI, issuer, audience
JWTVerifier(
    jwks_uri="{discovery_url}/jwks",
    issuer="{issuer_url}",
    audience="{expected_audience}",
)
```

## Group Claim Differences

```
Entra ID token:
  "groups": ["72460602-5251-4f2e-a4f2-611476cc984c", "4baa4106-..."]
  → GUIDs, map to role names in permissions.toml

Cognito token:
  "cognito:groups": ["admins", "developers"]
  → String names, map directly in permissions.toml

Auth0 token:
  "https://myapp.com/roles": ["admin"]
  → Custom namespace, need to know the claim name
```

## Frontend SDK Comparison

| Feature | MSAL.js | Amplify | Auth0 SPA SDK |
|---------|---------|---------|---------------|
| Token acquisition | `acquireTokenSilent()` | `Auth.currentSession()` | `getTokenSilently()` |
| Popup login | `acquireTokenPopup()` | `Auth.federatedSignIn()` | `loginWithPopup()` |
| Redirect login | `acquireTokenRedirect()` | `Auth.federatedSignIn()` | `loginWithRedirect()` |
| Account switching | Built-in | Manual | Single account |
| Package | `@azure/msal-browser` | `aws-amplify` | `@auth0/auth0-spa-js` |

## Real-World Multi-IdP Scenarios

### One Company, Multiple IdPs
```
MegaCorp:
  Office workers → Entra ID (company SSO)
  Engineering → Cognito (AWS workloads)
  External contractors → Auth0 (separate identity)

Same user, different tokens, different issuers.
Match on EMAIL as universal identity anchor.
```

### SaaS Platform, Multi-Tenant
```
Your agent platform, multiple subscribers:
  Acme Corp → Entra ID (tenant A)
  Beta Inc → Cognito (AWS account B)
  Gamma Ltd → Auth0 (tenant C)

Each company's users call YOUR agent.
YOUR permission store maps email → role per tenant.
```
