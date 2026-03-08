# MCP Multi-IdP: Requirements

## Problem Statement

The MCP server has ~130 lines of custom JWT validation code (`TokenValidationMiddleware`) hardwired to Microsoft Entra ID — manual JWKS fetching, signature verification, issuer/audience checks, group-to-role mapping. This needs to support multiple identity providers while ensuring trusted provider verification.

## Core Requirements

### R1: Trusted Provider Verification
- Only accept tokens from **configured, trusted providers**
- Validate JWT **signature** against the provider's JWKS (not just decode)
- Verify **issuer** matches a configured provider
- Verify **audience** matches expected values
- Reject tokens from unknown/unconfigured providers

### R2: Multi-IdP Support
- Support Microsoft Entra ID (current)
- Architecture ready for AWS Cognito, Auth0, generic OIDC
- Adding a new IdP should be config + verifier addition, not a rewrite

### R3: Agent-Owned Permissions
- Group-to-role mapping is the **primary** mechanism
- Managed by the agent in `permissions.toml`, not dictated by any IdP
- User-level overrides optional (for exceptions like demoting a user)
- Resolution order: group rules → user overrides → default

### R4: Explicit Role Selection
- Users must **explicitly select** which role to assume (like AWS AssumeRole)
- No auto-assumption of highest/lowest privilege
- Available roles determined from group membership via policy evaluator
- Invalid role selection → denied with list of available roles

### R5: Policy Engine Interface (Future-Ready)
- Abstract `PolicyEvaluator` interface for access control decisions
- Current implementation: TOML-based RBAC (`TomlPolicyEvaluator`)
- Swappable for OPA (Open Policy Agent) or AWS Cedar without changing callers
- `AccessRequest` dataclass carries all attributes for ABAC extensibility

### R6: Group Overage Handling
- Entra ID limits groups in tokens to ~150
- Detect overage indicator (`_claim_names.groups`) in token
- Log warning, fall back to user-level role assignment
- Production TODO: call Graph API `/me/memberOf` for full group list

### R7: Scope Isolation — MCP Server Only
- Don't touch A2A server, ADK agent, or frontend
- They pass tokens through — adapt later
- MCP server is where tool permissions live

### R8: Dev Bypass Compatibility
- When `is_auth_disabled("mcp")` is true, bypass all auth
- Same `dev_config.toml` mechanism as currently implemented
- Bypass skips both token validation and role selection

## Non-Requirements (Explicitly Out of Scope)

- OBO (On-Behalf-Of) token exchange for Graph API
- Frontend IdP selector UI
- A2A server multi-IdP support
- Database-backed permission store
- Real-time group overage resolution via Graph API
- OAuth proxy for MCP Inspector auto-login
