# Identity-Aware AI Agent System — Executive Summary

## Overview

This project demonstrates a **secure, multi-tier AI agent system** where user identity propagates from frontend authentication through the AI agent layer down to resource APIs. It solves a critical gap in AI agent architectures: ensuring that when an AI agent acts on behalf of a user, it respects the user's identity, role, and attributes at every layer — not just at the front door.

The system supports **multiple Identity Providers** (Microsoft Entra ID and AWS Cognito), enforces access control at **three independent tiers** using the **Cedar policy engine**, and has been **tested end-to-end** with real IdP tokens, real AWS S3 operations, and real Microsoft Graph API calls.

**Status:** Fully functional POC — all security tiers validated with real infrastructure.

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Frontend   │────▶│  A2A Server │────▶│  ADK Agent  │────▶│  MCP Tools  │
│   (React)    │     │  (Gateway)  │     │  (Google)   │     │  (FastMCP)  │
│  Port 10003  │     │  Port 10000 │     │  Port 10001 │     │  Port 10002 │
└─────────────┘     └─────────────┘     └─────────────┘     └──────┬──────┘
       │                   │                   │                   │
  IdP Token          JWT Validation       User Context        Cedar Policies
  (Entra/Cognito)    + Group Check        + Session Mgmt      (RBAC + ABAC)
                                                                   │
                                                    ┌──────────────┼──────────────┐
                                                    ▼              ▼              ▼
                                              ┌──────────┐  ┌──────────┐  ┌──────────┐
                                              │ Graph API │  │  AWS S3  │  │ Time/    │
                                              │ (OBO)     │  │ (IAM)   │  │ Utility  │
                                              └──────────┘  └──────────┘  └──────────┘
```

**Key principle:** The user's identity (token, role, attributes) propagates through every tier. Each tier makes independent access control decisions — a failure at any tier blocks the request.

---

## Multi-IdP Authentication

The system authenticates users via two Identity Providers, with an architecture designed to support additional IdPs (Auth0, Google, etc.) without code changes.

| Provider | Protocol | Frontend SDK | Token Type | Use Case |
|----------|----------|-------------|------------|----------|
| Microsoft Entra ID | OAuth 2.0 + PKCE | MSAL.js 3.x | JWT access token | Enterprise users, Microsoft Graph API |
| AWS Cognito | OAuth 2.0 + PKCE | AWS Amplify 6 | JWT access token | AWS-native users, S3 operations |

**How it works:**

1. **Frontend** presents a unified login experience — user chooses Entra ID or Cognito
2. **Tokens** are standard JWTs validated at every tier using JWKS (public key verification) — no shared secrets
3. **Provider detection** is automatic from the token's `iss` (issuer) claim — the backend is IdP-agnostic
4. **Group-to-role mapping** is configured per provider in `permissions.toml` — Entra uses security group GUIDs, Cognito uses group names

---

## Authentication at Each Tier

### A2A Gateway (Agent-to-Agent Protocol)

The A2A server is the entry point. It validates JWT tokens from any supported IdP, checks group membership, and enforces a user blocklist. This is the coarsest access control — "is this a legitimate, non-blocked user in an authorized group?"

### ADK Agent (Google Agent Development Kit)

The ADK agent maintains user sessions and propagates identity context (access token, role, ABAC attributes) to MCP tools via dynamic HTTP headers. It uses Claude Haiku 4.5 on AWS Bedrock for LLM inference.

### MCP Tools (Model Context Protocol)

The MCP server hosts 11 tools and enforces fine-grained access control via **Cedar policies**. Each tool call is authorized by Cedar before execution. This is where RBAC and ABAC decisions happen.

---

## Three-Tier Access Control

Each tier makes independent decisions. A request can be denied at any level.

| Tier | Location | Mechanism | Denies When |
|------|----------|-----------|-------------|
| **1. Agent** | A2A Gateway | JWT validation, group membership, blocklist | Invalid token, no group, or blocked user |
| **2. Tool** | MCP Server | Cedar policy engine (RBAC + ABAC) | Role lacks permission, or ABAC attributes don't match |
| **3. Resource** | Graph API / S3 | OAuth scopes (Graph), IAM policies (S3) | Token missing scope, or IAM denies |

**Defense in depth:** Even if a user bypasses one tier (e.g., a valid token with wrong groups), the next tier catches it independently.

---

## RBAC: Role-Based Access Control

Three roles are mapped from IdP group memberships. Users explicitly select a role per request (least-privilege, similar to AWS AssumeRole).

### Tool Permission Matrix

| Tool | Admin | Developer | Viewer | External API |
|------|:-----:|:---------:|:------:|-------------|
| get_user_profile | Y | Y | Y | Microsoft Graph |
| list_files | Y | Y | - | Microsoft Graph |
| send_email | Y | - | - | Microsoft Graph |
| delete_resource | Y | - | - | Simulated |
| get_current_time | Y | - | - | None |
| convert_timezone | Y | - | - | None |
| get_time_difference | Y | - | - | None |
| list_s3_buckets | Y | Y | - | AWS S3 |
| list_s3_objects | Y | Y | - | AWS S3 |
| get_s3_object_info | Y | Y | Y | AWS S3 |
| **delete_s3_object** | **ABAC** | **ABAC** | **ABAC** | AWS S3 |

RBAC is enforced by Cedar policies (`cedar/policies/rbac.cedar`), replacing previously hardcoded role checks. Policies are version-controlled, human-readable, and hot-reloadable.

---

## ABAC: Attribute-Based Access Control

ABAC goes beyond roles — access depends on **user attributes** and **resource context**. The `delete_s3_object` tool demonstrates this:

**No RBAC role grants delete access.** Only users with the `archiver=true` custom attribute (from Cognito) can delete S3 objects, and only under the `archive/` path prefix.

### ABAC Decision Matrix

| User Attribute | S3 Path | Decision | Policy |
|---------------|---------|----------|--------|
| `archiver=true` | `archive/report.csv` | **ALLOW** | ABAC permit |
| `archiver=true` | `data/important.csv` | **DENY** | Wrong path |
| `archiver=true` | `protected/critical.csv` | **DENY** | Guardrail forbid |
| No archiver attribute | Any path | **DENY** | No matching permit |
| Admin role (no archiver) | Any path | **DENY** | RBAC excluded |

### How It Works

```
User request: "Delete archive/old-report.csv"
  │
  ├── Phase 1 (RBAC gate): No RBAC permit for delete_s3_object
  │   └── Phase 1 passthrough: ABAC-only tool, let Phase 2 decide
  │
  ├── Phase 2 (ABAC check): Cedar evaluates with context
  │   ├── principal.archiver == true?  ← from Cognito token claim
  │   ├── context.resource_path like "archive/*"?  ← from tool parameter
  │   └── NOT in "protected/*"?  ← guardrail check
  │
  └── Decision: ALLOW or DENY
```

**Guardrails** are Cedar `forbid` policies that override all permits — even if every other condition is met, deletion in `protected/` is always blocked.

---

## Testing & Validation

### Automated Tests

**31 Cedar policy tests** covering four test suites:

| Suite | Tests | Coverage |
|-------|:-----:|---------|
| RBAC Smoke | 5 | Admin/developer/viewer basic permissions |
| ABAC Scenarios | 5 | Archiver attribute + path combinations |
| File-Based Policies | 9 | Actual .cedar policy files |
| Evaluator Integration | 12 | Full stack: TOML roles → Cedar → decisions |

### End-to-End Test Results (Live Infrastructure)

| Test | User | IdP | Archiver | Path | Expected | Actual |
|------|------|-----|----------|------|----------|--------|
| Admin delete | AdeleV@ | Entra ID | None | archive/ | DENY (no archiver) | **DENY** |
| Developer delete root | archiver@test.com | Cognito | true | test-file-2.txt | DENY (wrong path) | **DENY** |
| Developer delete archive/ | archiver@test.com | Cognito | true | archive/test-file-1.txt | ALLOW | **ALLOW** |
| Verify deletion | archiver@test.com | Cognito | - | - | 5→4 objects | **Confirmed** |

**All three security tiers validated independently:**
- Tool tier (Cedar): Correctly allowed/denied based on attributes and path
- Resource tier (AWS IAM): Independently blocked until DeleteObject permission was added
- Agent tier (A2A): Token validation + group membership passed for both IdPs

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Frontend | React 18 + MSAL.js 3.6 + AWS Amplify 6 | Multi-IdP login, role selection, ABAC toggle, test matrix |
| A2A Gateway | FastAPI + a2a-sdk | Agent-to-Agent protocol, JWT validation, identity propagation |
| AI Agent | Google ADK + LiteLLM | Session management, tool orchestration, streaming |
| LLM | Claude Haiku 4.5 (AWS Bedrock) | Natural language understanding, tool selection |
| MCP Tools | FastMCP 3.x (stateless HTTP) | 11 tools with per-tool Cedar authorization |
| Authorization | Cedar (cedarpy) | RBAC + ABAC policy engine, schema-validated, hot-reload |
| Identity | Microsoft Entra ID + AWS Cognito | OAuth 2.0 / OIDC, JWT tokens, group claims |
| Resources | Microsoft Graph API + AWS S3 | User profile, files, email, cloud storage |

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Policy engine | Cedar (not OPA) | In-process evaluation, readable policies, ABAC-native, AWS-backed |
| Multi-IdP | Provider-agnostic design | Enterprise reality: different teams use different IdPs |
| Role selection | Explicit per-request (X-Assume-Role) | Least-privilege principle, like AWS AssumeRole |
| ABAC-only for delete | No RBAC role grants delete | Demonstrates pure attribute-based control, clean separation |
| Token propagation | Bearer token at every tier | Each tier validates independently — defense in depth |
| Policy storage | Git (`.cedar` files) | Version control, code review, CI validation |

---

## Next Steps & Future Improvements

### Near-Term

| Item | Business Value |
|------|---------------|
| Group overage resolution (Entra ID >150 groups) | Required for large enterprise deployments |
| Streaming chat responses | Better user experience (progressive rendering) |
| Connection pooling (httpx) | Improved latency and resource efficiency |
| ADK agent IdP cleanup | Simplify codebase, remove redundant role logic |

### Medium-Term

| Item | Business Value |
|------|---------------|
| Permission management API | Self-service admin UI replaces manual TOML editing |
| Database-backed policy store | Audit trail, dynamic updates without Git commits |
| Additional IdPs (Auth0, Google) | Broader enterprise compatibility |

### Long-Term

| Item | Business Value |
|------|---------------|
| Agent-to-agent authentication (mTLS) | Secure multi-agent orchestration |
| Multi-tenant platform | Per-tenant IdP config, permission isolation |
| OpenFGA for relationships | Sharing, delegation, nested ownership models |
| OPA for platform guardrails | K8s admission, service mesh, CI/CD compliance |
