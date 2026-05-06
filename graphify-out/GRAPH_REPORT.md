# Graph Report - .  (2026-05-05)

## Corpus Check
- 57 files · ~76,574 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 677 nodes · 1354 edges · 38 communities detected
- Extraction: 69% EXTRACTED · 31% INFERRED · 0% AMBIGUOUS · INFERRED: 426 edges (avg confidence: 0.59)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Cedar Policy Engine|Cedar Policy Engine]]
- [[_COMMUNITY_MCP Multi-IdP Design Docs|MCP Multi-IdP Design Docs]]
- [[_COMMUNITY_Project Architecture Docs|Project Architecture Docs]]
- [[_COMMUNITY_Access Control Tests|Access Control Tests]]
- [[_COMMUNITY_Security Dashboard Tests|Security Dashboard Tests]]
- [[_COMMUNITY_A2A Gateway & Auth|A2A Gateway & Auth]]
- [[_COMMUNITY_Frontend Auth & Dashboard|Frontend Auth & Dashboard]]
- [[_COMMUNITY_ADK Agent Layer|ADK Agent Layer]]
- [[_COMMUNITY_Cedar Evaluator Internals|Cedar Evaluator Internals]]
- [[_COMMUNITY_MCP Tool Implementations|MCP Tool Implementations]]
- [[_COMMUNITY_Cedar ABAC Frontend Tests|Cedar ABAC Frontend Tests]]
- [[_COMMUNITY_Graph OBO Token Exchange|Graph OBO Token Exchange]]
- [[_COMMUNITY_Frontend A2A Client|Frontend A2A Client]]
- [[_COMMUNITY_AuditLog Component|AuditLog Component]]
- [[_COMMUNITY_DenialIndicator Component|DenialIndicator Component]]
- [[_COMMUNITY_Singleton 19|Singleton 19]]
- [[_COMMUNITY_Singleton 20|Singleton 20]]
- [[_COMMUNITY_Singleton 21|Singleton 21]]
- [[_COMMUNITY_Singleton 22|Singleton 22]]
- [[_COMMUNITY_Singleton 23|Singleton 23]]
- [[_COMMUNITY_Singleton 24|Singleton 24]]
- [[_COMMUNITY_Singleton 25|Singleton 25]]
- [[_COMMUNITY_Singleton 26|Singleton 26]]
- [[_COMMUNITY_Singleton 27|Singleton 27]]
- [[_COMMUNITY_Singleton 28|Singleton 28]]
- [[_COMMUNITY_Singleton 29|Singleton 29]]
- [[_COMMUNITY_Singleton 30|Singleton 30]]
- [[_COMMUNITY_Singleton 31|Singleton 31]]
- [[_COMMUNITY_Singleton 32|Singleton 32]]
- [[_COMMUNITY_Singleton 33|Singleton 33]]
- [[_COMMUNITY_Singleton 34|Singleton 34]]
- [[_COMMUNITY_Singleton 35|Singleton 35]]
- [[_COMMUNITY_Singleton 36|Singleton 36]]
- [[_COMMUNITY_Singleton 37|Singleton 37]]
- [[_COMMUNITY_Singleton 38|Singleton 38]]
- [[_COMMUNITY_Singleton 39|Singleton 39]]
- [[_COMMUNITY_Singleton 40|Singleton 40]]
- [[_COMMUNITY_Singleton 41|Singleton 41]]

## God Nodes (most connected - your core abstractions)
1. `CedarPolicyEvaluator` - 91 edges
2. `TomlPolicyEvaluator` - 87 edges
3. `AccessRequest` - 74 edges
4. `AccessDecision` - 64 edges
5. `PolicyEvaluator` - 36 edges
6. `make_a2a_message()` - 22 edges
7. `_user_entity()` - 21 edges
8. `TestCedarPolicyEvaluator` - 20 edges
9. `a2a_message()` - 17 edges
10. `MCP Multi-IdP Frontend Testing Strategy` - 16 edges

## Surprising Connections (you probably didn't know these)
- `Identity-Aware Access Control (HTML doc)` --semantically_similar_to--> `Three-Tier Access Control Model`  [INFERRED] [semantically similar]
  docs/identity-aware-access-control.html → claude.md
- `Identity-Aware Access Control (HTML doc)` --semantically_similar_to--> `Executive Summary: Multi-tier AI Agent System`  [INFERRED] [semantically similar]
  docs/identity-aware-access-control.html → EXECUTIVE_SUMMARY.md
- `Cedar ABAC Test Matrix (Section 6b)` --semantically_similar_to--> `ABAC Decision Matrix (delete_s3_object)`  [INFERRED] [semantically similar]
  MANUAL_TESTING.md → EXECUTIVE_SUMMARY.md
- `POC Demo Scenario (Archiver Developer)` --semantically_similar_to--> `ABAC Decision Matrix (delete_s3_object)`  [INFERRED] [semantically similar]
  scratchpad/cedar-abac/00-prerequisites.md → EXECUTIVE_SUMMARY.md
- `Deferred Items (OPA, OpenFGA, AVP)` --semantically_similar_to--> `Future Improvements Roadmap`  [INFERRED] [semantically similar]
  scratchpad/cedar-abac/00-prerequisites.md → EXECUTIVE_SUMMARY.md

## Hyperedges (group relationships)
- **Three-Tier Defense-in-Depth Authorization Flow** — claude_md_a2a_server, claude_md_mcp_server, claude_md_cedar_authorization, claude_md_three_tier_access_control, exec_summary_defense_in_depth [EXTRACTED 0.95]
- **X-Abac-Attrs Header Propagation Chain (Frontend to Cedar)** — claude_md_react_frontend, claude_md_a2a_server, claude_md_adk_agent, claude_md_mcp_server, claude_md_x_abac_attrs, scratchpad_02_x_abac_attrs_design [EXTRACTED 0.95]
- **Cedar Design-to-Implementation Pipeline** — scratchpad_00_problem, scratchpad_01_functional_requirements, scratchpad_02_cedar_schema_design, scratchpad_03_implementation_plan, scratchpad_04_test_strategy [EXTRACTED 0.95]
- **Multi-IdP MCP Lifecycle: Requirements -> Design -> Plan -> Test -> Results** — mcp_multiidp_01_requirements, mcp_multiidp_02_design, mcp_multiidp_03_implementation_plan, mcp_multiidp_04_testing_strategy, mcp_multiidp_07_test_results [EXTRACTED 0.95]
- **Frontend Role Switching End-to-End: Plan -> Strategy -> Results** — mcp_multiidp_08_role_switching_plan, mcp_multiidp_09_frontend_testing, mcp_multiidp_10_frontend_results, frontend_manual_2026_03_18 [EXTRACTED 0.90]
- **ABAC Attribute Propagation Stack (Frontend->A2A->ADK->MCP->Cedar)** — cedar_abac_05_propagation_chain, cedar_abac_05_archiver_paths, cedar_abac_05_components_modified, cedar_abac_05_eight_scenarios [EXTRACTED 0.90]

## Communities

### Community 0 - "Cedar Policy Engine"
Cohesion: 0.06
Nodes (89): ABC, AccessDecision, AccessRequest, CedarPolicyEvaluator, check_access(), get_available_roles(), PolicyEvaluator, Policy evaluator for tool access control.  Implements a PolicyEvaluator interf (+81 more)

### Community 1 - "MCP Multi-IdP Design Docs"
Cohesion: 0.03
Nodes (90): Frontend Manual Test Results 2026-03-18 (Admin), Problem: 130 lines of custom Entra-only JWT validation, R1 Trusted Provider Verification, R2 Multi-IdP Support, R3 Agent-Owned Permissions, R4 Explicit Role Selection, R5 Policy Engine Interface, R6 Group Overage Handling (+82 more)

### Community 2 - "Project Architecture Docs"
Cohesion: 0.03
Nodes (86): A2A Gateway Server (port 10000), Google ADK Agent (port 10001), Cedar Authorization Engine, ContextVar-based Auth Propagation, Denial Classification (4-tier), FastMCP Server (port 10002), Multi-IdP Support (Entra + Cognito), OBO Token Exchange (Microsoft Graph) (+78 more)

### Community 3 - "Access Control Tests"
Cohesion: 0.06
Nodes (66): a2a_url(), adk_url(), admin_token(), cognito_admin_token(), cognito_developer_token(), cognito_viewer_token(), create_cognito_test_token(), developer_token() (+58 more)

### Community 4 - "Security Dashboard Tests"
Cohesion: 0.08
Nodes (60): extract_agent_text(), make_a2a_message(), Factory for creating A2A JSON-RPC message/send request bodies., Extract text from an A2A JSON-RPC response.      Handles both:       - result, _assert_denial(), _assert_success(), Security Dashboard tests with real Entra ID tokens.  These tests validate the, Validate the GET /me endpoint returns correct security context. (+52 more)

### Community 5 - "A2A Gateway & Auth"
Cohesion: 0.08
Nodes (29): AgentExecutor, detect_provider(), get_section(), is_auth_disabled(), _load_config(), parse_abac_attrs(), Development configuration loader for auth bypass.  Reads dev_config.toml (giti, Check if auth is disabled for the given server section. (+21 more)

### Community 6 - "Frontend Auth & Dashboard"
Cohesion: 0.08
Nodes (16): App(), AuthProvider(), ensureAmplifyConfigured(), ensureMsalReady(), EntraAuthInner(), getMsalInstance(), useAuth(), AuthStatus() (+8 more)

### Community 7 - "ADK Agent Layer"
Cohesion: 0.1
Nodes (24): chat(), chat_stream(), create_session(), _extract_bearer_token(), health(), IdentityAwareAgent, mcp_header_provider(), _parse_chat_request() (+16 more)

### Community 8 - "Cedar Evaluator Internals"
Cohesion: 0.09
Nodes (9): Load Cedar policies + static entities. Hot-reload on file change., Concatenate all .cedar files from policies/ directory., Load static entities (roles, tools) from entities.json., Build a Cedar User entity from JWT claims + resolved roles.          The `pare, Delegate to TomlPolicyEvaluator — role resolution stays TOML-based., Evaluate Cedar policies for access decision.          Cedar policies define wh, Evaluate Cedar policies for multiple tools in one batch call.          Resolve, Return ALL roles the user qualifies for, ordered by priority. (+1 more)

### Community 9 - "MCP Tool Implementations"
Cohesion: 0.21
Nodes (23): _build_access_request(), _build_auth(), cedar_check_with_context(), convert_timezone(), delete_resource(), delete_s3_object(), _extract_email(), _extract_groups() (+15 more)

### Community 10 - "Cedar ABAC Frontend Tests"
Cohesion: 0.11
Nodes (20): Two paths archiver reaches Cedar (token + header), Archiver Toggle Interaction Matrix, Cognito IdP Prerequisites for archiver, Frontend Components Modified for ABAC, getScenariosForRole Decision Logic, Denial Tier Reference (AGENT/TOOL/SCOPE/RESOURCE), 8 ABAC Test Scenarios, Cedar ABAC Frontend Testing Strategy (+12 more)

### Community 11 - "Graph OBO Token Exchange"
Cohesion: 0.17
Nodes (10): get_obo_exchanger(), GraphOBOExchanger, init_obo_exchanger(), On-Behalf-Of (OBO) token exchange for Microsoft Graph API.  Exchanges the user, Get the module-level OBO exchanger, or None if not initialized., Exchanges user assertion tokens for Graph-scoped tokens via OBO flow., Get or create a cached credential for this user assertion., Exchange user token for a Graph-scoped token.          Args:             user (+2 more)

### Community 12 - "Frontend A2A Client"
Cohesion: 0.36
Nodes (5): buildAuditEntry(), extractResponseText(), sendA2AMessage(), classifyDenial(), matchesAny()

### Community 13 - "AuditLog Component"
Cohesion: 0.67
Nodes (2): AuditLog(), truncate()

### Community 14 - "DenialIndicator Component"
Cohesion: 0.67
Nodes (1): DenialIndicator()

### Community 19 - "Singleton 19"
Cohesion: 1.0
Nodes (1): Return ALL roles the user qualifies for (from groups + user overrides).

### Community 20 - "Singleton 20"
Cohesion: 1.0
Nodes (1): Check if the user can access a tool.          Args:             request: The

### Community 21 - "Singleton 21"
Cohesion: 1.0
Nodes (1): Request without token returns 401.

### Community 22 - "Singleton 22"
Cohesion: 1.0
Nodes (1): Request with invalid token returns 401.

### Community 23 - "Singleton 23"
Cohesion: 1.0
Nodes (1): User in BLOCKED_USERS list cannot access agent.

### Community 24 - "Singleton 24"
Cohesion: 1.0
Nodes (1): User without any allowed group cannot access agent.

### Community 25 - "Singleton 25"
Cohesion: 1.0
Nodes (1): User in allowed group can access agent.

### Community 26 - "Singleton 26"
Cohesion: 1.0
Nodes (1): Agent card endpoint should be accessible without authentication.

### Community 27 - "Singleton 27"
Cohesion: 1.0
Nodes (1): Viewer role cannot use send_email tool.

### Community 28 - "Singleton 28"
Cohesion: 1.0
Nodes (1): Developer role cannot use send_email tool.

### Community 29 - "Singleton 29"
Cohesion: 1.0
Nodes (1): Viewer role cannot use list_files tool.

### Community 30 - "Singleton 30"
Cohesion: 1.0
Nodes (1): Admin role can check permissions.

### Community 31 - "Singleton 31"
Cohesion: 1.0
Nodes (1): User without Files.Read scope cannot list files.

### Community 32 - "Singleton 32"
Cohesion: 1.0
Nodes (1): User without Mail.Send scope cannot send email.

### Community 33 - "Singleton 33"
Cohesion: 1.0
Nodes (1): A2A server health endpoint.

### Community 34 - "Singleton 34"
Cohesion: 1.0
Nodes (1): MCP server health check via root endpoint.

### Community 35 - "Singleton 35"
Cohesion: 1.0
Nodes (1): Cognito admin should be able to use S3 tools.

### Community 36 - "Singleton 36"
Cohesion: 1.0
Nodes (1): Cognito viewer should NOT be able to list S3 buckets.

### Community 37 - "Singleton 37"
Cohesion: 1.0
Nodes (1): Cognito users should get provider_not_supported for Graph tools.

### Community 38 - "Singleton 38"
Cohesion: 1.0
Nodes (1): Tool denial via LLM should contain [TOOL_DENIAL] or denial language.

### Community 39 - "Singleton 39"
Cohesion: 1.0
Nodes (1): Verify each documented denial reason returns correctly.

### Community 40 - "Singleton 40"
Cohesion: 1.0
Nodes (1): Admin token (user may be in multiple groups) resolves to admin.

### Community 41 - "Singleton 41"
Cohesion: 1.0
Nodes (1): Two consecutive messages with the same token both succeed (session reuse).

## Knowledge Gaps
- **190 isolated node(s):** `Check if auth is disabled for the given server section.`, `Get the full config section for a server.`, `Parse a JSON string of ABAC attributes into a dict.      Used by A2A and MCP s`, `Detect IdP from token issuer claim.      Shared across A2A and MCP servers to`, `Provides Authorization and X-Assume-Role headers for MCP calls from session stat` (+185 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `AuditLog Component`** (4 nodes): `AuditLog()`, `truncate()`, `AuditLog.js`, `AuditLog.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `DenialIndicator Component`** (3 nodes): `DenialIndicator.js`, `DenialIndicator()`, `DenialIndicator.js`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 19`** (1 nodes): `Return ALL roles the user qualifies for (from groups + user overrides).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 20`** (1 nodes): `Check if the user can access a tool.          Args:             request: The`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 21`** (1 nodes): `Request without token returns 401.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 22`** (1 nodes): `Request with invalid token returns 401.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 23`** (1 nodes): `User in BLOCKED_USERS list cannot access agent.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 24`** (1 nodes): `User without any allowed group cannot access agent.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 25`** (1 nodes): `User in allowed group can access agent.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 26`** (1 nodes): `Agent card endpoint should be accessible without authentication.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 27`** (1 nodes): `Viewer role cannot use send_email tool.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 28`** (1 nodes): `Developer role cannot use send_email tool.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 29`** (1 nodes): `Viewer role cannot use list_files tool.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 30`** (1 nodes): `Admin role can check permissions.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 31`** (1 nodes): `User without Files.Read scope cannot list files.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 32`** (1 nodes): `User without Mail.Send scope cannot send email.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 33`** (1 nodes): `A2A server health endpoint.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 34`** (1 nodes): `MCP server health check via root endpoint.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 35`** (1 nodes): `Cognito admin should be able to use S3 tools.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 36`** (1 nodes): `Cognito viewer should NOT be able to list S3 buckets.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 37`** (1 nodes): `Cognito users should get provider_not_supported for Graph tools.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 38`** (1 nodes): `Tool denial via LLM should contain [TOOL_DENIAL] or denial language.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 39`** (1 nodes): `Verify each documented denial reason returns correctly.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 40`** (1 nodes): `Admin token (user may be in multiple groups) resolves to admin.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Singleton 41`** (1 nodes): `Two consecutive messages with the same token both succeed (session reuse).`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `_get_graph_token()` connect `MCP Tool Implementations` to `Cedar Policy Engine`, `Graph OBO Token Exchange`?**
  _High betweenness centrality (0.162) - this node is a cross-community bridge._
- **Why does `event_loop()` connect `Access Control Tests` to `Graph OBO Token Exchange`?**
  _High betweenness centrality (0.153) - this node is a cross-community bridge._
- **Are the 79 inferred relationships involving `CedarPolicyEvaluator` (e.g. with `IdPConfig` and `TokenValidator`) actually correct?**
  _`CedarPolicyEvaluator` has 79 INFERRED edges - model-reasoned connections that need verification._
- **Are the 79 inferred relationships involving `TomlPolicyEvaluator` (e.g. with `IdPConfig` and `TokenValidator`) actually correct?**
  _`TomlPolicyEvaluator` has 79 INFERRED edges - model-reasoned connections that need verification._
- **Are the 71 inferred relationships involving `AccessRequest` (e.g. with `UserContextMiddleware` and `FastMCP server with Cedar ABAC policy evaluation.  Uses FastMCP's AzureJWTVeri`) actually correct?**
  _`AccessRequest` has 71 INFERRED edges - model-reasoned connections that need verification._
- **Are the 59 inferred relationships involving `AccessDecision` (e.g. with `UserContextMiddleware` and `FastMCP server with Cedar ABAC policy evaluation.  Uses FastMCP's AzureJWTVeri`) actually correct?**
  _`AccessDecision` has 59 INFERRED edges - model-reasoned connections that need verification._
- **Are the 30 inferred relationships involving `PolicyEvaluator` (e.g. with `UserContextMiddleware` and `FastMCP server with Cedar ABAC policy evaluation.  Uses FastMCP's AzureJWTVeri`) actually correct?**
  _`PolicyEvaluator` has 30 INFERRED edges - model-reasoned connections that need verification._