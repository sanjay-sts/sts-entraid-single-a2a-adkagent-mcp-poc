# ServiceNow Hybrid Authz — Cedar gate + Entra OBO + SN-native ACL

**Date:** 2026-05-20
**Branch:** `feature/servicenow-obo-hybrid` (base: `test-integration-servicenow`)
**Status:** Approved — implementation in progress
**Builds on:** `2026-05-19-servicenow-integration-abac-design.md` (Cedar-only v2, already shipped on the base branch and retained as the agent-side layer)

---

## Problem

The Cedar-only ServiceNow integration authorizes the *user* at the agent layer, then calls ServiceNow with a single **service account**. ServiceNow therefore only ever sees the integration account — it cannot apply per-user access controls (KB `user_criteria`, incident record ACLs, assignment groups, domain separation), and `department` is asserted by Cedar from the JWT rather than enforced by the resource owner.

Production identity-aware systems push the per-user decision down to the resource. We want ServiceNow to enforce access using the user's **own Entra identity** (via On-Behalf-Of token exchange), while keeping Cedar as a fast, multi-IdP, auditable agent-side gate.

## Chosen model: Hybrid

```
Cedar pre-check (fail-fast, every IdP)  →  OBO carries the user to SN  →  SN native ACL (authoritative)
```

This mirrors the existing **Graph tools**, which already combine `require_cedar(...)` with OBO (`mcp_server/server.py:499-604`, `mcp_server/graph_obo.py`). The increment is almost purely **additive**: existing Cedar checks, policies, entities, mock, frontend, and tests are untouched — we add an OBO token seam alongside them.

### Why keep Cedar (not pure-OBO)
- **Multi-IdP.** OBO is Entra-only. Cognito users can't OBO to SN; Cedar gates every provider uniformly.
- **Fail-fast + audit.** The agent denies obvious cross-dept / wrong-role calls before an OBO+SN round-trip, and the denial is captured in the central audit/denial-tier view.
- **Zero regression.** Existing dept-ABAC stays as the pre-filter; OBO adds an authoritative second layer underneath.

## Staging

OBO can't be exercised until ServiceNow + Entra are provisioned (not yet set up). So:
- **Build now (testable):** the OBO code seam — `servicenow_obo.py`, the `_get_effective_sn_token()` helper, the SN client's optional bearer token, and token threading through the 7 tools. Unit-tested with mocked exchange + respx.
- **Document now:** the live Entra-resource-app + SN-OIDC + user-provisioning runbook.
- **Verify when live:** an env-gated real-tier smoke test.

The seam is **config-gated and dormant**: with no `obo_scope`/`ENTRA_CLIENT_SECRET`, `_get_effective_sn_token()` returns `(None, False)` and every tool falls back to today's service-account/mock path. No behavior change ships.

---

## Decisions

| # | Question | Decision |
|---|---|---|
| D1 | Authorization model | Hybrid — Cedar coarse gate + dept pre-filter → OBO identity → SN native ACL authoritative. |
| D2 | Keep Cedar dept-composite, or thin RBAC gate? | **Keep** the dept pre-filter as fail-fast defense-in-depth (zero churn, preserves the dept-claim demonstration). Stripping it for a single SN source-of-truth is a noted future option. |
| D3 | OBO module | New `mcp_server/servicenow_obo.py`, near-clone of `graph_obo.py`. |
| D4 | SN client auth | Optional per-call bearer token: present → `Authorization: Bearer` (user, via OBO); absent → HTTP Basic service account. |
| D5 | Multi-IdP | OBO Entra-only; Cognito → service-account path → Cedar is the only authority. Documented. |
| D6 | Token propagation | `_get_effective_sn_token()` mirrors `_get_effective_graph_token()` / `_get_graph_token()`, including the dev-bypass guard. |
| D7 | Build vs document | Code seam + mocked tests now; live wiring documented; real-tier OBO smoke env-gated. |

---

## Components (delta)

### NEW — `mcp_server/servicenow_obo.py`
`ServiceNowOBOExchanger(tenant_id, client_id, client_secret, scope)` with an LRU credential cache keyed by `sha256(user_assertion)` (copied from `graph_obo.py`), `async get_sn_token(user_assertion) -> str | None` (via `OnBehalfOfCredential(...).get_token(scope)`), and module singleton `init_sn_obo_exchanger(scope)` / `get_sn_obo_exchanger()`. Disabled (returns `None`) when `ENTRA_CLIENT_SECRET`/tenant/client/scope are missing — same dormancy contract as `init_obo_exchanger()`.

### MODIFY — `mcp_server/servicenow.py`
`_request(..., *, token: str | None = None, ...)` → `Authorization: Bearer <token>` when set, else existing `auth=self._auth` Basic. All 8 public methods gain a forwarded `token` kwarg.

### MODIFY — `mcp_server/servicenow_mock.py`
Same `token` kwarg on every method (stashed as `self.last_token`, otherwise ignored) so the mock stays interface-compatible.

### MODIFY — `mcp_server/server.py`
- `init_sn_obo_exchanger(_sn_cfg.get("obo_scope", ""))` at startup, beside `init_obo_exchanger()`.
- `_get_effective_sn_token() -> tuple[str | None, bool]` beside `_get_effective_graph_token()`.
- Each of the 7 SN tools: after the Cedar checks, `sn_token, _ = await _get_effective_sn_token()` and pass `token=sn_token` to the client call(s). Cedar logic unchanged.

### MODIFY — config / docs
- `dev_config.example.toml`: `obo_scope = ""` under `[servicenow]`.
- NEW `docs/servicenow-obo-setup.md`; update `docs/servicenow-integration.md`, `CLAUDE.md`, `scratchpad/cedar-abac/06-test-results.md`.

---

## Data flow

- **Entra dev `IT` → `list_articles("HR KB")`:** Cedar dept pre-filter denies (`IT≠HR`) before any article fetch — SN never asked.
- **Entra dev `IT` → `list_articles("IT KB")`:** Cedar allows → OBO exchange → `Bearer <user>` → SN `user_criteria` returns IT articles for the *user*.
- **Cognito dev `IT` → `list_articles("IT KB")`:** Cedar allows → OBO unavailable → Basic service account → Cedar is the only authority (documented limitation).
- **`update_incident` cross-dept:** Cedar fetch-then-check denies before PUT; with OBO live, SN's record ACL is an independent second barrier.

---

## Testing

Existing tests stay green unmodified (seam dormant without config).

- **`tests/test_servicenow_obo.py`** — scope passed to `OnBehalfOfCredential`; exchange failure → `None`; disabled when unconfigured.
- **`tests/test_servicenow_integration.py`** (new) — Bearer used when Entra+configured (respx asserts header); fallback to Basic when exchanger absent; skipped for non-Entra; threaded through both `list_articles` calls.
- **Real-tier `@slow`** — `test_real_obo_user_identity_reaches_sn`, gated on `TEST_SERVICENOW_OBO` + Entra OBO env, read-only, skips cleanly.

Verify on Windows with `.venv\Scripts\python.exe -m pytest` (not `uv run` — yarl has no Windows wheel).

---

## Risks

- OBO untestable until SN provisioned → seam is mock-tested and config-gated dormant.
- SN per-user ACL requires the token's identity to map to a provisioned SN user (manual or SCIM) — flagged in the runbook.
- Cognito → Cedar-only on SN tools (matches Graph; not a regression).
- Dept logic in two places (Cedar + SN) — intentional defense-in-depth; SN authoritative once live.
- Wrong `obo_scope` → SN 401, surfaced as a resource-tier denial; runbook gives the exact `api://<app-id>/.default` form.
