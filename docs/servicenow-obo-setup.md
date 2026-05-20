# ServiceNow OBO (Hybrid) — Setup Guide

This guide turns on the **hybrid** authorization model for the ServiceNow MCP
tools: Cedar gates the call at the agent (fail-fast, multi-IdP, audited), then
the MCP server exchanges the end user's Entra token On-Behalf-Of for a
ServiceNow-scoped token so **ServiceNow enforces that user's own ACLs**.

```
Cedar pre-check (every IdP)  →  OBO carries the user to SN  →  SN native ACL (authoritative)
```

This mirrors the existing Microsoft Graph tools (`require_cedar(...)` + OBO).
The code already ships (`mcp_server/servicenow_obo.py`, `_get_effective_sn_token()`);
it is **dormant** until you complete the steps below. Until then every tool
uses the service-account path from [`servicenow-integration.md`](servicenow-integration.md)
and Cedar is the sole authority.

> **Prerequisite:** finish [`servicenow-integration.md`](servicenow-integration.md)
> first. OBO is layered on top of that working service-account setup — the
> service account stays in place as the fallback for non-Entra (Cognito) users.

---

## How it works

1. The frontend sends the user's Entra access token (custom audience
   `api://<agent-client-id>`) through A2A → ADK → MCP.
2. `_get_effective_sn_token()` (MCP) calls `ServiceNowOBOExchanger.get_sn_token()`,
   which uses Azure's `OnBehalfOfCredential` to exchange that token for one
   whose audience is the **ServiceNow resource app** (`obo_scope`).
3. The ServiceNow client sends `Authorization: Bearer <sn-token>`. ServiceNow
   validates it against Entra (inbound OIDC), maps a claim to a SN user, and
   applies that user's ACLs.
4. If OBO is unavailable (Cognito user, or `obo_scope`/secret unset), the client
   falls back to service-account HTTP Basic and Cedar remains the only check.

---

## Step 1 — Register ServiceNow as an Entra resource app

In the Entra admin center → **App registrations → New registration**:

1. Name it e.g. `servicenow-api`.
2. After creation, open **Expose an API**:
   - Set the Application ID URI, e.g. `api://<servicenow-app-id>`.
   - **Add a scope**, e.g. `user_impersonation` (admin-consent, "Access
     ServiceNow as the signed-in user").
3. Note the resulting scope value. Your `obo_scope` will be
   `api://<servicenow-app-id>/.default` (`.default` requests all consented
   delegated permissions).

## Step 2 — Grant the agent app permission to call ServiceNow

On the **agent's existing app registration** (`ENTRA_CLIENT_ID`):

1. **API permissions → Add a permission → My APIs → `servicenow-api`**.
2. Select the delegated scope from Step 1 (`user_impersonation`).
3. **Grant admin consent** for the tenant.

This is what lets the OBO exchange succeed: the agent app is authorized to get
a ServiceNow-audience token on behalf of the user. `ENTRA_CLIENT_SECRET` (already
required for Graph OBO) signs the exchange.

## Step 3 — Configure ServiceNow to accept Entra tokens (inbound OIDC)

In ServiceNow → **System OAuth → Application Registry → New →
"Configure an OIDC provider to verify ID tokens"**:

1. **OIDC Provider:** create/select an entry for Microsoft Entra.
2. **OIDC Metadata URL:**
   `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration`
3. Under **OAuth OIDC Entity → JWT Claims Validations**, validate:
   - `aud` = your ServiceNow Application ID URI / app id from Step 1.
   - `iss` = `https://login.microsoftonline.com/<tenant-id>/v2.0`.
4. **User claim mapping:** map a token claim to a ServiceNow user field so SN can
   resolve the caller to a real user — typically `email` or `preferred_username`
   → SN `user_name`/`email`. (`sub` is stable but opaque; email is easier to
   provision.)

## Step 4 — Provision the users in ServiceNow

ServiceNow can only apply per-user ACLs if the token's identity maps to an
existing SN user. For each test user:

1. Create the SN user with the **email/username that matches the mapped claim**.
2. Assign roles/groups that drive access (e.g. an `IT` group).
3. Set KB **`user_criteria`** (Can Read / Cannot Read) so, e.g., only IT users
   read the IT KB. This is the SN-side mirror of the Cedar dept rule — now
   enforced by the resource owner.

Production: automate this with **SCIM** provisioning from Entra rather than
hand-creating users.

## Step 5 — Turn OBO on

In `dev_config.toml`:

```toml
[servicenow]
instance_url = "https://devXXXXX.service-now.com"
api_user     = "agent_integration"   # still required — Cognito fallback
api_password = ""                     # SERVICENOW_API_PASSWORD env var
obo_scope    = "api://<servicenow-app-id>/.default"
```

Ensure `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, and `ENTRA_CLIENT_SECRET` are set
(the same trio Graph OBO uses). Restart the MCP server. Logs should show:

```
ServiceNow OBO exchanger initialised (scope: api://<servicenow-app-id>/.default)
```

If you instead see `ServiceNow OBO disabled -- ...`, a credential or the scope
is missing and the server is using the service-account fallback.

## Step 6 — Verify

**Manual:** sign in as an Entra user provisioned in SN with `department=IT` and a
SN account that can only read the IT KB. Ask the agent to "list IT articles"
(works) and "list HR articles" (Cedar denies first; even if it didn't, SN's
`user_criteria` would). The SN system log shows the request as the **end user**,
not the service account.

**Real-tier test** (read-only, skips unless configured):

```powershell
$py = ".venv\Scripts\python.exe"
$env:TEST_SERVICENOW_INSTANCE        = "https://devXXXXX.service-now.com"
$env:TEST_SERVICENOW_USER            = "agent_integration"
$env:TEST_SERVICENOW_PASS            = "<password>"
$env:TEST_SERVICENOW_OBO             = "1"
$env:TEST_SERVICENOW_OBO_SCOPE       = "api://<servicenow-app-id>/.default"
$env:TEST_SERVICENOW_OBO_USER_TOKEN  = "<a pre-acquired Entra user assertion JWT>"
& $py -m pytest tests/test_servicenow_integration.py::TestServiceNowRealOBO -v -m slow
```

---

## Caveats

- **Entra-only.** Cognito users cannot OBO; they fall back to the service
  account and Cedar is their only authority. Document this for your users.
- **Dept enforcement now lives in two places.** Cedar (fail-fast pre-filter) and
  SN `user_criteria` (authoritative). Intentional defense-in-depth. Keep them
  consistent, or drop the Cedar dept rule later if the duplication is a burden.
- **Wrong `obo_scope`/audience** → SN returns 401, surfaced as a resource-tier
  denial. Double-check the Application ID URI from Step 1.
- **Incident `u_department`** remains deferred — incident dept-ABAC is exercised
  only by mocked tests in this branch.
