# ServiceNow Integration — Setup Guide

This guide walks through the one-time ServiceNow setup that makes the seven
ServiceNow MCP tools functional against a live instance. **No SN setup is
required for local development** — leave `[servicenow].instance_url = ""` in
`dev_config.toml` and the agent routes through the in-memory mock at
`mcp_server/servicenow_mock.py`.

## What you need

- A ServiceNow developer instance (free): https://developer.servicenow.com/
- An admin account on that instance
- ~10 minutes for the configuration steps below

## Step 1 — Get an API service account

The branch ships with **service-account (HTTP Basic) auth**. We trade per-user
identity at ServiceNow for setup simplicity. Real OBO is a documented follow-up.

1. Sign into your dev instance as admin.
2. Create or reuse a service-account user (e.g. `agent_integration`).
3. Grant it the `admin` role (read-write for KBs + incidents). For a tighter
   model, grant `kb_admin` + `itil` instead.
4. Set a long random password. Store it in `dev_config.toml` or as the
   `SERVICENOW_API_PASSWORD` env var.

## Step 2 — Add the `u_department` custom field on `kb_knowledge_base`

The MCP tool `list_articles` fetches each KB's `u_department` before
running the Cedar Phase 2 ABAC check. Real ServiceNow doesn't ship this
field — you add it once.

1. In the SN top filter bar, navigate to **System Definition → Tables**.
2. Open the `kb_knowledge_base` table.
3. Scroll to the **Columns** related list, click **New**.
4. Configure:
   - **Column label:** `Department`
   - **Column name:** `u_department` (must match exactly — the tool reads
     this field name)
   - **Type:** `String`
   - **Max length:** `40`
5. Save.

**Note on incidents:** the spec defers the equivalent `u_department` field
on the `incident` table until the OBO follow-up. In this branch, real-tier
tests skip incident dept-ABAC; mocked tests still cover that path.

## Step 3 — Create three department-tagged KBs

Create the three KBs the test scenarios assume. In **Knowledge → Knowledge
Bases → Create New**:

| Title       | `u_department` value | Owner / Manager | User Criteria |
|-------------|----------------------|-----------------|---------------|
| `IT KB`     | `IT`                 | service-account | open (any user) |
| `HR KB`     | `HR`                 | service-account | open (any user) |
| `Finance KB`| `Finance`            | service-account | open (any user) |

Leave the `user_criteria` open so the service-account user can read all KBs;
Cedar enforces the dept restriction on the agent side. (When you upgrade to
OBO mode later, tighten the `user_criteria` to mirror Cedar — defense in
depth.)

Drop a couple of articles into each KB so `list_articles` returns something.

## Step 4 — Wire credentials into `dev_config.toml`

Copy from `dev_config.example.toml`:

```toml
[servicenow]
instance_url = "https://devXXXXX.service-now.com"   # your subdomain
api_user     = "agent_integration"
api_password = ""                                    # SERVICENOW_API_PASSWORD env var preferred
```

For production, set `SERVICENOW_API_PASSWORD` as an environment variable rather
than committing the password to disk. The MCP server reads `api_password`
from config only — if you wire it through env, leave `api_password = ""` in
the file and source the env var into the process.

## Step 5 — Restart the MCP server

```powershell
uv run python mcp_server/server.py
```

The logs should show:

```
ServiceNow client initialised (instance: https://devXXXXX.service-now.com)
```

(or the mock-fallback line if any required field is missing.)

## Step 6 — Smoke test

In the frontend (port 10003), sign in as an `admin` user with a valid Entra
token. Prompt:

> "List the available ServiceNow knowledge bases"

Expected: a list including IT KB, HR KB, and Finance KB.

Prompt:

> "List the articles in the IT KB"

Expected: articles from the IT KB.

## Real-tier integration tests

With the env vars set, the `@slow` real-tier suite runs:

```powershell
$env:TEST_SERVICENOW_INSTANCE = "https://devXXXXX.service-now.com"
$env:TEST_SERVICENOW_USER     = "agent_integration"
$env:TEST_SERVICENOW_PASS     = "<password>"
uv run pytest tests/test_servicenow_integration.py::TestServiceNowReal -v -m slow
```

The real-tier tests are **read-only**: list KBs, list articles, get one
article, and one auth-failure check with bad credentials. No data is created
or modified.

## Hybrid OBO mode

The service-account auth above is the **fallback**. The hybrid model adds
per-user enforcement: when configured, the MCP server exchanges the end user's
Entra token (On-Behalf-Of) for a ServiceNow-scoped token, so ServiceNow applies
that user's own ACLs (KB `user_criteria`, incident record rules). Cedar stays as
the fail-fast agent-side gate (defense in depth).

The code seam ships in this branch — `mcp_server/servicenow_obo.py` and
`_get_effective_sn_token()` in `mcp_server/server.py` — and stays **dormant**
until `[servicenow].obo_scope` and `ENTRA_CLIENT_SECRET` are set. To turn it on,
follow **[`servicenow-obo-setup.md`](servicenow-obo-setup.md)**.

> OBO is Entra-only. Cognito users keep the service-account path, so Cedar is
> the only authority for them. The incident `u_department` field remains
> deferred (real-tier incident dept-ABAC is exercised only by mocked tests).
