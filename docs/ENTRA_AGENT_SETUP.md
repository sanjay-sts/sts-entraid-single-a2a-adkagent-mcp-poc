# Entra Setup — Agent Identities

Provisions one app registration per agent, each authenticating with an x509
certificate (no client secrets). **Requires tenant admin.**

Prerequisite: `uv run python pki/generate_certs.py` (Task 1).

Login: `az login --tenant <ENTRA_TENANT_ID>`

> **Shell notes for Windows users:** The commands below are written for Git
> Bash (a real POSIX shell, so `bash.exe` runs them natively — no wrapper
> involved). Native PowerShell can run most of these commands too; its own
> `$(...)` subexpression syntax does the same job as bash's command
> substitution, so that part isn't the problem. The two things that do
> **not** translate are: (1) bash's `for VAR in a b c; do ... done` loop,
> which has no PowerShell equivalent (use `foreach ($VAR in "a","b","c")
> { ... }` instead), and (2) bash's `VAR=$(cmd)` assignment form — no `$`
> on the variable name, no spaces around `=` — which PowerShell doesn't
> parse; PowerShell instead writes `$VAR = cmd` (plain assignment, no
> `$(...)` needed to capture a whole command's output). Anywhere you see a
> `for` loop or a `VAR=$(...)` capture below, either run it in Git Bash, or
> use the PowerShell version given alongside it.

## 1. Create the app registrations

```bash
for AGENT in orchestrator peer event-trigger; do
  az ad app create --display-name "agent-$AGENT" --sign-in-audience AzureADMyOrg
done
```

PowerShell equivalent:

```powershell
foreach ($AGENT in "orchestrator", "peer", "event-trigger") {
  az ad app create --display-name "agent-$AGENT" --sign-in-audience AzureADMyOrg
}
```

Record each `appId`. Set them in `.env` as `AGENT_ORCHESTRATOR_CLIENT_ID`,
`AGENT_PEER_CLIENT_ID`, `AGENT_EVENT_TRIGGER_CLIENT_ID`. The **gateway**
reuses the existing app (`ENTRA_CLIENT_ID`).

Create a service principal for each (required for app-role assignment):

```bash
az ad sp create --id <appId>
```

## 2. Upload the certificate to each app

> **Warning — the `--append` trap.** `az ad app credential reset --cert`
> clears **all** existing credentials on the app **by default, even with
> `--append`**, unless the existing credential is the same type you're
> adding. Microsoft's own docs for this command say plainly: *"By default,
> this command clears all passwords and keys."* `--append` only preserves
> credentials of the type you're resetting (cert-to-cert); it does **not**
> protect an existing client secret when you reset with `--cert`. **Never
> run `az ad app credential reset` against the gateway app** — see §2b.

The private key stays local; only the public cert is uploaded. Entra
verifies client assertions against this exact cert.

### 2a. New agent apps (orchestrator, peer, event-trigger)

These three apps have no existing credentials, so `credential reset
--append` is safe — there's nothing for it to destroy:

```bash
az ad app credential reset --id <orchestrator-appId>   --cert "@pki/certs/orchestrator.crt"   --append
az ad app credential reset --id <peer-appId>           --cert "@pki/certs/peer.crt"           --append
az ad app credential reset --id <event-trigger-appId>  --cert "@pki/certs/event-trigger.crt"  --append
```

### 2b. Gateway app — do NOT use `credential reset`

The gateway app (`ENTRA_CLIENT_ID`) already has a client secret
(`ENTRA_CLIENT_SECRET`) that the running system uses for user-token OBO
exchange with Graph API (`get_user_profile`, `list_files`, `send_email`
depend on it). `az ad app credential reset --cert`, even with `--append`,
deletes that secret (see warning above). Use one of the two non-destructive
methods below instead.

**Recommended: Azure Portal.** *App registrations → (the gateway app) →
Certificates & secrets → Certificates tab → Upload certificate* → select
`pki/certs/gateway.crt` → Add. This tab only ever writes `keyCredentials`;
there is no control on it that can touch the existing password credential.
This is the safest option — use it unless you have a reason to script this
step.

**Alternative: `az rest`.** This PATCHes the application's `keyCredentials`
property directly, which Microsoft Graph treats independently of
`passwordCredentials` — a PATCH to `keyCredentials` cannot touch the
password. But a PATCH *replaces* whatever array you send for that
property, so you must read the app's current `keyCredentials`, append the
new cert to it in your own script, and send the merged array back —
sending only the new cert would silently drop any other certs already on
the app (today there are none, but don't build the habit of skipping this
read-append-write). The array/JSON handling is simplest in PowerShell,
regardless of which shell you used for the rest of this guide:

```powershell
$objectId = az ad app show --id <ENTRA_CLIENT_ID> --query id -o tsv

$lines = Get-Content pki/certs/gateway.crt
$certB64 = -join $lines[1..($lines.Count - 2)]   # strip BEGIN/END CERTIFICATE lines

$existing = az ad app show --id <ENTRA_CLIENT_ID> --query keyCredentials -o json | ConvertFrom-Json
if ($null -eq $existing) { $existing = @() }      # Windows PowerShell 5.1 turns "[]" into $null

$newCred = [PSCustomObject]@{ type = "AsymmetricX509Cert"; usage = "Verify"; key = $certB64; displayName = "gateway-cert" }
$body = @{ keyCredentials = @($existing) + $newCred } | ConvertTo-Json -Depth 6

az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$objectId" --body $body
```

**Verify the secret survived — do this after either method:**

```bash
az ad app credential list --id <ENTRA_CLIENT_ID>          # password credential: should still be listed, unchanged
az ad app credential list --id <ENTRA_CLIENT_ID> --cert    # should now include the new gateway cert
```

If the first command comes back empty, the secret was deleted — reissue
`ENTRA_CLIENT_SECRET` (*Certificates & secrets → Client secrets → New
client secret*) and update `.env` before proceeding.

## 3. Expose each callee as an API, with an app role

Callees are: **peer**, **gateway** (as a subagent), and **orchestrator**.
Each must expose an API (so callers can request a token for it) and define
the `Agent.Invoke` app role (so callers can be authorized).

Set the App ID URI (`api://<appId>` — no domain verification needed):

```bash
az ad app update --id <appId> --identifier-uris "api://<appId>"
```

Define the app role. Save as `approles.json` (generate a fresh GUID per app
with `uuidgen` / `[guid]::NewGuid()`):

```json
[
  {
    "allowedMemberTypes": ["Application"],
    "description": "Permits a registered agent to invoke this agent",
    "displayName": "Agent Invoke",
    "id": "<FRESH-GUID>",
    "isEnabled": true,
    "value": "Agent.Invoke"
  }
]
```

```bash
az ad app update --id <callee-appId> --app-roles @approles.json
```

> **Note:** both `--identifier-uris` and `--app-roles` *replace* the app's
> entire array for that property — they don't add to it. Not an issue the
> first time you run these (the apps have no existing URIs or roles), but
> if you ever re-run either command later to add a second URI or role,
> include the existing values in what you pass or they will be silently
> dropped.

## 4. Emit the `idtyp` claim

`idtyp: "app"` is the canonical marker distinguishing a machine token from a
user token. It is an **optional claim** and must be requested explicitly.
Save as `optionalclaims.json`:

```json
{
  "optionalClaims": {
    "accessToken": [{ "name": "idtyp", "essential": false }]
  }
}
```

Apply to **every** app (callers and callees):

```bash
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/<objectId>" --body @optionalclaims.json
```

(`<objectId>` is the app's `id`, not `appId`: `az ad app show --id <appId> --query id -o tsv`)

> The code has no fallback if `idtyp` is missing — it fails closed and
> rejects the token as not-an-agent-token. A prior heuristic (`roles`
> present, `scp`/`preferred_username` absent) was removed because a
> delegated user token for an app-roles-only API can satisfy it too,
> letting a human token be misclassified as a machine token. Configuring
> `idtyp` on every app registration in this step is not optional.

## 5. Assign `Agent.Invoke` to the callers

Who may call whom — **5 caller→callee pairs** (note orchestrator has two
separate callees; each is its own row and its own assignment):

| # | Caller | Callee |
|---|---|---|
| 1 | orchestrator | peer |
| 2 | orchestrator | gateway |
| 3 | gateway | peer |
| 4 | peer | gateway |
| 5 | event-trigger | orchestrator |

For each of the 5 rows, assign the callee's `Agent.Invoke` role to the
caller's SP:

```bash
CALLER_SP=$(az ad sp show --id <caller-appId> --query id -o tsv)
CALLEE_SP=$(az ad sp show --id <callee-appId> --query id -o tsv)
ROLE_ID=$(az ad app show --id <callee-appId> --query "appRoles[?value=='Agent.Invoke'].id | [0]" -o tsv)

az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$CALLEE_SP/appRoleAssignedTo" \
  --body "{\"principalId\":\"$CALLER_SP\",\"resourceId\":\"$CALLEE_SP\",\"appRoleId\":\"$ROLE_ID\"}"
```

> **This step does not work as written in native PowerShell.** `VAR=$(cmd)`
> is bash command-substitution-into-assignment syntax; PowerShell's
> assignment operator is `=` with no leading `$` on the left-hand side, and
> `$(...)` there would just be interpreted as part of the string. Either
> run this block in Git Bash, or use the PowerShell form below:
>
> ```powershell
> $CALLER_SP = az ad sp show --id <caller-appId> --query id -o tsv
> $CALLEE_SP = az ad sp show --id <callee-appId> --query id -o tsv
> $ROLE_ID = az ad app show --id <callee-appId> --query "appRoles[?value=='Agent.Invoke'].id | [0]" -o tsv
>
> az rest --method POST `
>   --url "https://graph.microsoft.com/v1.0/servicePrincipals/$CALLEE_SP/appRoleAssignedTo" `
>   --body "{\`"principalId\`":\`"$CALLER_SP\`",\`"resourceId\`":\`"$CALLEE_SP\`",\`"appRoleId\`":\`"$ROLE_ID\`"}"
> ```
>
> Repeat this block once per row in the table above (5 assignments total,
> including both orchestrator rows — it's easy to do orchestrator→peer and
> stop, which leaves gateway-as-subagent unreachable from the
> orchestrator).

## 6. Enable per-hop user-token OBO (delegated path)

For the orchestrator to exchange a user's token for one scoped to a subagent,
each callee must expose a delegated scope and pre-authorize the orchestrator.

Expose `access_as_user` on each callee (Portal: *Expose an API → Add a scope*,
value `access_as_user`, admins+users), then pre-authorize the orchestrator's
appId on that scope (*Expose an API → Add a client application*).

Grant the orchestrator delegated permission to each callee and consent:

```bash
az ad app permission add --id <orchestrator-appId> --api <callee-appId> --api-permissions <scope-guid>=Scope
az ad app permission admin-consent --id <orchestrator-appId>
```

## 7. Verify

```bash
uv run pytest tests/test_agent_identity.py -v -m integration
```

Integration tests skip cleanly if any `AGENT_*_CLIENT_ID` is unset.
