# Entra Setup — Agent Identities

Provisions one app registration per agent, each authenticating with an x509
certificate (no client secrets). **Requires tenant admin.**

Prerequisite: `uv run python pki/generate_certs.py` (Task 1).

Login: `az login --tenant <ENTRA_TENANT_ID>`

> **Shell notes for Windows users:** The commands below are written for Git
> Bash (they use `for` loops and `$(...)` command substitution, which Git
> Bash's `bash.exe` handles natively via the Azure CLI's own shell wrapper).
> If you are running in native PowerShell instead, `$(...)` does **not**
> mean "command substitution" — that's `$(...)` only in POSIX shells;
> PowerShell needs the same syntax but interprets it correctly for
> subexpressions, so simple cases work, but **`for AGENT in ...; do ... done`
> is not valid PowerShell** and neither is capturing `az` output with
> `VAR=$(az ...)`. Anywhere you see a `for` loop or a `VAR=$(...)` capture,
> either run the commands in Git Bash, or translate to PowerShell as noted
> inline (`foreach` and `$VAR = az ...`).

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

The private key stays local; only the public cert is uploaded. Entra
verifies client assertions against this exact cert.

```bash
az ad app credential reset --id <orchestrator-appId>   --cert "@pki/certs/orchestrator.crt"   --append
az ad app credential reset --id <peer-appId>           --cert "@pki/certs/peer.crt"           --append
az ad app credential reset --id <event-trigger-appId>  --cert "@pki/certs/event-trigger.crt"  --append
az ad app credential reset --id <ENTRA_CLIENT_ID>      --cert "@pki/certs/gateway.crt"        --append
```

> **`--append` is critical.** Without it, `az ad app credential reset`
> *replaces* all existing credentials on the app. The gateway app
> (`ENTRA_CLIENT_ID`) already has a client secret used for user-token OBO
> exchange with Graph API (`ENTRA_CLIENT_SECRET`) — omitting `--append` on
> that last command would silently delete it and break existing Graph
> functionality (`get_user_profile`, `list_files`, `send_email`). Always use
> `--append` for the gateway; it's safe (and harmless) to use it for the new
> agent apps too.

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
az rest --method PATCH \
  --url "https://graph.microsoft.com/v1.0/applications/<objectId>" \
  --body @optionalclaims.json
```

(`<objectId>` is the app's `id`, not `appId`: `az ad app show --id <appId> --query id -o tsv`)

> The code falls back to a heuristic (`roles` present, `scp`/`preferred_username`
> absent) if `idtyp` is missing, but configure it — the heuristic is a safety
> net, not the contract.

## 5. Assign `Agent.Invoke` to the callers

Who may call whom:

| Caller | Callee |
|---|---|
| orchestrator | peer, gateway |
| gateway | peer |
| peer | gateway |
| event-trigger | orchestrator |

For each pair, assign the callee's `Agent.Invoke` role to the caller's SP:

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
> Repeat this block once per row in the table above (4 assignments total).

## 6. Enable per-hop user-token OBO (delegated path)

For the orchestrator to exchange a user's token for one scoped to a subagent,
each callee must expose a delegated scope and pre-authorize the orchestrator.

Expose `access_as_user` on each callee (Portal: *Expose an API → Add a scope*,
value `access_as_user`, admins+users), then pre-authorize the orchestrator's
appId on that scope (*Expose an API → Add a client application*).

Grant the orchestrator delegated permission to each callee and consent:

```bash
az ad app permission add --id <orchestrator-appId> \
  --api <callee-appId> --api-permissions <scope-guid>=Scope
az ad app permission admin-consent --id <orchestrator-appId>
```

## 7. Verify

```bash
uv run pytest tests/test_agent_identity.py -v -m integration
```

Integration tests skip cleanly if any `AGENT_*_CLIENT_ID` is unset.
