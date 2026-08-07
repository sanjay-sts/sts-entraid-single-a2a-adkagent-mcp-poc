# Act 01 — The Golden Thread

**Needs:** the four human-path services running, and a working Entra login. Setup is in
[`../../TESTING.md`](../../TESTING.md) if you haven't done it.

**Goal of this act:** follow **one** real request — a single chat message from one signed-in
user — all the way from the browser, through the gateway, the LLM agent, and the MCP tools,
out to Microsoft Graph, and back. You'll watch it cross all three gates in the logs. This is
the thread everything else in the system is woven around.

Sign in as the **admin** test user for this act (`AdeleV@…`, in the `AI-Agent-Admins`
group). Admin passes every gate, so nothing gets in the way of seeing the happy path
end-to-end. Denials come in Act 02.

---

## 1.1 — Start the services and confirm they're up

Four terminals, from the repo root:

```bash
# Terminal 1 — MCP tools
uv run python mcp_server/server.py
# Terminal 2 — ADK agent (the LLM)
uv run python adk_agent/agent.py
# Terminal 3 — A2A gateway
uv run python a2a_server/server.py
# Terminal 4 — frontend
cd frontend && npm start
```

**Confirm the two services that have a health endpoint:**

```bash
curl.exe http://localhost:10000/health
curl.exe http://localhost:10001/health
```

**Expected output:**

```json
{"status":"healthy","service":"a2a-gateway"}
{"status":"healthy","agent":"identity_aware_agent"}
```

> **The MCP server has no `/health` endpoint** — on purpose. It's a stateless
> streamable-HTTP MCP endpoint at `http://localhost:10002/mcp`, not a REST service. Confirm
> it's up a different way: when the ADK agent starts, it connects to MCP and lists the tools;
> watch `logs/adk_agent.log` for a successful tool-listing line, or just confirm the process
> is listening on 10002. Curling `/mcp` with a plain GET will *not* give you a health blob —
> that's expected, and Act 03 shows how to probe `/mcp` properly.

**Read the code:** the health handlers are `a2a_server/server.py:883-885` and
`adk_agent/agent.py:444-447`. The MCP endpoint config — `path="/mcp"`, `stateless_http=True`
— is `mcp_server/server.py:985-990`.

---

## 1.2 — Sign in, and look at your own identity (frontend)

Open `http://localhost:10003` and sign in with the admin account.

Look at the **Security Context** panel in the sidebar. You should see, in order:

- **Provider:** `ENTRA ID`
- **User:** your name / email
- **Role:** a dropdown — `ADMIN`, `DEVELOPER`, `VIEWER` (highest available auto-selected, so
  `ADMIN` here)
- **Groups:** your group GUIDs
- **Token Scopes**, **Token Expiry** (a live `M:SS` countdown), and **Permissions** (one row
  per tool with `✓` / `✗`)

Now open the **Token Inspector** and look at your raw token's decoded payload. Find these
four claims — they're the ones the whole system keys off:

- **`aud`** — the audience. Who this token was minted *for*. It names the gateway's app.
- **`groups`** — your security-group GUIDs. This is what becomes your role.
- **`exp`** — expiry, as a Unix timestamp. The countdown in the panel is this minus now.
- **`scp`** — the scopes you consented to (e.g. `access_as_user`, `User.Read`).

The Token Inspector is display-only — it decodes the JWT in your browser, it doesn't verify
it. Verification is the gateway's job, which you'll see next.

**Read the code:** the panel is `frontend/src/components/SecurityContextPanel.js`; the
decoder is `frontend/src/utils/tokenDecoder.js` and
`frontend/src/components/TokenInspector.js`.

---

## 1.3 — Ask the gateway what it made of you (backend)

Copy your raw token from the Token Inspector. Then ask the gateway's `/me` endpoint what it
*derived* from that token — this is Gate 1's view of you, without sending a chat message yet.

```bash
# PowerShell: put the token in a variable first to keep the command readable
$TOKEN = "<paste your raw token>"
curl.exe -s http://localhost:10000/me -H "Authorization: Bearer $TOKEN"
```

**Expected output** (shape, with admin values):

```json
{
  "user": { "email": "AdeleV@...", "name": "Adele Vance", "oid": "..." },
  "security": {
    "provider": "entra",
    "role": "admin",
    "available_roles": ["admin"],
    "groups": ["<admin-group-guid>"],
    "group_names": { "<admin-group-guid>": "admin" },
    "token_scopes": ["access_as_user", "..."],
    "token_expiry": 1730000000,
    "issuer": "https://login.microsoftonline.com/<tenant>/v2.0"
  },
  "permissions": { "get_user_profile": true, "list_files": true, "...": "..." },
  "tool_scopes": { "...": "..." }
}
```

Notice what happened: you sent a *token*, and the gateway handed back a *role*, a set of
*available roles*, and a per-tool *permission map*. That translation — token → groups →
role → permissions — is the gateway's whole job at Gate 1. The `permissions` block is
literally "which tools would this role be allowed to call," computed here so the frontend can
grey out the ones you can't use.

Try it again with `-H "X-Assume-Role: viewer"` and watch `role` change to `viewer` and the
`permissions` map shrink — but only because `admin` *can* step down to any role. In Act 02
you'll see a viewer try to step *up* and get refused.

**Read the code:** `get_me` is `a2a_server/server.py:888-943`. Follow `_extract_user_info`
(`:846`), `_get_available_roles`, and the `permissions` comprehension at `:923`.

---

## 1.4 — Send one message, and watch it cross all three gates (the main event)

Set up four log tails first, so you can watch the request move through the services live.
PowerShell:

```powershell
# one per terminal, or use Windows Terminal panes
Get-Content -Wait -Tail 5 logs/a2a_server.log
Get-Content -Wait -Tail 5 logs/adk_agent.log
Get-Content -Wait -Tail 5 logs/mcp_server.log
```

(Bash: `tail -f logs/a2a_server.log`, etc.)

Now, in the frontend chat, send exactly:

> **Show my Microsoft profile**

Watch the thread move left to right across the logs:

**Gate 1 — the gateway (`logs/a2a_server.log`)** validates the token and lets a human in:

```
Token validated for user: AdeleV@...
Access control passed, storing claims in request state
```

Those two lines are `a2a_server/server.py:748` and `:756`. Between them the gateway ran the
blocklist check and the group-membership check — both of which admin passes silently. Then it
forwards your token and `X-Assume-Role` to the ADK agent.

**The agent (`logs/adk_agent.log`)** creates a session, stores your identity in session state
under `user:` keys, and calls the LLM, which decides to call the `get_user_profile` tool. When
it calls MCP, it injects your token via `mcp_header_provider`.

**Gate 2 — the MCP server (`logs/mcp_server.log`)** re-verifies your token from scratch (it
does *not* trust the agent), resolves your role, and checks that role against the tool's
requirement. `get_user_profile` allows all roles, so admin passes.

**Gate 3 — the resource.** For a Graph tool, the MCP server exchanges your token for a
Graph-scoped one (OBO) and calls Microsoft Graph, which enforces the token's scopes. The
profile comes back and flows all the way to your chat window.

The reply appears with no denial badge — a clean pass through all three gates. Open the
**Audit Log** panel and you'll see the request row: prompt, role, HTTP 200, `OK` in the
Denial column, and a latency figure.

**Read the code, in request order:**
1. `a2a_server/server.py:639` — `auth_middleware`, the gateway's entry point (Gate 1).
2. `adk_agent/agent.py:209-213` — identity stored in session state as `user:access_token`,
   `user:role`.
3. `adk_agent/agent.py:99-127` — `mcp_header_provider`, which injects `Authorization` and
   `X-Assume-Role` into every MCP call.
4. `mcp_server/server.py` — `UserContextMiddleware` (Gate 2) and the `get_user_profile` tool
   at `:527`.
5. `mcp_server/graph_obo.py:54` — `get_graph_token`, the OBO exchange (Gate 3).

---

## 1.5 — The propagation chain, named

The single most useful thing to hold in your head: **the same identity is re-expressed in a
different form at each tier, and each tier stores it in an async-safe `ContextVar`** so
concurrent requests don't cross wires.

```
Frontend        Bearer token + X-Assume-Role header
   │
Gateway         ContextVars: current_user_claims, current_access_token,
   │            current_assumed_role, current_principal
   │
ADK Agent       session state: user:access_token, user:role, user:email, user:groups
   │
MCP Server      ContextVars: current_user_token, current_user_role, current_user_email,
                current_user_provider, current_principal_type, current_agent_id
```

Six ContextVars on the MCP side, and every code path that sets one must set *all* of them —
because the MCP server is stateless and reuses contexts between requests, so a stale value
left behind by a previous request would misjudge the next one. That rule is in `CLAUDE.md`
(convention 3) and you'll see why it matters in Act 03.

---

## Architecture decision — ContextVars and stateless MCP

**What was chosen:** propagate identity through `ContextVar`s at each tier, and run the MCP
server in stateless HTTP mode (`stateless_http=True`) with no server-side session.

**The alternatives:** (a) thread identity explicitly through every function call as
arguments; (b) keep a server-side session per user (stateful MCP) and look identity up by
session id.

**Why ContextVars:** the async request handlers and the MCP tool functions are far apart in
the call stack, with framework code in between that you don't control. Passing a token as an
argument would mean touching every layer. A `ContextVar` is async-safe (unlike a thread-local
or a global) — each concurrent request sees its own value — and it reads cleanly inside a
tool function without plumbing.

**Why stateless MCP:** a stateless server scales horizontally with no shared session store
and no session-affinity routing. The cost is that there's nowhere to stash per-user state
between requests, which is exactly why identity must ride in on every request's headers and
be re-resolved each time.

**The trade-off you're accepting:** stateless + ContextVars means the "set all six vars on
every path" discipline is load-bearing. Miss one on one code path, and a reused context
leaks a stale value into the next request. The code guards this by setting the full set in
every branch; Act 03 shows the branch where a machine principal must reset the human-only
vars for exactly this reason.

---

> ### Checkpoint — Act 01
> **You have now proven:** one real request crosses Gate 1 (gateway), Gate 2 (MCP role
> check), and Gate 3 (Graph scopes), and you can point at the log line where each fired.
>
> **You now understand:** how identity is re-expressed at each tier (token → ContextVars →
> session `user:` state → ContextVars again), why MCP is stateless, and why `/me` returns a
> role and a permission map rather than just echoing your token.
>
> **Explain it in one sentence:** *"One signed-in user sends one message, and you can watch
> the same identity get re-verified three times by three different services on its way to the
> data and back."*

Next: [Act 02 — denials by gate](02-denials-by-gate.md). Now break it, one gate at a time.
