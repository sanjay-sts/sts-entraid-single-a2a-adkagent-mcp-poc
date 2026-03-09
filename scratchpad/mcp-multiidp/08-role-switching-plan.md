# MCP Multi-IdP: Frontend Role Switching Implementation Plan

**Date**: 2026-03-09
**Prerequisite**: Multi-IdP auth (Steps 1-5 in 03-implementation-plan.md) — COMPLETE
**Goal**: End-to-end role switching from frontend UI through to MCP server

---

## Problem Statement

The MCP server supports `X-Assume-Role` header (validated by `UserContextMiddleware` against `permissions.toml`), but:
- Frontend never sends `X-Assume-Role`
- A2A server doesn't forward it to ADK
- ADK agent's `mcp_header_provider` only sends `Authorization` header
- Role testing is only possible via MCP Inspector (manual header injection)

This blocks end-to-end RBAC testing through the frontend UI.

## Propagation Chain

```
Frontend                    A2A Server                 ADK Agent                  MCP Server
─────────────────────────   ──────────────────────     ──────────────────────     ──────────────
X-Assume-Role header   ──>  Extract from request  ──>  Store in session state ──> X-Assume-Role
                            + ContextVar                via /session & /chat      header (already
                            Pass in JSON body           body "role" field.        reads it ✓)
                            to ADK /session             mcp_header_provider
                            and /chat                   includes it in MCP calls
```

---

## Files Modified

| File | Change |
|------|--------|
| `a2a_server/server.py` | Add `current_assumed_role` ContextVar, extract from header, forward to ADK, enhance GET /me |
| `adk_agent/agent.py` | Update `mcp_header_provider`, accept role in /session and /chat |
| `frontend/src/App.js` | Add `selectedRole` state, wire to all components |
| `frontend/src/components/SecurityContextPanel.js` | Add role dropdown from `available_roles` |
| `frontend/src/components/ChatInterface.js` | Accept `selectedRole`, add `X-Assume-Role` header |
| `frontend/src/components/ConversationTabs.js` | Pass `selectedRole` through to ChatInterface |
| `frontend/src/components/RBACTestMatrix.js` | Use `selectedRole` for scenarios + header |
| `frontend/src/utils/testScenarios.js` | Update denial expectations (role-only, no scope denial) |
| `frontend/src/App.css` | Style role dropdown |

### Files NOT Modified
- `mcp_server/server.py` — already reads `X-Assume-Role` via `UserContextMiddleware`
- `mcp_server/policy.py` — already resolves available roles
- `frontend/src/utils/denialClassifier.js` — already classifies `[TOOL_DENIAL]`

---

## Backend Changes

### A2A Server (`a2a_server/server.py`)

**1. New ContextVar** (line 27):
```python
current_assumed_role: ContextVar[str] = ContextVar("current_assumed_role", default="")
```

**2. Auth middleware** (line 552): Extract header after token validation:
```python
current_assumed_role.set(request.headers.get("X-Assume-Role", ""))
```

**3. IdentityAwareAgentExecutor.execute()** (line 265-274): Add role to /chat body:
```python
json={
    "message": message_text,
    "user_id": user_id,
    "session_id": session_id,
    "role": current_assumed_role.get(),  # NEW
},
```

**4. _ensure_session()** (line 350-362): Add assumed_role to user_info:
```python
"user_info": {
    "email": ...,
    "name": ...,
    "groups": ...,
    "assumed_role": current_assumed_role.get(),  # NEW
},
```

**5. New helper** (near line 620):
```python
def _get_available_roles(groups: list) -> list:
    """Return all roles the user qualifies for, ordered by priority."""
    role_priority = ["admin", "developer", "viewer"]
    user_roles = [GROUP_TO_ROLE.get(g) for g in groups if g in GROUP_TO_ROLE]
    return [r for r in role_priority if r in user_roles]
```

**6. Enhanced GET /me** (line 636): Return `available_roles`, accept `X-Assume-Role` for permissions:
```python
available_roles = _get_available_roles(user_groups)
assumed_role = request.headers.get("X-Assume-Role", "")
active_role = assumed_role if (assumed_role and assumed_role in available_roles) else _determine_role(user_groups)

# Permissions based on active (possibly assumed) role
permissions = {tool: active_role in roles for tool, roles in TOOL_ROLES.items()}

return {
    "security": {
        "role": active_role,
        "available_roles": available_roles,  # NEW
        ...
    },
    "permissions": permissions,
}
```

### ADK Agent (`adk_agent/agent.py`)

**1. mcp_header_provider** (line 54-66): Add X-Assume-Role:
```python
def mcp_header_provider(readonly_context):
    headers = {}
    if readonly_context and readonly_context.state:
        access_token = readonly_context.state.get("user:access_token", "")
        role = readonly_context.state.get("user:role", "")
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        if role:
            headers["X-Assume-Role"] = role
    return headers
```

**2. create_session** (line 143-176): Accept assumed_role from user_info:
```python
assumed_role = user_info.get("assumed_role", "")
role = assumed_role if assumed_role else self._determine_role(user_info.get("groups", []))
```

**3. /chat endpoint** (line 351-416): Read role from body, update session state:
```python
role = body.get("role", "")
if role:
    agent.session_service.user_state.setdefault("identity-agent", {}).setdefault(user_id, {})["role"] = role
```

---

## Frontend Changes

### App.js
- Add `selectedRole` state: `const [selectedRole, setSelectedRole] = useState(null)`
- Pass `selectedRole` + `onRoleChange` to SecurityContextPanel
- Pass `selectedRole` to RBACTestMatrix and ConversationTabs

### SecurityContextPanel.js
- Accept `selectedRole` and `onRoleChange` props
- Replace static role badge with `<select>` dropdown populated from `security.available_roles`
- Auto-select highest role on initial load via useEffect
- Send `X-Assume-Role` header with GET /me to update permissions display
- Add `selectedRole` to fetchSecurityContext dependency array

### ConversationTabs.js
- Accept `selectedRole` prop, pass to ChatInterface

### ChatInterface.js
- Accept `selectedRole` prop
- Add `X-Assume-Role: selectedRole` header to POST requests
- Add `role` field to audit entries

### RBACTestMatrix.js
- Accept `selectedRole` prop
- Use `selectedRole || role` for `getScenariosForRole()` computation
- Add `X-Assume-Role` header to test requests
- Clear results via useEffect when `selectedRole` changes
- Show "Testing as: [ROLE]" with switch indication

### testScenarios.js
- Update `denialExpected`: role denial → `'tool'`, scope denial → `'resource'`
- Reflects removal of `require_scopes_from_token` from MCP

### App.css
- Role dropdown styling (`.role-select`, `.role-select.role-admin`, etc.)
- Match dark theme, reuse existing role color variables

---

## Edge Cases

| Case | Behavior |
|------|----------|
| Role change mid-conversation | Next message uses new role; previous messages unchanged |
| Invalid role assumption | MCP returns `[TOOL_DENIAL] Cannot assume role...` → TOOL denial badge |
| No available roles | Dropdown disabled, shows "No roles available" |
| Dev bypass mode | Role defaults to admin from dev_config.toml, all tools work |
| Session persistence | Session stays; only `user:role` in state updates |

---

## Verification Test Plan

| Test | Steps | Expected |
|------|-------|----------|
| T1: Dropdown populates | Sign in as AdeleV (admin) | Dropdown shows ADMIN (+ VIEWER if override exists) |
| T2: Permissions update | Switch to VIEWER | Permissions list shows only get_user_profile allowed |
| T3: Chat as admin | Ask "What time is it in Tokyo?" | Success |
| T4: Chat as viewer | Switch to VIEWER, ask same | [TOOL_DENIAL] in response |
| T5: RBAC matrix | Switch roles, Run All | Scenarios recompute, all should PASS |
| T6: Invalid role | Developer tries admin | [TOOL_DENIAL] "Cannot assume role 'admin'" |
| T7: Audit log | Send messages with different roles | Role column shows per-request role |