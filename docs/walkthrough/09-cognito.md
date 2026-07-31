# Act 09 — The Second IdP: Cognito

**Needs:** a configured AWS Cognito user pool (the `COGNITO_*` env vars in `.env`, and
`REACT_APP_COGNITO_*` in `frontend/.env`). Optional — do it only after Acts 00–08, and only if
you care about the multi-IdP story.

**Goal of this act:** prove that the *entire* identity model you just learned isn't
Entra-specific. A completely different identity provider — AWS Cognito, with different token
shapes and a different group mechanism — flows through the same gates, resolves to the same
three roles, and hits the same tool permissions. The only things that change are provider-shaped
details, and they're isolated to exactly the places you'd expect.

---

## 9.1 — Sign in with Cognito and watch the same gates apply

**Frontend:** the login prompt offers a provider choice. Pick **Cognito** and sign in with a
Cognito user who's a member of one of the platform groups (`platform-admins`,
`platform-developers`, `platform-viewers`).

Open the **Security Context** panel. The **Provider** badge now reads `COGNITO` instead of
`ENTRA ID`. Everything else in the panel behaves identically: a Role dropdown, groups, a token
expiry countdown, a permissions map. The RBAC Test Matrix works the same way, with the same
per-role pass/fail counts — because the role model is provider-independent.

**What's the same, and why:** roles, tool permissions, the three gates, the denial tiers. Once a
Cognito user is mapped to `admin`/`developer`/`viewer`, every downstream decision is identical to
Entra — Gate 2 and Gate 3 never even know which IdP you used.

**What's different, and where it's isolated:**

- **Provider detection** — the system figures out Cognito vs Entra from the token's `iss`
  (issuer) claim. Cognito's issuer is `cognito-idp.<region>.amazonaws.com/<pool>`.
- **The audience claim** — Cognito access tokens use `client_id`, not the standard `aud`. The
  MCP verifier omits the audience check for Cognito and validates `client_id` in the middleware
  instead (there's a comment in `_build_auth` saying exactly this).
- **The groups claim** — Cognito puts groups in `cognito:groups`, not `groups`. And the
  group→role mapping is a *separate table*: `[group_rules.cognito]` in `permissions.toml`, keyed
  by group *name* (`platform-admins`), versus `[group_rules.entra]` keyed by group *GUID*.

**Test a denial to confirm the gates are identical:** switch the Cognito user's role to VIEWER
and ask to list files → the same **amber TOOL badge** you saw in Act 02.2. Same gate, same code,
different IdP.

**Read the code:**
- Provider detection: `_detect_provider` (gateway, `a2a_server/server.py`) and the equivalent in
  the MCP middleware, both keying off `iss`.
- Cognito verifier and the `client_id`-not-`aud` note: `_build_auth`,
  `mcp_server/server.py:203-212`.
- Per-provider group rules: `permissions.toml` `[group_rules.cognito]` vs `[group_rules.entra]`,
  consumed by `TomlPolicyEvaluator`.

---

## 9.2 — Graph tools refuse a non-Entra user (correctly)

**Goal:** confirm the one place a Cognito user legitimately hits a wall. **What it proves:** the
system knows a Cognito identity has no Microsoft Graph token to offer, and says so cleanly
instead of failing obscurely.

As a Cognito user, ask for your Microsoft profile or to list OneDrive files. The Graph tools
return:

```json
{"error": "provider_not_supported"}
```

**Why:** Graph OBO exchanges a *Microsoft* user token for a Graph token. A Cognito user doesn't
have one — there's no Microsoft identity to exchange. So the Graph tools check the provider and
return `provider_not_supported` rather than attempting an exchange that can't work.

**What still works:** the **S3 tools**. They use server-side AWS credentials, not the user's
token, so they're identity-provider-agnostic — a Cognito viewer can call `get_s3_object_info`
exactly like an Entra viewer. This is a nice illustration of the resource gate (Gate 3) being
about *the resource's* auth model, not the user's IdP: Graph needs the user's Microsoft token, S3
needs the server's AWS creds, and the same Cognito user gets different answers accordingly.

**Read the code:** `_require_entra_provider` (`mcp_server/server.py`) returns the
`provider_not_supported` dict for non-Entra users; it's called by the Graph tools and *not* by
the S3 tools.

---

## Architecture decision — multi-IdP by issuer detection and per-provider rule tables

**What was chosen:** detect the provider from the token's `iss` claim, then route to
provider-specific handling only where the providers genuinely differ (audience claim, groups
claim name, group→role table), keeping everything downstream provider-agnostic.

**The alternative:** a separate code path per IdP end to end, or forcing all IdPs into one
normalized token shape at the edge.

**Why issuer detection + narrow branching:** the providers really *are* different in a few
specific claims (Cognito's `client_id`, `cognito:groups`, group names vs GUIDs), and pretending
they're not would mean either lossy normalization or bugs. But they're the *same* everywhere
that matters for authorization — once you have a role, the IdP is irrelevant. So the design
branches only at the three points of real difference and converges immediately after. The
`iss`-based detection is robust because `iss` is a signed claim (you're past signature
verification before you trust it) and it's the one field guaranteed to identify the issuer.

**The trade-off:** two group-rule tables to keep in sync conceptually (`[group_rules.entra]` and
`[group_rules.cognito]`), and a few `if provider == "cognito"` branches that must each be correct.
In exchange, adding a *third* IdP is a bounded change — a new issuer pattern, a new group-claim
name, a new rule table — not a rewrite, and the entire authorization core is untouched.

---

> ### Checkpoint — Act 09
> **You have now proven:** a completely different IdP (Cognito) flows through the same three
> gates to the same roles and tool permissions; Graph tools refuse a non-Entra user with
> `provider_not_supported` while S3 tools still work; and the provider differences are isolated
> to issuer detection, the audience claim, and the groups mechanism.
>
> **You now understand:** how the system stays IdP-agnostic below the role layer, and why the
> few provider-specific branches live exactly where they do.
>
> **Explain it in one sentence:** *"Swap Entra for Cognito and everything past 'which role are
> you' is identical — the IdP only matters for how we read your groups and whether you have a
> Microsoft token for Graph."*

---

**That's the walkthrough.** You've tested the human path, the machine chain, and the delegated
chain; probed the MCP server directly; attacked every guarantee; synthesized the trust model;
and proven it's not tied to one IdP. For teaching it to someone else, go to
[`CODE-TOUR.md`](CODE-TOUR.md) — the code in the order that makes the architecture click.
