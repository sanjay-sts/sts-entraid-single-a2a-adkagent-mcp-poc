# Act 07 — Adversarial: Try to Break the Gates

**Needs:** Act 04 complete; peer + orchestrator + gateway running.

**Goal of this act:** stop being a well-behaved caller and *attack*. Each scenario is an attempt
to defeat one guarantee from the earlier acts, and each one should fail in a specific,
observable way. A guarantee you've only seen hold for cooperative input isn't a guarantee yet.

You'll use the second helper script, `scripts/mint_agent_token.py`, which mints a real
agent token for a callee you name — the same capability an attacker with one agent's cert would
have.

---

## 7.1 — Replay a token at the wrong hop

**Attack:** mint a token for the **orchestrator**, then present it to the **peer**. If audience
narrowing is real, the peer must refuse a token that was minted for someone else.

```bash
# mint a token whose audience is the orchestrator
uv run python docs/walkthrough/scripts/mint_agent_token.py --as event-trigger --for orchestrator --print-token
# then POST it to the peer's /invoke with that token as the Bearer
curl.exe -s -i -X POST http://localhost:10005/invoke \
  -H "Authorization: Bearer <the minted token>" \
  -H "Content-Type: application/json" \
  -d '{"action":"status","params":{}}'
```

**Expected:** HTTP **401**, body `denial_reason: validation_failed`.

**The subtlety worth understanding — why 401, not 403.** You might expect `403 wrong_audience`,
since the problem *is* the audience. But the peer checks audience **twice**: once inside the JWT
signature validator (`EntraJWTValidator.validate`, which is handed the peer's expected audience
and rejects a mismatch as part of validation), and once in the claim-level
`verify_agent_claims` (which would raise `wrong_audience`). The signature validator runs
**first**, so a live cross-hop token is caught there and surfaces as `validation_failed` — the
claim-level check never gets to run. That second check isn't redundant: it's the backstop that
still holds if the validator is ever swapped out. But against the real system, this attack is a
401. (A test asserting 403 here would be wrong — and the integration suite deliberately asserts
401. This exact trap is documented in `CLAUDE.md`.)

**Read the code:** `agent_common/jwt_validator.py:89-136` — `validate` takes `expected_audience`
and rejects a mismatch (`InvalidAudienceError` → `TokenVerificationError`). The claim-level
backstop is `_audience_matches` + the `wrong_audience` raise in
`agent_common/principal.py:91-135`.

---

## 7.2 — Put an agent token in the user slot (fabricate a human)

**Attack:** call the orchestrator with a valid agent token as `Authorization` (fine), but also
put an **app-only** token in `X-Delegated-User-Token` — trying to make a machine call look
delegated, inventing a human who isn't there.

```bash
uv run python docs/walkthrough/scripts/mint_agent_token.py --as event-trigger --for orchestrator --print-token   # the caller token
uv run python docs/walkthrough/scripts/mint_agent_token.py --as peer --for orchestrator --print-token             # an app token to abuse as the "user"
curl.exe -s -i -X POST http://localhost:10004/dispatch \
  -H "Authorization: Bearer <caller token>" \
  -H "X-Delegated-User-Token: <app token in the user slot>" \
  -H "Content-Type: application/json" \
  -d '{"task":"status"}'
```

**Expected:** HTTP **403**, `denial_reason: delegated_token_not_a_user`.

**Why it holds:** the rider-token check runs `is_app_token` on the delegated token and refuses
anything with `idtyp=app`. A user token never has that claim, so an app-only token can't
masquerade as one. You cannot fabricate a human out of a token that says, on its face, that
it's an app.

**Read the code:** `verify_delegated_user` (`agent_common/principal.py:152-180`) — the
`is_app_token` guard that raises `delegated_token_not_a_user`, then the blocklist check. The
gateway calls this same shared function (Act 06's reuse point).

---

## 7.3 — Call an agent that doesn't know you

**Attack:** the gateway is *not* in the orchestrator's allowed-callers list (the call graph is
event-trigger→orchestrator, not gateway→orchestrator). Mint a gateway-identity token for the
orchestrator and call it.

```bash
uv run python docs/walkthrough/scripts/mint_agent_token.py --as gateway --for orchestrator --print-token
curl.exe -s -i -X POST http://localhost:10004/dispatch \
  -H "Authorization: Bearer <gateway-as-caller token>" \
  -H "Content-Type: application/json" -d '{"task":"status"}'
```

**Expected:** HTTP **403**, `denial_reason: unknown_agent` — assuming the gateway even *can*
mint a token for the orchestrator. (If gateway→orchestrator was never granted `Agent.Invoke` in
Act 04 §5, Entra won't mint the token at all and you'll get a minting error instead — also a
correct refusal, one layer earlier.)

**Why it holds:** even a perfectly valid, correctly-audienced agent token is refused if the
caller isn't on the callee's allow-list. Identity being genuine is not the same as being
authorized. The allow-list is `registry.allowed_callers_for("orchestrator")`, which returns
only `event-trigger`.

**Read the code:** `verify_agent_claims` (`agent_common/principal.py:91-149`) — the
`caller not in allowed_callers` check raising `unknown_agent`; the list comes from
`registry.allowed_callers_for` (`agent_common/registry.py:89-101`).

---

## 7.4 — Forge a token outright

**Attack:** the classic JWT forgeries — `alg=none` (a token with no signature), and HS256
key-confusion (signing with the provider's *public* key as if it were an HMAC secret). These
are the attacks that break systems which check claims before signatures.

You don't need to hand-craft these; the unit suite already does, adversarially. Run them
targeted and read them:

```bash
uv run pytest tests/test_agent_registry.py -v -k "alg_none or hs256 or forged"
```

**Expected:** all pass — meaning the forgeries are all **rejected** before any claim is read.

**Why it holds:** the validator pins `algorithms=["RS256"]` and verifies the signature against
the provider's JWKS public keys *first*. `alg=none` is refused because no signature verifies;
HS256-with-public-key is refused because the token wasn't signed with the private key. This is
the "signature first, claims second" rule — `azp`/`roles`/`aud` are attacker-supplied strings
until the signature check passes, so the check must come first.

**Read the code:** `agent_common/jwt_validator.py:114-136` — `jwt.decode(..., algorithms=["RS256"], ...)`
and the per-key retry loop. The tests are in `tests/test_agent_registry.py` (search for
`alg_none`, `hs256_confusion`, `forged`).

---

## 7.5 — Run the whole integration suite

Everything above is a spot-check. The 14-test integration suite is the systematic version — it
exercises the machine chain, the delegated chain, OBO narrowing, and the replay refusal against
your **real tenant**.

```bash
uv run pytest tests/ -m integration -v
```

**Expected:** with Act 04 fully done, these run and pass. If something's unconfigured, they
**skip with a reason** rather than fail — e.g. "AGENT_ORCHESTRATOR_CLIENT_ID not set" or
"orchestrator not running at :10004" or "TEST_ADMIN_TOKEN has expired." Read the skip messages;
they're written to point you at the exact missing piece.

**One honest caveat** (from `CLAUDE.md`): these integration tests were written but, at least as
of this walkthrough, had never been run against a live tenant — nothing had yet *proven* Entra
accepts a certificate assertion from these registrations. When you run them, you are closing
that gap for real. The open `groups` question from Act 06 is one of the things they settle.

**Read the code:** `tests/test_multi_agent_integration.py` — every test is marked
`pytest.mark.integration`; the module docstring is candid that these can't be mutation-tested,
and each assertion is cross-checked against the code it exercises.

---

## Architecture decision — signature-first, and fail-closed everywhere

**What was chosen:** verify the cryptographic signature before reading any claim, and make every
ambiguous case a refusal rather than an admission.

**The alternative:** read claims first for a fast-path decision (e.g. "if `azp` isn't a known
agent, reject early without the expensive signature check"), and treat missing/ambiguous data
leniently to avoid false denials.

**Why signature-first:** before the signature is verified, every claim is just bytes the
attacker chose. A fast-path that reads `azp` first is reading an attacker-controlled string; any
decision made on it is meaningless, and worse, it can leak information (timing, different error
messages) about what the system would accept. Signature-first means the *only* thing you act on
before verification is "does this verify," and everything else waits behind it.

**Why fail-closed:** the recurring temptation in identity code is a helpful fallback — "no
`idtyp`, probably a machine"; "OBO failed, proceed without the user token"; "unknown agent, give
it the default role." Each one turns a *failure* into a silent *downgrade* to a different, often
weaker, security posture — with a 200 and nothing to say so. This system refuses instead:
missing `idtyp` → treat as human and refuse the agent call; failed exchange → the hop fails;
unknown agent → no role. You occasionally pay for it with a denial that needs a config fix (the
whole of Act 04's checkpoints exist to surface those early), but you never pay for it with a
guarantee that quietly stopped holding.

**The trade-off:** stricter, louder, more setup, more denials-that-are-really-misconfigurations.
In exchange, there is no input — forged, replayed, fabricated, or merely malformed — that
converts into a smaller-than-intended set of checks.

---

> ### Checkpoint — Act 07
> **You have now proven:** cross-hop replay → 401 `validation_failed` (and you know why not
> 403); fabricated human → 403 `delegated_token_not_a_user`; uninvited caller → 403
> `unknown_agent`; and outright forgeries rejected before claims are read.
>
> **You now understand:** signature-first ordering, fail-closed as a deliberate posture, and why
> a genuine identity still isn't authorization.
>
> **Explain it in one sentence:** *"Every attack — replay, fabrication, impersonation, forgery —
> hits a check that runs before the thing it's trying to exploit, and every ambiguous case is a
> refusal, so there's no input that buys you fewer checks than intended."*

Next: [Act 08 — orchestration security, synthesized](08-orchestration-security.md). Put the whole
picture together.
