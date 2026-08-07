# Agent PKI

Local mini-CA issuing one key pair per agent. Each agent's **private key**
signs its Entra client assertion; the **public certificate** is uploaded to
that agent's app registration.

## Generate

    uv run python pki/generate_certs.py

Produces `pki/certs/`: `ca.key`, `ca.crt`, and `<agent>.key` / `<agent>.crt`
for `gateway`, `orchestrator`, `peer`, `event-trigger`.

`pki/certs/` is gitignored. Regenerating invalidates every uploaded cert —
you must re-upload to Entra (see `docs/ENTRA_AGENT_SETUP.md`).

## Production

An enterprise CA (AWS Private CA, DigiCert, Venafi, Vault PKI) replaces this
script with **no code change**:

- For **Entra client assertions**, the CA is irrelevant — Entra matches the
  assertion signature against the exact uploaded public cert; it does not
  walk a chain. Self-signed and CA-issued are equivalent here.
- For **mTLS** (Phase 2), the CA chain *is* the trust root, replacing `ca.crt`.

What the CA buys: policy-controlled issuance, central inventory, automated
rotation, revocation (CRL/OCSP), audit trail.
