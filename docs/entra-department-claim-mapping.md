# Entra ID — Adding `department` as a Token Claim

The Cedar pre-check for ServiceNow's dept-scoped tools reads
`principal.department` from the validated JWT. By default, Entra ID does
**not** include the user-profile `department` field in access tokens. You
add it once as an optional claim on your App Registration.

This guide is for the same Entra App Registration that already powers the
A2A gateway's JWT validation.

## What you need

- Admin access to the Microsoft Entra admin center
  (https://entra.microsoft.com/)
- The App Registration's Application (client) ID
- At least one test user with a `Department` field populated on their
  profile (Users → User → Edit → Department)

## Step 1 — Add `department` as an optional claim

1. Sign into the Entra admin center.
2. Navigate: **Identity → Applications → App registrations → \<your app\>**.
3. In the left nav, click **Token configuration**.
4. Click **+ Add optional claim**.
5. Select **Access token** (the agent reads access-token claims, not ID
   tokens).
6. Tick `department`. Click **Add**.
7. If prompted to grant Microsoft Graph **User.Read** delegated permission
   (Entra automatically requests this when adding `department`), accept and
   click **Add**.
8. Save.

The next access token issued by Entra will include a `department` claim
matching the user's profile field.

## Step 2 — Populate the test users' `Department` field

For the tests to be meaningful, each test user needs a `Department` set:

- **Users → User → Properties (or Edit)**
- Set `Department` to one of: `IT`, `HR`, `Finance` (must match the KB
  `u_department` values you set in `docs/servicenow-integration.md`).

Suggested minimum set of test users:

| User                | Role group      | Department |
|---------------------|-----------------|------------|
| `admin@<tenant>`    | admin group     | _(empty)_  |
| `dev-it@<tenant>`   | developer group | IT         |
| `dev-hr@<tenant>`   | developer group | HR         |
| `viewer-it@<tenant>`| viewer group    | IT         |
| `viewer-fn@<tenant>`| viewer group    | Finance    |

Admin users typically have no department (or `admin` if you want to model
that explicitly) — admin's Cedar permits are not dept-conditional.

## Step 3 — Verify the claim is in the issued token

Sign in to the frontend (port 10003) as one of the test users. Open the
**Security Context** panel:

- The **Department** badge should show the user's `Department` value.
- If it shows `— (no claim)`, either the optional claim is missing (Step 1)
  or the user's profile field is empty (Step 2).

You can also inspect the JWT directly via the **Token Inspector** panel —
look for the `department` claim in the payload.

## Cognito equivalent (when applicable)

For Cognito users (multi-IdP fallback path), the corresponding setup is:

1. **User Pool → Sign-up experience → Custom attributes** → add
   `custom:department` (mutable, string).
2. Backfill values via the AWS CLI or Cognito console for each test user:
   ```powershell
   aws cognito-idp admin-update-user-attributes `
     --user-pool-id us-east-1_XXXX `
     --username dev-it@example.com `
     --user-attributes Name=custom:department,Value=IT
   ```

The MCP server's claim extractor already handles both providers — see
`mcp_server/policy.py` (`ABAC_CLAIM_KEYS = {"department": str, "archiver": bool}`).

## Security note

The X-Abac-Attrs header **cannot** override the `department` claim. The
A2A and MCP servers strip `department` from the header during parsing
(`dev_config.parse_abac_attrs` → `HEADER_BLOCKED_ABAC_KEYS`). This prevents
a client with a valid token from spoofing their department to gain cross-dept
access. The `archiver` attribute remains header-overridable (intentional —
that's how the frontend toggle works for `delete_s3_object`).
