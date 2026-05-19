// ── ABAC Policies ──────────────────────────────────────────────────
// Attribute-based access control.
// Two patterns:
//   1. delete_s3_object — pure ABAC (archiver attribute, no role gate)
//   2. ServiceNow dept-scoped tools — composite role + department check

// ── delete_s3_object: archiver attribute, archive/* path ────────────
// Any user with archiver=true can delete S3 objects in archive/ only.
// Role is irrelevant — admin, developer, viewer all denied without archiver.
// The archiver attribute comes from Cognito access token customization.
permit(
  principal,
  action == AgentAuth::Action::"call_tool",
  resource == AgentAuth::Tool::"delete_s3_object"
) when {
  principal has archiver &&
  principal.archiver == true &&
  context has resource_path &&
  context.resource_path like "archive/*"
};

// ── ServiceNow: developer composite role + department ──────────────
// Developer can call dept-scoped SN tools only when their department
// claim matches the resource's target_department context. This is the
// "claim → Cedar pre-check" gap-closure path.
permit(
  principal in AgentAuth::Role::"developer",
  action == AgentAuth::Action::"call_tool",
  resource
) when {
  (resource == AgentAuth::Tool::"list_articles" ||
   resource == AgentAuth::Tool::"list_incidents" ||
   resource == AgentAuth::Tool::"create_incident" ||
   resource == AgentAuth::Tool::"update_incident") &&
  principal has department &&
  context has target_department &&
  principal.department == context.target_department
};

// ── ServiceNow: viewer composite role + department (KB articles only) ─
// Viewer can read articles in their department's KB only.
// Incidents are entirely off-limits to viewer.
permit(
  principal in AgentAuth::Role::"viewer",
  action == AgentAuth::Action::"call_tool",
  resource == AgentAuth::Tool::"list_articles"
) when {
  principal has department &&
  context has target_department &&
  principal.department == context.target_department
};
