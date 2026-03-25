// ── ABAC Policies ──────────────────────────────────────────────────
// Attribute-based access control — delete_s3_object is ABAC-only.
// No RBAC role grants access; only the archiver attribute does.
// Demonstrates: permissions based on user attributes, not roles.

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
