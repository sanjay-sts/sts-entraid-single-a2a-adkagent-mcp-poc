// ── ABAC Policies ──────────────────────────────────────────────────
// Attribute-based access control beyond simple RBAC.
// Demonstrates: same role, different permissions based on attributes.

// Developer with archiver attribute can delete S3 objects in archive/ only.
// Admin access to delete_s3_object comes from the blanket admin permit in rbac.cedar.
permit(
  principal in AgentAuth::Role::"developer",
  action == AgentAuth::Action::"call_tool",
  resource == AgentAuth::Tool::"delete_s3_object"
) when {
  principal has archiver &&
  principal.archiver == true &&
  context has resource_path &&
  context.resource_path like "archive/*"
};
