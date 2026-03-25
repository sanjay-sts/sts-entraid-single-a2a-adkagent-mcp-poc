// ── RBAC Policies ──────────────────────────────────────────────────
// Replaces require_role() decorators on MCP tools.
// Role membership is modeled via Cedar entity hierarchy: User in [Role].

// ── Admin: all tools except delete_s3_object ──────────────────────
// delete_s3_object is ABAC-only — requires archiver=true attribute.
// No RBAC role grants access; see abac.cedar for the permit.
permit(
  principal in AgentAuth::Role::"admin",
  action == AgentAuth::Action::"call_tool",
  resource
) when {
  resource != AgentAuth::Tool::"delete_s3_object"
};

// ── Developer: specific tools ───────────────────────────────────────
permit(
  principal in AgentAuth::Role::"developer",
  action == AgentAuth::Action::"call_tool",
  resource
) when {
  resource == AgentAuth::Tool::"get_user_profile" ||
  resource == AgentAuth::Tool::"list_files" ||
  resource == AgentAuth::Tool::"list_s3_buckets" ||
  resource == AgentAuth::Tool::"list_s3_objects" ||
  resource == AgentAuth::Tool::"get_s3_object_info"
};
// NOTE: delete_s3_object is excluded from ALL RBAC permits.
// Access is granted solely via ABAC policy (abac.cedar) for users
// with archiver=true attribute, regardless of role.

// ── Viewer: limited tools ───────────────────────────────────────────
permit(
  principal in AgentAuth::Role::"viewer",
  action == AgentAuth::Action::"call_tool",
  resource
) when {
  resource == AgentAuth::Tool::"get_user_profile" ||
  resource == AgentAuth::Tool::"get_s3_object_info"
};

// ── Tool listing: all authenticated users can discover tools ────────
permit(
  principal,
  action == AgentAuth::Action::"list_tools",
  resource
);
