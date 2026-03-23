// ── Guardrail Policies ─────────────────────────────────────────────
// Hard safety limits. Forbid always overrides permit in Cedar.

// No one can delete in protected/ — not even admin.
forbid(
  principal,
  action == AgentAuth::Action::"call_tool",
  resource == AgentAuth::Tool::"delete_s3_object"
) when {
  context has resource_path &&
  context.resource_path like "protected/*"
};
