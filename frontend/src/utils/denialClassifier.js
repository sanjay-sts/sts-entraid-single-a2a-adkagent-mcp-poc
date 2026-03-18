/**
 * Classify a denial by tier based on HTTP status and response content.
 *
 * Returns: { level: 'agent'|'tool'|'scope'|'resource', reason: string } or null for success.
 */
export function classifyDenial(httpStatus, responseBody, responseText) {
  // 1. HTTP 401/403 from A2A server → agent level
  if (httpStatus === 401 || httpStatus === 403) {
    const reason = responseBody?.denial_reason || responseBody?.error || 'unknown';
    return { level: 'agent', reason };
  }

  const text = responseText || '';

  // 2. Explicit TOOL_DENIAL tag from MCP ToolError
  if (text.includes('[TOOL_DENIAL]')) {
    return { level: 'tool', reason: 'role_denied' };
  }

  // 3. Explicit SCOPE_DENIAL tag from MCP ToolError
  if (text.includes('[SCOPE_DENIAL]')) {
    return { level: 'scope', reason: 'missing_scopes' };
  }

  // 4. Fallback regex patterns (LLM may paraphrase)
  if (/Role.*cannot use/i.test(text)) {
    return { level: 'tool', reason: 'role_denied' };
  }
  // 4b. LLM soft denial — tool not exposed for this role (LLM says it can't do it)
  if (/don't have the ability to/i.test(text) ||
      /don't have access to.*tool/i.test(text) ||
      /don't have permission to/i.test(text) ||
      /restricted to admin/i.test(text) ||
      /tools available to me are limited/i.test(text)) {
    return { level: 'tool', reason: 'tool_not_available' };
  }
  if (/Missing scopes/i.test(text) || /Insufficient permissions/i.test(text)) {
    return { level: 'scope', reason: 'missing_scopes' };
  }

  // 5. Graph API resource-level denial (401 or 403)
  if (/graph_api_unavailable/i.test(text) ||
      /(401|403).*graph/i.test(text) ||
      /graph.*(401|403)/i.test(text) ||
      /401.*unauthorized/i.test(text) ||
      /OBO flow/i.test(text) ||
      /insufficient_scope/i.test(text) ||
      /Access is denied/i.test(text)) {
    return { level: 'resource', reason: 'graph_api_denied' };
  }

  // 6. Generic access denied in response text
  if (/Access denied/i.test(text) && !/Role.*cannot/i.test(text)) {
    return { level: 'tool', reason: 'access_denied' };
  }

  return null;
}
