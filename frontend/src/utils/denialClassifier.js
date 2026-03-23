// LLM may paraphrase tool denials -- these patterns catch common phrasings
const TOOL_SOFT_DENIAL_PATTERNS = [
  /don't have the ability to/i,
  /don't have access to.*(tool|function)/i,
  /don't have permission to/i,
  /restricted to admin/i,
  /tools available to me are limited/i,
  /Tool.*not found/i,
];

const GRAPH_DENIAL_PATTERNS = [
  /graph_api_unavailable/i,
  /(401|403).*graph/i,
  /graph.*(401|403)/i,
  /401.*unauthorized/i,
  /OBO flow/i,
  /insufficient_scope/i,
  /Access is denied/i,
];

function matchesAny(text, patterns) {
  return patterns.some(p => p.test(text));
}

/**
 * Classify a denial by tier based on HTTP status and response content.
 * Returns { level, reason } or null for success.
 */
export function classifyDenial(httpStatus, responseBody, responseText) {
  if (httpStatus === 401 || httpStatus === 403) {
    const reason = responseBody?.denial_reason || responseBody?.error || 'unknown';
    return { level: 'agent', reason };
  }

  const text = responseText || '';

  // Explicit denial tags from MCP ToolError
  if (text.includes('[TOOL_DENIAL]')) {
    return { level: 'tool', reason: 'role_denied' };
  }
  if (text.includes('[SCOPE_DENIAL]')) {
    return { level: 'scope', reason: 'missing_scopes' };
  }

  // Fallback regex patterns for LLM-paraphrased denials
  if (/Role.*cannot use/i.test(text)) {
    return { level: 'tool', reason: 'role_denied' };
  }
  if (matchesAny(text, TOOL_SOFT_DENIAL_PATTERNS)) {
    return { level: 'tool', reason: 'tool_not_available' };
  }
  if (/Missing scopes/i.test(text) || /Insufficient permissions/i.test(text)) {
    return { level: 'scope', reason: 'missing_scopes' };
  }

  // Graph API resource-level denial
  if (matchesAny(text, GRAPH_DENIAL_PATTERNS)) {
    return { level: 'resource', reason: 'graph_api_denied' };
  }

  // S3/AWS resource-level errors
  if (/aws_not_configured/i.test(text) || /s3_access_denied/i.test(text)) {
    return { level: 'resource', reason: 'aws_error' };
  }

  // Generic access denied (but not role-based, which was already caught above)
  if (/Access denied/i.test(text) && !/Role.*cannot/i.test(text)) {
    return { level: 'tool', reason: 'access_denied' };
  }

  return null;
}
