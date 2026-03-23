import { A2A_SERVER_URL } from './constants';
import { classifyDenial } from './denialClassifier';

/**
 * Extract text content from an A2A JSON-RPC response body.
 * Handles both `result.status.message.parts` and `result.message.parts` shapes.
 */
function extractResponseText(data) {
  if (data.error) {
    return `Error: ${data.error.message}`;
  }

  const parts =
    data.result?.status?.message?.parts ||
    data.result?.message?.parts;

  if (parts) {
    const text = parts
      .filter(p => p.kind === 'text' || p.type === 'text')
      .map(p => p.text)
      .join('\n');
    return text || 'No text response';
  }

  console.log('Unexpected A2A response format:', JSON.stringify(data, null, 2));
  return 'Received response (check console for format)';
}

/**
 * Send a message to the A2A server via JSON-RPC.
 * Returns { httpStatus, body, responseText, latency, isAuthError, denial }.
 */
export async function sendA2AMessage({ accessToken, message, selectedRole }) {
  const startTime = performance.now();

  const response = await fetch(A2A_SERVER_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
      ...(selectedRole && { 'X-Assume-Role': selectedRole }),
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'message/send',
      params: {
        message: {
          messageId: `msg-${Date.now()}`,
          role: 'user',
          parts: [{ type: 'text', text: message }],
        },
      },
      id: `req-${Date.now()}`,
    }),
  });

  const latency = Math.round(performance.now() - startTime);
  const httpStatus = response.status;
  const isAuthError = httpStatus === 401 || httpStatus === 403;

  if (isAuthError) {
    const body = await response.json().catch(() => ({}));
    const responseText = body.message || 'Access denied';
    const denial = classifyDenial(httpStatus, body, responseText);
    return { httpStatus, body, responseText, latency, isAuthError, denial };
  }

  const body = await response.json();
  const responseText = extractResponseText(body);
  const denial = classifyDenial(httpStatus, null, responseText);
  return { httpStatus, body, responseText, latency, isAuthError, denial };
}

/**
 * Build a standardized audit log entry from a request/response pair.
 */
export function buildAuditEntry({ prompt, scopeKey, selectedRole, httpStatus, denial, latency, response }) {
  return {
    timestamp: new Date().toISOString(),
    prompt,
    scopeKey,
    role: selectedRole,
    httpStatus,
    denial,
    latency,
    response,
  };
}
