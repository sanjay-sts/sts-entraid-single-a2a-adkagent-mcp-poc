/**
 * Decode a JWT token's header and payload without verification.
 * Uses atob() for base64url decoding - display only, never for authorization.
 */
export function decodeToken(token) {
  if (!token) return null;

  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));

    return { header, payload };
  } catch {
    return null;
  }
}

function base64UrlDecode(str) {
  // Replace base64url chars with base64 chars
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Pad with '=' if needed
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return atob(base64);
}
