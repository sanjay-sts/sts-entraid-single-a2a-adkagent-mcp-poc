import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../AuthProvider';
import { decodeToken } from '../utils/tokenDecoder';

const HIGHLIGHT_FIELDS = ['groups', 'cognito:groups', 'scp', 'scope', 'aud', 'iss', 'exp', 'oid', 'sub', 'preferred_username', 'email'];

export default function TokenInspector({ scopeKey }) {
  const { isAuthenticated, getAccessToken } = useAuth();
  const [collapsed, setCollapsed] = useState(true);
  const [decoded, setDecoded] = useState(null);

  const refresh = useCallback(async () => {
    if (!isAuthenticated) return;
    try {
      const accessToken = await getAccessToken(scopeKey);
      setDecoded(accessToken ? decodeToken(accessToken) : null);
    } catch {
      setDecoded(null);
    }
  }, [isAuthenticated, getAccessToken, scopeKey]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <div className="token-inspector">
      <h3
        className="panel-title collapsible"
        onClick={() => setCollapsed(!collapsed)}
      >
        Token Inspector {collapsed ? '\u25B6' : '\u25BC'}
      </h3>

      {!collapsed && decoded && (
        <div className="token-content">
          <div className="token-section">
            <h4>Header</h4>
            <pre className="token-json">{JSON.stringify(decoded.header, null, 2)}</pre>
          </div>
          <div className="token-section">
            <h4>Payload</h4>
            <div className="token-claims">
              {Object.entries(decoded.payload).map(([key, value]) => (
                <div
                  key={key}
                  className={`claim-row ${HIGHLIGHT_FIELDS.includes(key) ? 'claim-highlight' : ''}`}
                >
                  <span className="claim-key">{key}</span>
                  <span className="claim-value">
                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {!collapsed && !decoded && (
        <p className="panel-muted">No token to inspect</p>
      )}
    </div>
  );
}
