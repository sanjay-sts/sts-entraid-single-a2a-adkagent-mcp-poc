import React, { useState, useEffect, useCallback } from 'react';
import { useMsal, useAccount } from '@azure/msal-react';
import { InteractionRequiredAuthError } from '@azure/msal-browser';
import { graphScopes } from '../authConfig';
import { decodeToken } from '../utils/tokenDecoder';

const HIGHLIGHT_FIELDS = ['groups', 'scp', 'aud', 'iss', 'exp', 'oid', 'sub', 'preferred_username'];

export default function TokenInspector({ scopeKey }) {
  const { instance, accounts } = useMsal();
  const account = useAccount(accounts[0] || {});
  const [collapsed, setCollapsed] = useState(true);
  const [decoded, setDecoded] = useState(null);

  const refresh = useCallback(async () => {
    if (!account) return;
    try {
      const scopes = graphScopes[scopeKey] || graphScopes.basic;
      let accessToken;
      try {
        const resp = await instance.acquireTokenSilent({ scopes, account });
        accessToken = resp.accessToken;
      } catch (err) {
        if (err instanceof InteractionRequiredAuthError) {
          const resp = await instance.acquireTokenPopup({ scopes });
          accessToken = resp.accessToken;
        } else {
          throw err;
        }
      }
      setDecoded(decodeToken(accessToken));
    } catch {
      setDecoded(null);
    }
  }, [instance, account, scopeKey]);

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
