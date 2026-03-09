import React, { useState, useEffect, useCallback } from 'react';
import { useMsal, useAccount } from '@azure/msal-react';
import { InteractionRequiredAuthError } from '@azure/msal-browser';
import { graphScopes } from '../authConfig';

const A2A_SERVER_URL = process.env.REACT_APP_A2A_SERVER_URL || 'http://localhost:10000';

const ROLE_COLORS = {
  admin: 'role-admin',
  developer: 'role-developer',
  viewer: 'role-viewer',
  none: 'role-none',
};

export default function SecurityContextPanel({ scopeKey, onSecurityContext, selectedRole, onRoleChange }) {
  const { instance, accounts } = useMsal();
  const account = useAccount(accounts[0] || {});
  const [securityCtx, setSecurityCtx] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expiryCountdown, setExpiryCountdown] = useState('');

  const fetchSecurityContext = useCallback(async () => {
    if (!account) return;
    setLoading(true);
    setError(null);

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

      const response = await fetch(`${A2A_SERVER_URL}/me`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          ...(selectedRole && { 'X-Assume-Role': selectedRole }),
        },
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.message || `HTTP ${response.status}`);
      }

      const data = await response.json();
      setSecurityCtx(data);
      if (onSecurityContext) onSecurityContext(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [instance, account, scopeKey, selectedRole, onSecurityContext]);

  useEffect(() => {
    fetchSecurityContext();
    const handler = () => fetchSecurityContext();
    window.addEventListener('msal-account-change', handler);
    return () => window.removeEventListener('msal-account-change', handler);
  }, [fetchSecurityContext]);

  // Token expiry countdown
  useEffect(() => {
    if (!securityCtx?.security?.token_expiry) return;

    const update = () => {
      const exp = securityCtx.security.token_expiry;
      const now = Math.floor(Date.now() / 1000);
      const diff = exp - now;

      if (diff <= 0) {
        setExpiryCountdown('EXPIRED');
        return;
      }
      const mins = Math.floor(diff / 60);
      const secs = diff % 60;
      setExpiryCountdown(`${mins}:${String(secs).padStart(2, '0')}`);
    };

    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [securityCtx?.security?.token_expiry]);

  // Auto-select highest available role on initial load
  useEffect(() => {
    if (securityCtx?.security?.available_roles?.length && !selectedRole) {
      onRoleChange(securityCtx.security.available_roles[0]);
    }
  }, [securityCtx, selectedRole, onRoleChange]);

  if (loading && !securityCtx) {
    return <div className="security-panel"><p className="panel-loading">Loading security context...</p></div>;
  }

  if (error) {
    return (
      <div className="security-panel">
        <p className="panel-error">{error}</p>
        <button className="btn-small" onClick={fetchSecurityContext}>Retry</button>
      </div>
    );
  }

  if (!securityCtx) return null;

  const { security, user, permissions } = securityCtx;
  const expiryClass = expiryCountdown === 'EXPIRED' ? 'expiry-expired'
    : (securityCtx.security.token_expiry - Math.floor(Date.now() / 1000) < 300 ? 'expiry-warning' : 'expiry-ok');

  return (
    <div className="security-panel">
      <h3 className="panel-title">Security Context</h3>

      <div className="panel-section">
        <label>User</label>
        <div className="panel-value">{user.name || user.email}</div>
      </div>

      <div className="panel-section">
        <label>Role</label>
        {security.available_roles && security.available_roles.length > 0 ? (
          <select
            className={`role-select role-${selectedRole || security.role}`}
            value={selectedRole || security.role}
            onChange={(e) => onRoleChange(e.target.value)}
          >
            {security.available_roles.map(r => (
              <option key={r} value={r}>{r.toUpperCase()}</option>
            ))}
          </select>
        ) : (
          <span className={`role-badge ${ROLE_COLORS[security.role] || 'role-none'}`}>
            {security.role.toUpperCase()}
          </span>
        )}
      </div>

      <div className="panel-section">
        <label>Groups</label>
        <div className="panel-groups">
          {security.groups.length === 0 && <span className="panel-muted">None</span>}
          {security.groups.map(gid => (
            <div key={gid} className="group-item">
              <span className="group-role">{security.group_names[gid] || 'unknown'}</span>
              <span className="group-id" title={gid}>{gid.substring(0, 8)}...</span>
            </div>
          ))}
        </div>
      </div>

      <div className="panel-section">
        <label>Token Scopes</label>
        <div className="scope-tags">
          {security.token_scopes.length === 0 && <span className="panel-muted">None</span>}
          {security.token_scopes.map(s => (
            <span key={s} className="scope-tag">{s}</span>
          ))}
        </div>
      </div>

      <div className="panel-section">
        <label>Token Expiry</label>
        <span className={`expiry-countdown ${expiryClass}`}>{expiryCountdown}</span>
      </div>

      <div className="panel-section">
        <label>Permissions</label>
        <div className="permission-list">
          {Object.entries(permissions).map(([tool, allowed]) => (
            <div key={tool} className={`permission-item ${allowed ? 'perm-allowed' : 'perm-denied'}`}>
              <span className="perm-indicator">{allowed ? '\u2713' : '\u2717'}</span>
              <span className="perm-name">{tool}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
