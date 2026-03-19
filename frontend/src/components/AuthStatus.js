import React from 'react';
import { useAuth } from '../AuthProvider';

const PROVIDER_LABELS = {
  entra: 'Entra ID',
  cognito: 'Cognito',
};

export default function AuthStatus() {
  const { provider, isAuthenticated, user, login, logout, switchProvider } = useAuth();

  if (!isAuthenticated) {
    if (!provider) {
      return (
        <div className="auth-status">
          <button onClick={() => login('entra')}>Sign In (Entra)</button>
          <button className="btn-secondary" onClick={() => login('cognito')}>Sign In (Cognito)</button>
        </div>
      );
    }
    return (
      <div className="auth-status">
        <span className="auth-username">Connecting...</span>
      </div>
    );
  }

  return (
    <div className="auth-status">
      <span className={`provider-badge provider-${provider}`}>
        {PROVIDER_LABELS[provider] || provider}
      </span>
      <span className="auth-username">{user?.email || 'Unknown'}</span>
      <button onClick={logout}>Sign Out</button>
      <button
        className="btn-secondary"
        onClick={() => {
          switchProvider(null);
        }}
        title="Switch identity provider"
      >
        Switch IdP
      </button>
    </div>
  );
}
