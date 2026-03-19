import React from 'react';
import { useAuth } from '../AuthProvider';

export default function LoginPrompt() {
  const { login, provider } = useAuth();

  return (
    <div className="login-prompt">
      <h2>Welcome to the Identity-Aware AI Agent</h2>
      <p>Sign in to start chatting. Choose your identity provider:</p>
      <p className="description">
        This agent respects your identity and permissions at multiple levels:
      </p>
      <ul className="features">
        <li><strong>Agent Level:</strong> Access control based on group membership</li>
        <li><strong>Tool Level:</strong> Role-based permissions for different operations</li>
        <li><strong>Resource Level:</strong> OAuth scopes enforce data access</li>
      </ul>
      <div className="login-buttons">
        <button
          className="login-button login-entra"
          onClick={() => login('entra')}
        >
          Sign In with Microsoft Entra ID
        </button>
        <button
          className="login-button login-cognito"
          onClick={() => login('cognito')}
        >
          Sign In with AWS Cognito
        </button>
      </div>
      {provider && (
        <p className="login-status">
          Redirecting to {provider === 'entra' ? 'Microsoft' : 'AWS Cognito'}...
        </p>
      )}
    </div>
  );
}
