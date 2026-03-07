import React from 'react';
import { useMsal } from '@azure/msal-react';
import { loginRequest } from '../authConfig';

export default function LoginPrompt() {
  const { instance } = useMsal();

  return (
    <div className="login-prompt">
      <h2>Welcome to the Identity-Aware AI Agent</h2>
      <p>Sign in with your Microsoft account to start chatting.</p>
      <p className="description">
        This agent respects your identity and permissions at multiple levels:
      </p>
      <ul className="features">
        <li><strong>Agent Level:</strong> Access control based on group membership</li>
        <li><strong>Tool Level:</strong> Role-based permissions for different operations</li>
        <li><strong>Resource Level:</strong> OAuth scopes enforce data access</li>
      </ul>
      <button
        className="login-button"
        onClick={() => instance.loginPopup(loginRequest)}
      >
        Sign In with Microsoft
      </button>
    </div>
  );
}
