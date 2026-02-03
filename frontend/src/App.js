import React, { useState, useCallback } from 'react';
import { useMsal, useAccount, AuthenticatedTemplate, UnauthenticatedTemplate } from '@azure/msal-react';
import { InteractionRequiredAuthError } from '@azure/msal-browser';
import { loginRequest, graphScopes } from './authConfig';

const A2A_SERVER_URL = process.env.REACT_APP_A2A_SERVER_URL || 'http://localhost:8000';

function App() {
  return (
    <div className="app">
      <header>
        <h1>Identity-Aware AI Agent</h1>
        <AuthStatus />
      </header>

      <main>
        <AuthenticatedTemplate>
          <ChatInterface />
        </AuthenticatedTemplate>

        <UnauthenticatedTemplate>
          <LoginPrompt />
        </UnauthenticatedTemplate>
      </main>
    </div>
  );
}

function AuthStatus() {
  const { instance, accounts } = useMsal();
  const account = useAccount(accounts[0] || {});

  const handleLogin = () => {
    instance.loginPopup(loginRequest).catch(console.error);
  };

  const handleLogout = () => {
    instance.logoutPopup({ postLogoutRedirectUri: '/' });
  };

  if (account) {
    return (
      <div className="auth-status">
        <span>Signed in as: {account.username}</span>
        <button onClick={handleLogout}>Sign Out</button>
      </div>
    );
  }

  return (
    <div className="auth-status">
      <button onClick={handleLogin}>Sign In with Microsoft</button>
    </div>
  );
}

function LoginPrompt() {
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

function ChatInterface() {
  const { instance, accounts } = useMsal();
  const account = useAccount(accounts[0] || {});
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedScopes, setSelectedScopes] = useState('basic');
  const [error, setError] = useState(null);

  // Acquire token with selected scopes
  const getAccessToken = useCallback(async () => {
    const scopes = graphScopes[selectedScopes];

    try {
      // Try silent acquisition first
      const response = await instance.acquireTokenSilent({
        scopes,
        account,
      });
      return response.accessToken;
    } catch (error) {
      if (error instanceof InteractionRequiredAuthError) {
        // Fallback to popup
        const response = await instance.acquireTokenPopup({ scopes });
        return response.accessToken;
      }
      throw error;
    }
  }, [instance, account, selectedScopes]);

  // Send message to A2A server
  const sendMessage = async (e) => {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const userMessage = input.trim();
    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);
    setError(null);

    try {
      const accessToken = await getAccessToken();

      const response = await fetch(A2A_SERVER_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'message/send',
          params: {
            message: {
              messageId: `msg-${Date.now()}`,
              role: 'user',
              parts: [{ kind: 'text', text: userMessage }],
            },
          },
          id: `req-${Date.now()}`,
        }),
      });

      if (response.status === 401) {
        setError('Authentication failed. Please sign in again.');
        setMessages(prev => [...prev, {
          role: 'system',
          content: 'Authentication failed. Please sign in again.',
          isError: true
        }]);
        return;
      }

      if (response.status === 403) {
        const errorData = await response.json();
        const errorMessage = errorData.message || 'You do not have permission to use this agent.';
        setError(`Access denied: ${errorMessage}`);
        setMessages(prev => [...prev, {
          role: 'system',
          content: `Access denied: ${errorMessage}`,
          isError: true
        }]);
        return;
      }

      const data = await response.json();

      if (data.error) {
        setMessages(prev => [...prev, {
          role: 'system',
          content: `Error: ${data.error.message}`,
          isError: true
        }]);
      } else if (data.result?.message) {
        const agentText = data.result.message.parts
          .filter(p => p.kind === 'text')
          .map(p => p.text)
          .join('\n');
        setMessages(prev => [...prev, { role: 'agent', content: agentText }]);
      }

    } catch (err) {
      console.error('Chat error:', err);
      setError(err.message);
      setMessages(prev => [...prev, {
        role: 'system',
        content: `Error: ${err.message}`,
        isError: true
      }]);
    } finally {
      setLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([]);
    setError(null);
  };

  return (
    <div className="chat-container">
      <div className="scope-selector">
        <label>Permission Level:</label>
        <select value={selectedScopes} onChange={e => setSelectedScopes(e.target.value)}>
          <option value="basic">Basic (User.Read)</option>
          <option value="files">Files (+ Files.Read)</option>
          <option value="email">Email (+ Mail.Send)</option>
          <option value="full">Full Access</option>
        </select>
        <span className="scope-hint">
          Selected scopes: {graphScopes[selectedScopes].join(', ')}
        </span>
        <button className="clear-button" onClick={clearChat}>Clear Chat</button>
      </div>

      {error && (
        <div className="error-banner">
          {error}
          <button onClick={() => setError(null)}>x</button>
        </div>
      )}

      <div className="messages">
        {messages.length === 0 && (
          <div className="welcome-message">
            <p>Start a conversation with the agent. Try asking:</p>
            <ul>
              <li>"What's my email?"</li>
              <li>"What are my permissions?"</li>
              <li>"List my files"</li>
              <li>"Show my profile"</li>
            </ul>
          </div>
        )}
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role} ${msg.isError ? 'error' : ''}`}>
            <strong>{msg.role === 'user' ? 'You' : msg.role === 'agent' ? 'Agent' : 'System'}:</strong>
            <p>{msg.content}</p>
          </div>
        ))}
        {loading && (
          <div className="message agent loading">
            <span className="typing-indicator">Agent is thinking...</span>
          </div>
        )}
      </div>

      <form onSubmit={sendMessage} className="input-form">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Type a message..."
          disabled={loading}
        />
        <button type="submit" disabled={loading || !input.trim()}>
          Send
        </button>
      </form>
    </div>
  );
}

export default App;
