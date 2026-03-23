import React, { useState, useRef, useEffect } from 'react';
import { useAuth } from '../AuthProvider';
import { sendA2AMessage, buildAuditEntry } from '../utils/a2aClient';
import DenialIndicator from './DenialIndicator';

const ROLE_LABELS = { user: 'You', agent: 'Agent', system: 'System' };

export default function ChatInterface({ scopeKey, onAuditEntry, selectedRole }) {
  const { getAccessToken } = useAuth();
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const emitAudit = (entry) => {
    if (onAuditEntry) onAuditEntry(entry);
  };

  const sendMessage = async (e) => {
    e.preventDefault();
    const userMessage = input.trim();
    if (!userMessage || loading) return;

    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);

    try {
      const accessToken = await getAccessToken(scopeKey);
      const result = await sendA2AMessage({ accessToken, message: userMessage, selectedRole });

      setMessages(prev => [...prev, {
        role: result.isAuthError ? 'system' : 'agent',
        content: result.responseText,
        isError: result.isAuthError,
        denial: result.denial,
      }]);

      emitAudit(buildAuditEntry({
        prompt: userMessage, scopeKey, selectedRole,
        httpStatus: result.httpStatus, denial: result.denial,
        latency: result.latency, response: result.body,
      }));
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'system',
        content: `Error: ${err.message}`,
        isError: true,
      }]);

      emitAudit(buildAuditEntry({
        prompt: userMessage, scopeKey, selectedRole,
        httpStatus: 0, denial: null, latency: 0,
        response: { error: err.message },
      }));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="chat-interface">
      <div className="messages">
        {messages.length === 0 && (
          <div className="welcome-message">
            <p>Start a conversation. Try asking:</p>
            <ul>
              <li>"What's my email?"</li>
              <li>"Show my profile"</li>
              <li>"List my files"</li>
              <li>"List my S3 buckets"</li>
              <li>"What time is it in Tokyo?"</li>
            </ul>
          </div>
        )}
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role} ${msg.isError ? 'error' : ''}`}>
            <div className="message-header">
              <strong>{ROLE_LABELS[msg.role] || msg.role}</strong>
              {msg.denial && <DenialIndicator level={msg.denial.level} reason={msg.denial.reason} />}
            </div>
            <p>{msg.content}</p>
          </div>
        ))}
        {loading && (
          <div className="message agent loading">
            <span className="typing-indicator">Agent is thinking...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={sendMessage} className="input-form">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Type a message..."
          disabled={loading}
        />
        <button type="submit" disabled={loading || !input.trim()}>Send</button>
      </form>
    </div>
  );
}
