import React, { useState, useCallback, useRef, useEffect } from 'react';
import { useAuth } from '../AuthProvider';
import { classifyDenial } from '../utils/denialClassifier';
import DenialIndicator from './DenialIndicator';

const A2A_SERVER_URL = process.env.REACT_APP_A2A_SERVER_URL || 'http://localhost:10000';

export default function ChatInterface({ scopeKey, onAuditEntry, selectedRole }) {
  const { getAccessToken } = useAuth();
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = async (e, overrideMessage) => {
    if (e) e.preventDefault();
    const userMessage = overrideMessage || input.trim();
    if (!userMessage || loading) return;

    if (!overrideMessage) setInput('');
    setMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setLoading(true);

    const startTime = performance.now();
    let httpStatus = 0;
    let responseBody = null;
    let denial = null;

    try {
      const accessToken = await getAccessToken(scopeKey);

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
              parts: [{ type: 'text', text: userMessage }],
            },
          },
          id: `req-${Date.now()}`,
        }),
      });

      httpStatus = response.status;
      const latency = Math.round(performance.now() - startTime);

      if (response.status === 401 || response.status === 403) {
        responseBody = await response.json().catch(() => ({}));
        const errorMessage = responseBody.message || 'Access denied';
        denial = classifyDenial(response.status, responseBody, errorMessage);
        setMessages(prev => [...prev, {
          role: 'system',
          content: errorMessage,
          isError: true,
          denial,
        }]);

        if (onAuditEntry) {
          onAuditEntry({
            timestamp: new Date().toISOString(),
            prompt: userMessage,
            scopeKey,
            role: selectedRole,
            httpStatus,
            denial,
            latency,
            response: responseBody,
          });
        }
        return;
      }

      const data = await response.json();
      responseBody = data;

      // Extract text from A2A response
      let agentText = '';
      if (data.error) {
        agentText = `Error: ${data.error.message}`;
      } else if (data.result?.status?.message?.parts) {
        agentText = data.result.status.message.parts
          .filter(p => p.kind === 'text' || p.type === 'text')
          .map(p => p.text)
          .join('\n') || 'No text response';
      } else if (data.result?.message?.parts) {
        agentText = data.result.message.parts
          .filter(p => p.kind === 'text' || p.type === 'text')
          .map(p => p.text)
          .join('\n') || 'No text response';
      } else {
        agentText = 'Received response (check console for format)';
        console.log('Unexpected A2A response format:', JSON.stringify(data, null, 2));
      }

      denial = classifyDenial(200, null, agentText);

      setMessages(prev => [...prev, {
        role: 'agent',
        content: agentText,
        denial,
      }]);

      if (onAuditEntry) {
        onAuditEntry({
          timestamp: new Date().toISOString(),
          prompt: userMessage,
          scopeKey,
          role: selectedRole,
          httpStatus,
          denial,
          latency,
          response: data,
        });
      }

    } catch (err) {
      const latency = Math.round(performance.now() - startTime);
      setMessages(prev => [...prev, {
        role: 'system',
        content: `Error: ${err.message}`,
        isError: true,
      }]);

      if (onAuditEntry) {
        onAuditEntry({
          timestamp: new Date().toISOString(),
          prompt: userMessage,
          scopeKey,
          role: selectedRole,
          httpStatus: 0,
          denial: null,
          latency,
          response: { error: err.message },
        });
      }
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
              <strong>{msg.role === 'user' ? 'You' : msg.role === 'agent' ? 'Agent' : 'System'}</strong>
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
