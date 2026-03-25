import React, { useState } from 'react';
import { useAuth } from '../AuthProvider';
import { graphScopes } from '../authConfig';
import ChatInterface from './ChatInterface';

const MAX_TABS = 4;
const SCOPE_OPTIONS = Object.keys(graphScopes);

export default function ConversationTabs({ onAuditEntry, selectedRole, archiverEnabled }) {
  const { provider } = useAuth();
  const [tabs, setTabs] = useState([
    { id: 1, scopeKey: 'basic', label: 'basic' },
  ]);
  const [activeTab, setActiveTab] = useState(1);
  const [showScopePicker, setShowScopePicker] = useState(false);

  // Cognito users don't have Graph scope presets — hide scope picker
  const isCognito = provider === 'cognito';

  const addTab = (scopeKey) => {
    if (tabs.length >= MAX_TABS) return;
    const newId = Math.max(...tabs.map(t => t.id)) + 1;
    setTabs(prev => [...prev, { id: newId, scopeKey, label: scopeKey }]);
    setActiveTab(newId);
    setShowScopePicker(false);
  };

  const closeTab = (id) => {
    if (tabs.length <= 1) return;
    const remaining = tabs.filter(t => t.id !== id);
    setTabs(remaining);
    if (activeTab === id) {
      setActiveTab(remaining[0].id);
    }
  };

  const currentTab = tabs.find(t => t.id === activeTab);

  return (
    <div className="conversation-tabs">
      <div className="tab-bar">
        {tabs.map(tab => (
          <div
            key={tab.id}
            className={`tab ${tab.id === activeTab ? 'tab-active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="tab-label">{tab.label}</span>
            {!isCognito && <span className="tab-scope-badge">{tab.scopeKey}</span>}
            {tabs.length > 1 && (
              <button
                className="tab-close"
                onClick={(e) => { e.stopPropagation(); closeTab(tab.id); }}
              >
                &times;
              </button>
            )}
          </div>
        ))}

        {!isCognito && tabs.length < MAX_TABS && (
          <div className="tab tab-add" onClick={() => setShowScopePicker(true)}>
            +
          </div>
        )}

        {showScopePicker && !isCognito && (
          <div className="scope-picker-dropdown">
            {SCOPE_OPTIONS.map(key => (
              <button
                key={key}
                className="scope-picker-option"
                onClick={() => addTab(key)}
              >
                {key}
                <span className="scope-picker-detail">
                  {graphScopes[key].filter(s => !s.startsWith('api://')).join(', ')}
                </span>
              </button>
            ))}
            <button
              className="scope-picker-option scope-picker-cancel"
              onClick={() => setShowScopePicker(false)}
            >
              Cancel
            </button>
          </div>
        )}
      </div>

      <div className="tab-content">
        {currentTab && (
          <ChatInterface
            key={currentTab.id}
            scopeKey={currentTab.scopeKey}
            onAuditEntry={onAuditEntry}
            selectedRole={selectedRole}
            archiverEnabled={archiverEnabled}
          />
        )}
      </div>
    </div>
  );
}
