import React, { useState, useCallback } from 'react';
import { useAuth } from './AuthProvider';
import AuthStatus from './components/AuthStatus';
import LoginPrompt from './components/LoginPrompt';
import SecurityContextPanel from './components/SecurityContextPanel';
import TokenInspector from './components/TokenInspector';
import RBACTestMatrix from './components/RBACTestMatrix';
import ConversationTabs from './components/ConversationTabs';
import AuditLog from './components/AuditLog';

function App() {
  const { isAuthenticated } = useAuth();
  const [auditEntries, setAuditEntries] = useState([]);
  const [securityCtx, setSecurityCtx] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [selectedRole, setSelectedRole] = useState(null);

  const currentScopeKey = 'basic';

  const handleAuditEntry = useCallback((entry) => {
    setAuditEntries(prev => [...prev, entry]);
  }, []);

  const clearAudit = useCallback(() => {
    setAuditEntries([]);
  }, []);

  const identityRole = securityCtx?.security?.available_roles?.[0] || securityCtx?.security?.role || 'none';

  return (
    <div className="app-dashboard">
      <header className="dashboard-header">
        <h1>Security Testing Dashboard</h1>
        <AuthStatus />
      </header>

      {!isAuthenticated && (
        <main className="main-unauthenticated">
          <LoginPrompt />
        </main>
      )}

      {isAuthenticated && (
        <div className="dashboard-body">
          {/* Left Sidebar */}
          <aside className={`sidebar ${sidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
            <button
              className="sidebar-toggle"
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {sidebarCollapsed ? '\u25B6' : '\u25C0'}
            </button>

            {!sidebarCollapsed && (
              <>
                <SecurityContextPanel
                  scopeKey={currentScopeKey}
                  onSecurityContext={setSecurityCtx}
                  selectedRole={selectedRole}
                  onRoleChange={setSelectedRole}
                />

                <TokenInspector scopeKey={currentScopeKey} />

                <RBACTestMatrix
                  role={identityRole}
                  selectedRole={selectedRole}
                  onAuditEntry={handleAuditEntry}
                />
              </>
            )}
          </aside>

          {/* Main Content */}
          <main className="main-content">
            <ConversationTabs onAuditEntry={handleAuditEntry} selectedRole={selectedRole} />

            <div className="audit-section">
              <AuditLog entries={auditEntries} />
              {auditEntries.length > 0 && (
                <button className="btn-small btn-clear-audit" onClick={clearAudit}>
                  Clear Audit Log
                </button>
              )}
            </div>
          </main>
        </div>
      )}
    </div>
  );
}

export default App;
