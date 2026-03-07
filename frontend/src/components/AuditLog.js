import React, { useState } from 'react';
import DenialIndicator from './DenialIndicator';

export default function AuditLog({ entries }) {
  const [collapsed, setCollapsed] = useState(false);
  const [expandedRow, setExpandedRow] = useState(null);

  const copyAsJson = () => {
    navigator.clipboard.writeText(JSON.stringify(entries, null, 2)).catch(console.error);
  };

  return (
    <div className="audit-log">
      <div className="audit-header">
        <h3 className="panel-title collapsible" onClick={() => setCollapsed(!collapsed)}>
          Audit Log ({entries.length}) {collapsed ? '\u25B6' : '\u25BC'}
        </h3>
        {!collapsed && entries.length > 0 && (
          <div className="audit-actions">
            <button className="btn-small" onClick={copyAsJson}>Copy JSON</button>
          </div>
        )}
      </div>

      {!collapsed && (
        <div className="audit-table-wrapper">
          {entries.length === 0 ? (
            <p className="panel-muted">No requests yet</p>
          ) : (
            <table className="audit-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Time</th>
                  <th>Prompt</th>
                  <th>Scope</th>
                  <th>HTTP</th>
                  <th>Denial</th>
                  <th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry, i) => (
                  <React.Fragment key={i}>
                    <tr
                      className={`audit-row ${expandedRow === i ? 'expanded' : ''}`}
                      onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                    >
                      <td>{i + 1}</td>
                      <td>{new Date(entry.timestamp).toLocaleTimeString()}</td>
                      <td className="audit-prompt" title={entry.prompt}>
                        {entry.prompt.length > 40 ? entry.prompt.substring(0, 40) + '...' : entry.prompt}
                      </td>
                      <td><span className="scope-tag scope-tag-sm">{entry.scopeKey}</span></td>
                      <td className={entry.httpStatus >= 400 ? 'http-error' : ''}>{entry.httpStatus || '--'}</td>
                      <td>
                        {entry.denial
                          ? <DenialIndicator level={entry.denial.level} reason={entry.denial.reason} />
                          : <span className="audit-ok">OK</span>}
                      </td>
                      <td>{entry.latency}ms</td>
                    </tr>
                    {expandedRow === i && (
                      <tr className="audit-detail-row">
                        <td colSpan={7}>
                          <pre className="audit-detail">
                            {JSON.stringify(entry.response, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
