import React, { useState, useCallback } from 'react';
import { useMsal, useAccount } from '@azure/msal-react';
import { InteractionRequiredAuthError } from '@azure/msal-browser';
import { graphScopes } from '../authConfig';
import { classifyDenial } from '../utils/denialClassifier';
import { getScenariosForRole } from '../utils/testScenarios';
import DenialIndicator from './DenialIndicator';

const A2A_SERVER_URL = process.env.REACT_APP_A2A_SERVER_URL || 'http://localhost:10000';

export default function RBACTestMatrix({ role, onAuditEntry }) {
  const { instance, accounts } = useMsal();
  const account = useAccount(accounts[0] || {});
  const [results, setResults] = useState({});
  const [running, setRunning] = useState(null);
  const [runningAll, setRunningAll] = useState(false);

  const scenarios = getScenariosForRole(role);

  const getAccessToken = useCallback(async (scopeKey) => {
    const scopes = graphScopes[scopeKey] || graphScopes.basic;
    try {
      const resp = await instance.acquireTokenSilent({ scopes, account });
      return resp.accessToken;
    } catch (err) {
      if (err instanceof InteractionRequiredAuthError) {
        const resp = await instance.acquireTokenPopup({ scopes });
        return resp.accessToken;
      }
      throw err;
    }
  }, [instance, account]);

  const runScenario = useCallback(async (scenario) => {
    setRunning(scenario.id);
    const startTime = performance.now();

    try {
      const accessToken = await getAccessToken(scenario.scopeKey);

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
              messageId: `test-${scenario.id}-${Date.now()}`,
              role: 'user',
              parts: [{ type: 'text', text: scenario.prompt }],
            },
          },
          id: `test-${Date.now()}`,
        }),
      });

      const latency = Math.round(performance.now() - startTime);
      const httpStatus = response.status;
      let body = null;
      let responseText = '';

      if (httpStatus === 401 || httpStatus === 403) {
        body = await response.json().catch(() => ({}));
        responseText = body.message || '';
      } else {
        body = await response.json();
        // Extract agent text
        if (body.result?.status?.message?.parts) {
          responseText = body.result.status.message.parts
            .filter(p => p.kind === 'text' || p.type === 'text')
            .map(p => p.text).join('\n');
        } else if (body.result?.message?.parts) {
          responseText = body.result.message.parts
            .filter(p => p.kind === 'text' || p.type === 'text')
            .map(p => p.text).join('\n');
        }
      }

      const denial = classifyDenial(httpStatus, body, responseText);
      const succeeded = !denial;
      const pass = succeeded === scenario.shouldSucceed;

      setResults(prev => ({
        ...prev,
        [scenario.id]: { pass, denial, latency, httpStatus, succeeded },
      }));

      if (onAuditEntry) {
        onAuditEntry({
          timestamp: new Date().toISOString(),
          prompt: `[TEST: ${scenario.id}] ${scenario.prompt}`,
          scopeKey: scenario.scopeKey,
          httpStatus,
          denial,
          latency,
          response: body,
        });
      }
    } catch (err) {
      const latency = Math.round(performance.now() - startTime);
      setResults(prev => ({
        ...prev,
        [scenario.id]: { pass: false, error: err.message, latency, httpStatus: 0, succeeded: false },
      }));
    } finally {
      setRunning(null);
    }
  }, [getAccessToken, onAuditEntry]);

  const runAll = async () => {
    setRunningAll(true);
    for (const scenario of scenarios) {
      await runScenario(scenario);
      // Small delay to avoid overwhelming the server
      await new Promise(r => setTimeout(r, 2000));
    }
    setRunningAll(false);
  };

  return (
    <div className="rbac-matrix">
      <h3 className="panel-title">RBAC Test Matrix</h3>
      <div className="matrix-role-info">
        Testing as: <span className={`role-badge role-${role}`}>{role.toUpperCase()}</span>
      </div>

      <div className="matrix-table-wrapper">
        <table className="matrix-table">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Scope</th>
              <th>Expected</th>
              <th>Result</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {scenarios.map(scenario => {
              const result = results[scenario.id];
              return (
                <tr key={scenario.id} className={result ? (result.pass ? 'row-pass' : 'row-fail') : ''}>
                  <td>
                    <span className="matrix-tool">{scenario.tool}</span>
                    <span className="matrix-desc">{scenario.description}</span>
                  </td>
                  <td><span className="scope-tag scope-tag-sm">{scenario.scopeKey}</span></td>
                  <td>
                    {scenario.shouldSucceed
                      ? <span className="expect-pass">ALLOW</span>
                      : <span className="expect-deny">{scenario.denialExpected?.toUpperCase() || 'DENY'}</span>}
                  </td>
                  <td>
                    {running === scenario.id ? (
                      <span className="matrix-running">Running...</span>
                    ) : result ? (
                      <div className="matrix-result">
                        <span className={result.pass ? 'result-pass' : 'result-fail'}>
                          {result.pass ? 'PASS' : 'FAIL'}
                        </span>
                        {result.denial && <DenialIndicator level={result.denial.level} reason={result.denial.reason} />}
                        {result.error && <span className="result-error" title={result.error}>ERR</span>}
                        <span className="result-latency">{result.latency}ms</span>
                      </div>
                    ) : (
                      <span className="matrix-pending">--</span>
                    )}
                  </td>
                  <td>
                    <button
                      className="btn-small btn-run"
                      onClick={() => runScenario(scenario)}
                      disabled={running !== null || runningAll}
                    >
                      Run
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <button
        className="btn-run-all"
        onClick={runAll}
        disabled={running !== null || runningAll}
      >
        {runningAll ? 'Running...' : 'Run All'}
      </button>
    </div>
  );
}
