import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { useAuth } from '../AuthProvider';
import { sendA2AMessage, buildAuditEntry } from '../utils/a2aClient';
import { getScenariosForRole } from '../utils/testScenarios';
import DenialIndicator from './DenialIndicator';

const RUN_ALL_DELAY_MS = 2000; // Delay between tests to avoid rate limiting

function ResultCell({ scenarioId, running, result }) {
  if (running === scenarioId) {
    return <span className="matrix-running">Running...</span>;
  }
  if (!result) {
    return <span className="matrix-pending">--</span>;
  }
  return (
    <div className="matrix-result">
      <span className={result.pass ? 'result-pass' : 'result-fail'}>
        {result.pass ? 'PASS' : 'FAIL'}
      </span>
      {result.denial && <DenialIndicator level={result.denial.level} reason={result.denial.reason} />}
      {result.error && <span className="result-error" title={result.error}>ERR</span>}
      <span className="result-latency">{result.latency}ms</span>
    </div>
  );
}

export default function RBACTestMatrix({ role, selectedRole, onAuditEntry, archiverEnabled }) {
  const { getAccessToken } = useAuth();
  const [results, setResults] = useState({});
  const [running, setRunning] = useState(null);
  const [runningAll, setRunningAll] = useState(false);

  const effectiveRole = selectedRole || role;
  const activeAbacAttrs = useMemo(
    () => (archiverEnabled ? { archiver: true } : {}),
    [archiverEnabled]
  );
  const scenarios = getScenariosForRole(effectiveRole, activeAbacAttrs);

  // Reset results when role or archiver toggle changes
  useEffect(() => {
    setResults({});
  }, [selectedRole, archiverEnabled]);

  const runScenario = useCallback(async (scenario) => {
    setRunning(scenario.id);

    try {
      const accessToken = await getAccessToken(scenario.scopeKey);
      const result = await sendA2AMessage({
        accessToken,
        message: scenario.prompt,
        selectedRole,
        abacAttrs: activeAbacAttrs,
      });

      const succeeded = !result.denial;
      const pass = succeeded === scenario.shouldSucceed;

      setResults(prev => ({
        ...prev,
        [scenario.id]: { pass, denial: result.denial, latency: result.latency, httpStatus: result.httpStatus, succeeded },
      }));

      if (onAuditEntry) {
        onAuditEntry(buildAuditEntry({
          prompt: `[TEST: ${scenario.id}] ${scenario.prompt}`,
          scopeKey: scenario.scopeKey,
          selectedRole,
          httpStatus: result.httpStatus,
          denial: result.denial,
          latency: result.latency,
          response: result.body,
        }));
      }
    } catch (err) {
      setResults(prev => ({
        ...prev,
        [scenario.id]: { pass: false, error: err.message, latency: 0, httpStatus: 0, succeeded: false },
      }));
    } finally {
      setRunning(null);
    }
  }, [getAccessToken, selectedRole, activeAbacAttrs, onAuditEntry]);

  const runAll = async () => {
    setRunningAll(true);
    for (const scenario of scenarios) {
      await runScenario(scenario);
      await new Promise(r => setTimeout(r, RUN_ALL_DELAY_MS));
    }
    setRunningAll(false);
  };

  const isDisabled = running !== null || runningAll;

  return (
    <div className="rbac-matrix">
      <h3 className="panel-title">Access Control Test Matrix</h3>
      <div className="matrix-role-info">
        Testing as: <span className={`role-badge role-${effectiveRole}`}>{effectiveRole.toUpperCase()}</span>
        {archiverEnabled && <span className="abac-badge">+archiver</span>}
        {role !== effectiveRole && <span className="role-switch-note">(switched from {role})</span>}
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
                    <ResultCell scenarioId={scenario.id} running={running} result={result} />
                  </td>
                  <td>
                    <button
                      className="btn-small btn-run"
                      onClick={() => runScenario(scenario)}
                      disabled={isDisabled}
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
        disabled={isDisabled}
      >
        {runningAll ? 'Running...' : 'Run All'}
      </button>
    </div>
  );
}
