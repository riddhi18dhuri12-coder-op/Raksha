function severityFromScore(score) {
  if (score >= 0.85) return { label: 'CRITICAL', tone: 'var(--signal-red)' };
  if (score >= 0.6) return { label: 'HIGH', tone: 'var(--signal-amber)' };
  if (score >= 0.3) return { label: 'MEDIUM', tone: 'var(--signal-amber)' };
  return { label: 'LOW', tone: 'var(--signal-green)' };
}

export default function IncidentsEvidence({ state }) {
  const hasIncident = state.events.length > 0;
  const maxScore = hasIncident ? Math.max(...state.events.map((e) => e.anomaly_score)) : 0;
  const severity = severityFromScore(maxScore);
  const isResolved = state.pending_approvals.length === 0 && state.current_stage >= state.total_stages - 1 && hasIncident;
  const incidentId = `INC-${2000 + state.current_stage + 1}`;
  const techniques = [...new Set(state.events.map((e) => e.mitre_technique))];

  const evidenceItems = [
    {
      icon: '📄',
      title: 'Anomaly Event Log',
      count: state.events.length,
      detail: 'Structured behavioral anomaly events with MITRE mapping and scoring.',
    },
    {
      icon: '🔗',
      title: 'Hash-Chained Audit Trail',
      count: state.audit_log.length,
      detail: 'Tamper-evident record of every detection, auto-action, and analyst decision.',
    },
    {
      icon: '🧬',
      title: 'IOC List',
      count: techniques.length,
      detail: techniques.length ? techniques.join(', ') : 'No indicators recorded yet.',
    },
    {
      icon: '🤖',
      title: 'AI Investigation Summary',
      count: 1,
      detail: 'Available on the AI Investigation page — explainable reasoning over this incident.',
    },
    {
      icon: '⚙️',
      title: 'Response Action Log',
      count: state.soar_actions.length,
      detail: 'SOAR actions — auto-executed and analyst-approved, with confidence and blast radius.',
    },
  ];

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Incidents &amp; Evidence Vault</h1>
        <p className="page-subtitle">Case management view of the current investigation and its supporting evidence.</p>
      </div>

      <div className="panel incident-case">
        <div className="panel-header">
          <span className="panel-title">Case File</span>
        </div>
        {!hasIncident ? (
          <div className="empty-state">No incident open. Monitoring baseline behavior.</div>
        ) : (
          <div className="incident-case-grid">
            <div className="incident-field"><span>Incident</span><strong>#{incidentId}</strong></div>
            <div className="incident-field">
              <span>Severity</span>
              <strong style={{ color: severity.tone }}>{severity.label}</strong>
            </div>
            <div className="incident-field"><span>Assigned</span><strong>SOC Team Alpha</strong></div>
            <div className="incident-field"><span>Evidence</span><strong>{state.events.length + state.audit_log.length} items</strong></div>
            <div className="incident-field"><span>Status</span><strong>{isResolved ? 'Contained' : 'Investigating'}</strong></div>
            <div className="incident-field"><span>Stage</span><strong>{state.current_stage + 1} / {state.total_stages}</strong></div>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Evidence Vault</span>
        </div>
        <div className="evidence-list">
          {evidenceItems.map((item, i) => (
            <div className="evidence-item" key={i}>
              <div className="evidence-icon">{item.icon}</div>
              <div className="evidence-body">
                <div className="evidence-title-row">
                  <span className="evidence-title">{item.title}</span>
                  <span className="evidence-count">{item.count}</span>
                </div>
                <div className="evidence-detail">{item.detail}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
