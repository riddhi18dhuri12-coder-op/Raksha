const PIPELINE = [
  'Initial Access',
  'Execution',
  'Credential Access',
  'Lateral Movement',
  'Impair Process Control (ICS)',
  'Containment',
];

function formatTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString('en-IN', { hour12: false });
}

export default function AttackTimelinePage({ state }) {
  const observedTactics = new Set(state.events.map((e) => e.mitre_tactic));
  const containmentReached = state.soar_actions.some((a) => a.auto_executed || a.approved);
  if (containmentReached) observedTactics.add('Containment');

  const reachedCount = PIPELINE.filter((t) => observedTactics.has(t)).length;

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Attack Timeline</h1>
        <p className="page-subtitle">Kill-chain progression of the current incident, stage by stage.</p>
      </div>

      <div className="panel kill-chain-panel">
        <div className="kill-chain">
          {PIPELINE.map((stage, i) => {
            const reached = observedTactics.has(stage);
            const isLast = i === PIPELINE.length - 1;
            return (
              <div className="kill-chain-step" key={stage}>
                <div className="kill-chain-node-wrap">
                  <div className={`kill-chain-node ${reached ? 'reached' : ''}`}>{i + 1}</div>
                  <div className="kill-chain-name">{stage}</div>
                </div>
                {!isLast && <div className={`kill-chain-arrow ${reached ? 'reached' : ''}`}>↓</div>}
              </div>
            );
          })}
        </div>
        <div className="kill-chain-footer">
          {reachedCount} of {PIPELINE.length} kill-chain stages observed
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Detailed Event Log</span>
          <span className="panel-count">{state.events.length} event{state.events.length !== 1 ? 's' : ''}</span>
        </div>
        <div className="timeline-list">
          {state.events.length === 0 && <div className="empty-state">No incident activity recorded yet.</div>}
          {state.events.map((e, i) => (
            <div key={e.id} className="timeline-item">
              <div className="timeline-marker">
                <div className="timeline-dot" />
                {i < state.events.length - 1 && <div className="timeline-line" />}
              </div>
              <div className="timeline-content">
                <div className="timeline-top">
                  <span className="timeline-time">{formatTime(e.timestamp)}</span>
                  <span className="timeline-technique">{e.mitre_technique}</span>
                </div>
                <div className="timeline-desc">{e.description}</div>
                <div className="timeline-score-bar">
                  <div className="timeline-score-fill" style={{ width: `${e.anomaly_score * 100}%` }} />
                  <span className="timeline-score-label">{e.anomaly_score.toFixed(2)}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
