const LABELS = {
  recovery_readiness: 'Recovery Readiness',
  attack_resistance: 'Attack Resistance',
  backup_health: 'Backup Health',
  patch_compliance: 'Patch Compliance',
  critical_assets_protected: 'Critical Assets Protected',
  zero_trust_maturity: 'Zero Trust Maturity',
};

function toneFor(v) {
  if (v >= 80) return 'var(--signal-green)';
  if (v >= 50) return 'var(--signal-amber)';
  return 'var(--signal-red)';
}

export default function ResilienceScore({ state }) {
  const r = state.resilience;

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Cyber Resilience Score</h1>
        <p className="page-subtitle">
          Beyond detecting this one incident — how resilient is the organization overall?
          This is the score problem statement 7 asks for: measure, explain, simulate, and improve.
        </p>
      </div>

      <div className="panel resilience-hero">
        <div className="resilience-hero-score" style={{ color: toneFor(r.overall) }}>{r.overall}<span>/100</span></div>
        <div className="resilience-hero-label">Overall Resilience Score</div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Component Breakdown</span>
        </div>
        <div className="resilience-components">
          {Object.entries(r.components).map(([key, value]) => (
            <div className="resilience-row" key={key}>
              <div className="resilience-row-top">
                <span className="resilience-row-label">{LABELS[key] || key}</span>
                <span className="resilience-row-value" style={{ color: toneFor(value) }}>{value}%</span>
              </div>
              <div className="resilience-bar-track">
                <div className="resilience-bar-fill" style={{ width: `${value}%`, background: toneFor(value) }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Recommendations</span>
        </div>
        <ul className="resilience-recs">
          {r.recommendations.map((rec, i) => (
            <li key={i}>{rec}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
