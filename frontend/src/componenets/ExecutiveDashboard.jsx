function fmtSeconds(s) {
  if (s === null || s === undefined) return '—';
  if (s < 60) return `${s.toFixed(0)}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

function Tile({ label, value, sub, tone }) {
  return (
    <div className="exec-tile">
      <div className="exec-tile-label">{label}</div>
      <div className={`exec-tile-value ${tone || ''}`}>{value}</div>
      {sub && <div className="exec-tile-sub">{sub}</div>}
    </div>
  );
}

export default function ExecutiveDashboard({ state }) {
  const ex = state.executive_summary;
  const riskTone = ex.current_risk_pct >= 50 ? 'tone-red' : ex.current_risk_pct >= 20 ? 'tone-amber' : 'tone-green';

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Executive Dashboard</h1>
        <p className="page-subtitle">A one-glance view of organizational cyber risk — built for a CISO or board audience, not analysts.</p>
      </div>

      <div className="exec-grid">
        <Tile label="Current Risk" value={`${ex.current_risk_pct}%`} tone={riskTone} sub="Derived from live anomaly severity" />
        <Tile label="Critical Assets" value={ex.critical_assets_total} sub={`${ex.critical_assets_at_risk} currently at risk`} />
        <Tile label="Attack Progress" value={`Stage ${ex.attack_stage} / ${ex.attack_total_stages}`} sub={state.stage_name} />
        <Tile label="Time to Detection" value={fmtSeconds(ex.time_to_detection_seconds)} sub="First anomaly after baseline" />
        <Tile label="Systems Protected" value={`${ex.systems_protected_pct}%`} tone="tone-green" sub="Assets not currently compromised" />
        <Tile label="Containment Success" value={`${ex.containment.containment_success_pct}%`} sub={`${ex.containment.contained}/${ex.containment.total_actions} actions resolved`} />
      </div>

      <div className="panel exec-narrative">
        <div className="panel-header">
          <span className="panel-title">Board Summary</span>
        </div>
        <p className="exec-narrative-text">
          RAKSHA is currently at stage {ex.attack_stage} of {ex.attack_total_stages} of a simulated intrusion against
          the water utility environment. {ex.critical_assets_at_risk} of {ex.critical_assets_total} critical assets are
          presently flagged, and {ex.containment.contained} containment action{ex.containment.contained === 1 ? '' : 's'} have
          been resolved out of {ex.containment.total_actions} triggered. Overall Cyber Health Score is {state.cyber_health_score}/100
          and the aggregate Resilience Score is {state.resilience.overall}/100 — see the Resilience Score page for the full breakdown.
        </p>
      </div>
    </div>
  );
}
