import { useState, useEffect } from 'react';

export default function MitreMatrix({ state }) {
  const coverage = state.mitre_coverage;
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    // default-select the most recently active tactic
    const withData = coverage.filter((c) => c.count > 0);
    if (withData.length > 0) {
      setSelected(withData[withData.length - 1].tactic);
    }
  }, [state.events.length]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectedData = coverage.find((c) => c.tactic === selected);

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>MITRE ATT&amp;CK Visualizer</h1>
        <p className="page-subtitle">Observed tactics mapped against the ATT&amp;CK &amp; ATT&amp;CK-for-ICS frameworks.</p>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Tactic Coverage</span>
          <span className="panel-count">{coverage.filter((c) => c.count > 0).length} / {coverage.length} tactics active</span>
        </div>
        <div className="mitre-bars">
          {coverage.map((c) => (
            <button
              key={c.tactic}
              className={`mitre-bar-row ${selected === c.tactic ? 'selected' : ''} ${c.count === 0 ? 'inactive' : ''}`}
              onClick={() => c.count > 0 && setSelected(c.tactic)}
              disabled={c.count === 0}
            >
              <span className="mitre-bar-label">{c.tactic}</span>
              <div className="mitre-bar-track">
                <div
                  className="mitre-bar-fill"
                  style={{ width: `${Math.max(c.max_score * 100, c.count > 0 ? 6 : 0)}%` }}
                />
              </div>
              <span className="mitre-bar-score">{c.count > 0 ? c.max_score.toFixed(2) : '—'}</span>
            </button>
          ))}
        </div>
      </div>

      {selectedData && selectedData.count > 0 ? (
        <div className="panel mitre-detail">
          <div className="panel-header">
            <span className="panel-title">Technique Detail</span>
          </div>
          <div className="mitre-detail-body">
            <div className="mitre-detail-row">
              <span className="mitre-detail-key">Detected</span>
              <span className="mitre-detail-val">{selectedData.latest_description}</span>
            </div>
            <div className="mitre-detail-row">
              <span className="mitre-detail-key">Mapped Technique</span>
              <span className="mitre-detail-val mono">{selectedData.latest_technique}</span>
            </div>
            <div className="mitre-detail-row">
              <span className="mitre-detail-key">Tactic</span>
              <span className="mitre-detail-val">{selectedData.tactic}</span>
            </div>
            <div className="mitre-detail-row">
              <span className="mitre-detail-key">Confidence</span>
              <span className="mitre-detail-val mono confidence-val">{Math.round(selectedData.latest_score * 100)}%</span>
            </div>
            <div className="mitre-detail-row">
              <span className="mitre-detail-key">Occurrences</span>
              <span className="mitre-detail-val mono">{selectedData.count}</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="panel">
          <div className="empty-state">Select an active tactic above to see technique-level detail.</div>
        </div>
      )}
    </div>
  );
}
