function formatTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString('en-IN', { hour12: false });
}

export default function Timeline({ events }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Threat Timeline</span>
        <span className="panel-count">{events.length} stage{events.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="timeline-list">
        {events.length === 0 && <div className="empty-state">No incident activity recorded.</div>}
        {events.map((e, i) => (
          <div key={e.id} className="timeline-item">
            <div className="timeline-marker">
              <div className="timeline-dot" />
              {i < events.length - 1 && <div className="timeline-line" />}
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
  );
}
