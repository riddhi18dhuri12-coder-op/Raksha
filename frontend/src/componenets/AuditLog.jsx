const TYPE_LABEL = {
  system: 'SYSTEM',
  anomaly_detected: 'ANOMALY',
  soar_auto_action: 'AUTO-ACTION',
  soar_pending_approval: 'PENDING',
  human_decision: 'DECISION',
  phishing_capture: 'PHISHING CAPTURE',
};

export default function AuditLog({ entries }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Audit Log</span>
        <span className="panel-count">hash-chained</span>
      </div>
      <div className="audit-list">
        {entries.slice().reverse().map((e) => (
          <div key={e.index} className="audit-entry">
            <div className="audit-meta">
              <span className={`audit-type type-${e.event_type}`}>{TYPE_LABEL[e.event_type] || e.event_type}</span>
              <span className="audit-hash">#{e.index} · {e.hash}</span>
            </div>
            <div className="audit-detail">{e.detail}</div>
          </div>
        ))}
      </div>
    </div>
  );
}