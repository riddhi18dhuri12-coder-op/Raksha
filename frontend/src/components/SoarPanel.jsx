import { sendSoarDecision } from '../api';

const BLAST_COLOR = {
  low: 'var(--signal-green)',
  medium: 'var(--signal-amber)',
  high: 'var(--signal-amber)',
  critical: 'var(--signal-red)',
};

function TrustBadge({ action }) {
  return (
    <div className="trust-badge">
      <div className="trust-row">
        <span className="trust-label">Confidence</span>
        <span className="trust-value">{Math.round(action.confidence * 100)}%</span>
      </div>
      <div className="trust-row">
        <span className="trust-label">Blast radius</span>
        <span className="trust-value" style={{ color: BLAST_COLOR[action.blast_radius] }}>
          {action.blast_radius.toUpperCase()}
        </span>
      </div>
      <div className="trust-row">
        <span className="trust-label">Approval</span>
        <span className="trust-value">{action.approval_required ? 'Required' : 'Not required'}</span>
      </div>
    </div>
  );
}

export default function SoarPanel({ actions, pendingApprovals, onDecision }) {
  const handleDecision = async (actionId, approved) => {
    await sendSoarDecision(actionId, approved);
    onDecision();
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title">Response Orchestrator</span>
        <span className="panel-count">{actions.length} action{actions.length !== 1 ? 's' : ''}</span>
      </div>

      {pendingApprovals.length > 0 && (
        <div className="pending-section">
          <div className="pending-label">Awaiting your decision</div>
          {pendingApprovals.map((a) => (
            <div key={a.id} className="action-card pending">
              <div className="action-title">{a.action}</div>
              <div className="action-target">{a.target_asset}</div>
              <div className="action-impact">{a.business_impact}</div>
              <TrustBadge action={a} />
              <div className="action-buttons">
                <button className="btn-approve" onClick={() => handleDecision(a.id, true)}>
                  Approve
                </button>
                <button className="btn-reject" onClick={() => handleDecision(a.id, false)}>
                  Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="action-list">
        {actions.filter((a) => a.approved !== null || a.auto_executed).length === 0 && pendingApprovals.length === 0 && (
          <div className="empty-state">No containment actions triggered yet.</div>
        )}
        {actions
          .filter((a) => !pendingApprovals.find((p) => p.id === a.id))
          .map((a) => (
            <div key={a.id} className="action-card resolved">
              <div className="action-title">
                {a.action}
                <span className={`action-tag ${a.auto_executed ? 'tag-auto' : a.approved ? 'tag-approved' : 'tag-rejected'}`}>
                  {a.auto_executed ? 'AUTO' : a.approved ? 'APPROVED' : 'REJECTED'}
                </span>
              </div>
              <div className="action-target">{a.target_asset}</div>
              <TrustBadge action={a} />
            </div>
          ))}
      </div>
    </div>
  );
}
