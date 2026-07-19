import AttackGraph from './AttackGraph';
import PredictionBanner from './PredictionBanner';
import SoarPanel from './SoarPanel';
import Timeline from './Timeline';
import AuditLog from './AuditLog';
import MlValidationPanel from './MlValidationPanel';

export default function MissionControl({ state, poll }) {
  return (
    <main className="main-grid">
      <section className="graph-column">
        <PredictionBanner prediction={state.prediction} />
        <div className="panel graph-panel">
          <div className="panel-header">
            <span className="panel-title">Live Attack Graph</span>
            <span className="panel-count">IT + OT unified view</span>
          </div>
          <AttackGraph nodes={state.nodes} edges={state.edges} />
          <div className="graph-legend">
            <span><i className="dot" style={{ background: '#3A4256' }} /> Normal</span>
            <span><i className="dot" style={{ background: '#F5A623' }} /> Suspicious</span>
            <span><i className="dot" style={{ background: '#FF4D4F' }} /> Compromised</span>
            <span><i className="dot" style={{ background: '#3DD68C' }} /> Contained</span>
          </div>
        </div>
        <Timeline events={state.events} />
      </section>

      <section className="side-column">
        <SoarPanel
          actions={state.soar_actions}
          pendingApprovals={state.pending_approvals}
          onDecision={poll}
        />
      </section>

      <section className="audit-column">
        <MlValidationPanel />
        <AuditLog entries={state.audit_log} />
      </section>
    </main>
  );
}
