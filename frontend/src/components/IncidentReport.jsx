import { useState } from 'react';
import { fetchIncidentReport } from '../api';

export default function IncidentReport() {
  const [report, setReport] = useState(null);
  const [open, setOpen] = useState(false);

  const generate = async () => {
    const res = await fetchIncidentReport();
    setReport(res);
    setOpen(true);
  };

  return (
    <>
      <button className="btn-generate-report" onClick={generate}>
        Generate incident report
      </button>
      {open && report && (
        <div className="report-overlay" onClick={() => setOpen(false)}>
          <div className="report-modal" onClick={(e) => e.stopPropagation()}>
            <div className="report-header">
              <h2>{report.title}</h2>
              <button className="report-close" onClick={() => setOpen(false)}>×</button>
            </div>
            <p className="report-summary">{report.summary}</p>

            <h3>Timeline</h3>
            <ul className="report-timeline">
              {report.timeline.map((t, i) => (
                <li key={i}>
                  <strong>{t.mitre_technique}</strong> — {t.description} (score {t.anomaly_score.toFixed(2)})
                </li>
              ))}
            </ul>

            <h3>Actions taken</h3>
            <ul className="report-actions">
              {report.actions_taken.map((a, i) => (
                <li key={i}>
                  {a.action} on {a.target} —{' '}
                  {a.auto_executed ? 'auto-executed' : a.approved ? 'approved by analyst' : 'rejected by analyst'}
                  {' '}(confidence {Math.round(a.confidence * 100)}%, blast radius {a.blast_radius})
                </li>
              ))}
            </ul>

            <h3>Recommendations</h3>
            <ul className="report-recommendations">
              {report.recommendations.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>

            <div className="report-footer">Cyber Health Score at time of report: {report.cyber_health_score}/100</div>
          </div>
        </div>
      )}
    </>
  );
}
