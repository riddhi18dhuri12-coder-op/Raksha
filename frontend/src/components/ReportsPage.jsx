import { useState } from 'react';
import { fetchIncidentReport } from '../api';

function reportToText(report, resilience) {
  const lines = [
    report.title,
    '='.repeat(report.title.length),
    '',
    report.summary,
    '',
    'TIMELINE',
    '--------',
    ...report.timeline.map((t) => `[${t.mitre_technique}] ${t.description} (score ${t.anomaly_score.toFixed(2)})`),
    '',
    'ACTIONS TAKEN',
    '-------------',
    ...report.actions_taken.map(
      (a) => `${a.action} on ${a.target} — ${a.auto_executed ? 'auto-executed' : a.approved ? 'approved by analyst' : 'rejected by analyst'} (confidence ${Math.round(a.confidence * 100)}%, blast radius ${a.blast_radius})`
    ),
    '',
    'RECOMMENDATIONS',
    '---------------',
    ...report.recommendations.map((r) => `- ${r}`),
    '',
    `Cyber Health Score at time of report: ${report.cyber_health_score}/100`,
    resilience ? `Resilience Score at time of report: ${resilience.overall}/100` : '',
  ];
  return lines.join('\n');
}

export default function ReportsPage({ state }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const generate = async () => {
    setLoading(true);
    const res = await fetchIncidentReport();
    setReport(res);
    setLoading(false);
  };

  const download = () => {
    if (!report) return;
    const text = reportToText(report, state.resilience);
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.title.replace(/[^a-z0-9]+/gi, '_')}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Reports</h1>
        <p className="page-subtitle">One-click, compliance-ready incident report generation.</p>
      </div>

      <div className="panel report-generate-panel">
        <button className="btn-generate-report btn-generate-lg" onClick={generate} disabled={loading}>
          {loading ? 'Generating…' : 'Generate PDF-style Report'}
        </button>
        {report && (
          <button className="btn-reset" onClick={download}>Download report (.txt)</button>
        )}
      </div>

      {report && (
        <div className="panel report-inline">
          <div className="report-header">
            <h2>{report.title}</h2>
          </div>
          <p className="report-summary">{report.summary}</p>

          <h3>Timeline</h3>
          <ul>
            {report.timeline.map((t, i) => (
              <li key={i}>
                <strong>{t.mitre_technique}</strong> — {t.description} (score {t.anomaly_score.toFixed(2)})
              </li>
            ))}
          </ul>

          <h3>Actions taken</h3>
          <ul>
            {report.actions_taken.map((a, i) => (
              <li key={i}>
                {a.action} on {a.target} —{' '}
                {a.auto_executed ? 'auto-executed' : a.approved ? 'approved by analyst' : 'rejected by analyst'}
                {' '}(confidence {Math.round(a.confidence * 100)}%, blast radius {a.blast_radius})
              </li>
            ))}
          </ul>

          <h3>Recommendations</h3>
          <ul>
            {report.recommendations.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>

          <div className="report-footer">
            Cyber Health Score: {report.cyber_health_score}/100 · Resilience Score: {state.resilience.overall}/100
          </div>
        </div>
      )}
    </div>
  );
}
