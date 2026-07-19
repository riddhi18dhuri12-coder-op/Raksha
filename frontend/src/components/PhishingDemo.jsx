import { useEffect, useState, useCallback } from 'react';
import { fetchPhishingCaptures, resetPhishingCaptures } from '../api';

export default function PhishingDemo({ state }) {
  const [captures, setCaptures] = useState([]);
  const [loading, setLoading] = useState(true);

  const poll = useCallback(async () => {
    try {
      const res = await fetchPhishingCaptures();
      setCaptures(res.captures || []);
    } catch {
      // backend may not be reachable yet; ignore, next poll will retry
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    poll();
    const id = setInterval(poll, 3000);
    return () => clearInterval(id);
  }, [poll]);

  const reset = async () => {
    await resetPhishingCaptures();
    poll();
  };

  const phishingAuditEntries = state.audit_log.filter((a) => a.event_type === 'phishing_capture');

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Phishing Awareness Demo</h1>
        <p className="page-subtitle">
          A self-contained, clearly-labeled fake bank login page for phishing-awareness training —
          not a real banking system, and nothing leaves your local machine.
        </p>
      </div>

      <div className="panel phishing-launch-panel">
        <div className="panel-header">
          <span className="panel-title">Simulated Login Page</span>
        </div>
        <div className="phishing-launch-body">
          <p>
            Open the demo "SecureTrust Bank" login page in a new tab. Anything typed into it is
            captured here — masked, in memory only — the same way a real detection pipeline would
            react to a credential-harvesting attempt.
          </p>
          <a
            className="btn-generate-report"
            href="http://localhost:5173/phishing_demo/bank-login.html"
            target="_blank"
            rel="noreferrer"
          >
            Open simulated bank login ↗
          </a>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Captured Submissions (this session)</span>
          <span className="panel-count">{captures.length}</span>
        </div>
        {loading ? (
          <div className="empty-state">Loading…</div>
        ) : captures.length === 0 ? (
          <div className="empty-state">No submissions yet — open the demo page above and try logging in.</div>
        ) : (
          <div className="evidence-list">
            {captures.map((c, i) => (
              <div className="evidence-item" key={i}>
                <div className="evidence-icon">🎣</div>
                <div className="evidence-body">
                  <div className="evidence-title-row">
                    <span className="evidence-title">Customer ID: {c.customerId}</span>
                    <span className="evidence-count mono">{c.password_masked}</span>
                  </div>
                  <div className="evidence-detail">
                    {c.page} · submitted {new Date(c.client_timestamp).toLocaleString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="phishing-reset-row">
          <button className="btn-reset" onClick={reset} disabled={captures.length === 0}>
            Clear captures
          </button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Linked Audit Trail Entries</span>
        </div>
        {phishingAuditEntries.length === 0 ? (
          <div className="empty-state">Captures appear here too, hash-chained into the same audit log as every other detection.</div>
        ) : (
          <ul className="resilience-recs">
            {phishingAuditEntries.map((a, i) => (
              <li key={i}>{a.detail}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
