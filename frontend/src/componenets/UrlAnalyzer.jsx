import { useState, useEffect, useRef, useCallback } from 'react';
import { scanUrl } from '../api';

const URL_RE = /^(https?:\/\/)?([\w-]+\.)+[a-z]{2,}(\/\S*)?$/i;
const ALERT_THRESHOLD = 90;
const POLL_MS = 3000;

function riskColorVar(level) {
  if (level === 'High') return 'var(--signal-red)';
  if (level === 'Medium') return 'var(--signal-amber)';
  return 'var(--signal-green)';
}

export default function UrlAnalyzer() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [protectionOn, setProtectionOn] = useState(false);
  const [clipboardDenied, setClipboardDenied] = useState(false);
  const [alert, setAlert] = useState(null);
  const [history, setHistory] = useState([]);
  const lastSeenRef = useRef('');

  const runScan = useCallback(async (target, { background = false } = {}) => {
    if (!target) return null;
    try {
      const res = await scanUrl(target);
      if (background) {
        setHistory((h) => [{ url: target, res, at: Date.now() }, ...h].slice(0, 8));
        if (res.threat_analysis.risk_score > ALERT_THRESHOLD) {
          setAlert({ url: target, score: res.threat_analysis.risk_score, level: res.threat_analysis.risk_level });
        }
      }
      return res;
    } catch {
      if (!background) setError('Could not reach the analyzer backend.');
      return null;
    }
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    if (!url.trim() || loading) return;
    setLoading(true);
    setError(null);
    const res = await runScan(url.trim());
    if (res) setResult(res);
    setLoading(false);
  };

  // Background protection: while ON, poll the clipboard for a new URL (only
  // while this tab is visible/focused -- a browser page genuinely cannot see
  // links opened elsewhere on your system; that would need a browser
  // extension. This is the honest, in-tab equivalent: copy a link anywhere,
  // and it gets auto-scanned within a few seconds without you pasting it.
  useEffect(() => {
    if (!protectionOn) return undefined;
    let cancelled = false;

    const poll = async () => {
      if (document.visibilityState !== 'visible') return;
      if (!navigator.clipboard || !navigator.clipboard.readText) {
        setClipboardDenied(true);
        return;
      }
      try {
        const text = (await navigator.clipboard.readText()).trim();
        if (cancelled) return;
        setClipboardDenied(false);
        if (text && text !== lastSeenRef.current && URL_RE.test(text)) {
          lastSeenRef.current = text;
          runScan(text, { background: true });
        }
      } catch {
        if (!cancelled) setClipboardDenied(true);
      }
    };

    poll();
    const id = setInterval(poll, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [protectionOn, runScan]);

  return (
    <div className="page-container">
      {alert && (
        <div className="threat-alert-banner" role="alert">
          <span>
            ⚠ HIGH THREAT DETECTED — {alert.url} scored {alert.score}/100 ({alert.level} Risk)
          </span>
          <button className="threat-alert-dismiss" onClick={() => setAlert(null)}>Dismiss</button>
        </div>
      )}

      <div className="page-header">
        <h1>URL Analyzer</h1>
        <p className="page-subtitle">
          Ported from a standalone phishing-URL detector: a trained ML model plus live WHOIS,
          SSL, and DNS checks against the real domain — combined into one risk score.
        </p>
      </div>

      <div className="panel protection-panel">
        <div className="protection-row">
          <div>
            <div className="panel-title">Background Protection</div>
            <p className="protection-desc">
              While ON, this tab watches your clipboard and auto-scans any link you copy —
              from a search result, an email, anywhere — without you pasting it in manually.
              A page can't see links opened elsewhere on your system without a browser
              extension, so clipboard is the honest, in-tab version of "watch what I open."
              Any result scoring above {ALERT_THRESHOLD}/100 triggers the red alert above.
            </p>
          </div>
          <button
            className={`btn-generate-report protection-toggle ${protectionOn ? 'on' : ''}`}
            onClick={() => setProtectionOn((v) => !v)}
          >
            {protectionOn ? '● Protection ON' : 'Start Protection'}
          </button>
        </div>
        {protectionOn && clipboardDenied && (
          <div className="empty-state protection-warning">
            Clipboard access was denied or isn't available in this browser — grant clipboard
            permission to this tab, or use the manual scan box below instead.
          </div>
        )}
        {protectionOn && history.length > 0 && (
          <div className="protection-history">
            <div className="panel-title">Recent Background Scans</div>
            <div className="evidence-list">
              {history.map((h, i) => (
                <div className="evidence-item" key={i}>
                  <div className="evidence-icon">{h.res.threat_analysis.risk_score > ALERT_THRESHOLD ? '🛑' : '🔗'}</div>
                  <div className="evidence-body">
                    <div className="evidence-title-row">
                      <span className="evidence-title">{h.url}</span>
                      <span
                        className="evidence-count"
                        style={{ color: riskColorVar(h.res.threat_analysis.risk_level) }}
                      >
                        {h.res.threat_analysis.risk_score}/100
                      </span>
                    </div>
                    <div className="evidence-detail">{h.res.threat_analysis.risk_level} risk · scanned {new Date(h.at).toLocaleTimeString()}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <form className="panel url-analyzer-form" onSubmit={submit}>
        <input
          className="copilot-input url-analyzer-input"
          placeholder="Or paste a URL here to scan manually, e.g. http://example.com/login"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <button className="btn-generate-report" type="submit" disabled={loading}>
          {loading ? 'Scanning…' : 'Scan URL'}
        </button>
      </form>

      {error && <div className="panel"><div className="empty-state">{error}</div></div>}

      {result && (
        <>
          <div className="panel resilience-hero">
            <div
              className="resilience-hero-score"
              style={{ color: riskColorVar(result.threat_analysis.risk_level) }}
            >
              {result.threat_analysis.risk_score}<span>/100</span>
            </div>
            <div className="resilience-hero-label">
              {result.threat_analysis.risk_level} Risk · ML verdict: {result.prediction.verdict}
              {' '}({result.prediction.phishing_probability}% phishing confidence)
            </div>
          </div>

          <div className="panel">
            <div className="panel-header"><span className="panel-title">Why</span></div>
            {result.threat_analysis.reasons.length === 0 ? (
              <div className="empty-state">No risk factors found.</div>
            ) : (
              <ul className="resilience-recs">
                {result.threat_analysis.reasons.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            )}
          </div>

          <div className="incident-case-grid" style={{ padding: '0 4px' }}>
            <div className="panel" style={{ padding: 14 }}>
              <div className="panel-header"><span className="panel-title">WHOIS</span></div>
              {result.whois.error ? (
                <div className="empty-state">{result.whois.error}</div>
              ) : (
                <div className="incident-case-grid">
                  <div className="incident-field"><span>Registrar</span><strong>{result.whois.registrar || '—'}</strong></div>
                  <div className="incident-field"><span>Domain Age</span><strong>{result.whois.domain_age_days ?? '—'} days</strong></div>
                </div>
              )}
            </div>
            <div className="panel" style={{ padding: 14 }}>
              <div className="panel-header"><span className="panel-title">SSL</span></div>
              {result.ssl.valid ? (
                <div className="incident-case-grid">
                  <div className="incident-field"><span>Issuer</span><strong>{result.ssl.issuer || '—'}</strong></div>
                  <div className="incident-field"><span>Days Remaining</span><strong>{result.ssl.days_remaining}</strong></div>
                </div>
              ) : (
                <div className="empty-state">{result.ssl.reason}</div>
              )}
            </div>
            <div className="panel" style={{ padding: 14 }}>
              <div className="panel-header"><span className="panel-title">DNS</span></div>
              <div className="incident-case-grid">
                <div className="incident-field"><span>MX Records</span><strong>{(result.dns.MX || []).length}</strong></div>
                <div className="incident-field"><span>NS Records</span><strong>{(result.dns.NS || []).length}</strong></div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
