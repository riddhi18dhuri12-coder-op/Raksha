import { useState } from 'react';
import { scanPackage } from '../api';

function trustColorVar(level) {
  if (level === 'Trusted') return 'var(--signal-green)';
  if (level === 'Caution') return 'var(--signal-amber)';
  return 'var(--signal-red)';
}

export default function PackageTrustScanner() {
  const [pkg, setPkg] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    if (!pkg.trim() || loading) return;
    setLoading(true);
    setError(null);
    try {
      const res = await scanPackage(pkg.trim());
      setResult(res);
    } catch {
      setError('Could not reach the scanner backend.');
    }
    setLoading(false);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Package Trust Scanner</h1>
        <p className="page-subtitle">
          Ported from an npm supply-chain security CLI: live typosquat detection against a
          curated popular-package list, plus install-script risk heuristics run against the
          package's real, live npm registry metadata.
        </p>
      </div>

      <form className="panel url-analyzer-form" onSubmit={submit}>
        <input
          className="copilot-input url-analyzer-input"
          placeholder="npm package name, e.g. expres or lod4sh"
          value={pkg}
          onChange={(e) => setPkg(e.target.value)}
        />
        <button className="btn-generate-report" type="submit" disabled={loading}>
          {loading ? 'Scanning…' : 'Scan Package'}
        </button>
      </form>

      {error && <div className="panel"><div className="empty-state">{error}</div></div>}

      {result && (
        <>
          {result.registry_error && (
            <div className="panel"><div className="empty-state">{result.registry_error}</div></div>
          )}

          <div className="panel resilience-hero">
            <div className="resilience-hero-score" style={{ color: trustColorVar(result.trust_level) }}>
              {result.trust_score}<span>/100</span>
            </div>
            <div className="resilience-hero-label">{result.trust_level} · {result.package}</div>
          </div>

          <div className="panel">
            <div className="panel-header"><span className="panel-title">Why</span></div>
            {result.reasons.length === 0 ? (
              <div className="empty-state">No risk factors found — looks clean.</div>
            ) : (
              <ul className="resilience-recs">
                {result.reasons.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            )}
          </div>

          {result.typosquat_findings.length > 0 && (
            <div className="panel">
              <div className="panel-header"><span className="panel-title">Typosquat Matches</span></div>
              <div className="evidence-list">
                {result.typosquat_findings.map((f, i) => (
                  <div className="evidence-item" key={i}>
                    <div className="evidence-icon">⚠️</div>
                    <div className="evidence-body">
                      <div className="evidence-title-row">
                        <span className="evidence-title">Similar to "{f.similar_to}"</span>
                      </div>
                      <div className="evidence-detail">
                        {f.matches.map((m) => m.description).join('; ')}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {Object.keys(result.metadata).length > 0 && (
            <div className="panel">
              <div className="panel-header"><span className="panel-title">Registry Metadata</span></div>
              <div className="incident-case-grid">
                <div className="incident-field"><span>Latest Version</span><strong>{result.metadata.latest_version || '—'}</strong></div>
                <div className="incident-field"><span>Total Versions</span><strong>{result.metadata.total_versions}</strong></div>
                <div className="incident-field"><span>Package Age</span><strong>{result.metadata.package_age_days ?? '—'} days</strong></div>
                <div className="incident-field"><span>Maintainers</span><strong>{result.metadata.maintainer_count}</strong></div>
                <div className="incident-field"><span>Repository Listed</span><strong>{result.metadata.has_repository ? 'Yes' : 'No'}</strong></div>
                <div className="incident-field"><span>License</span><strong>{result.metadata.license || '—'}</strong></div>
              </div>
            </div>
          )}

          {Object.keys(result.install_scripts || {}).length > 0 && (
            <div className="panel">
              <div className="panel-header"><span className="panel-title">Install Scripts (from package.json)</span></div>
              <ul className="resilience-recs">
                {Object.entries(result.install_scripts).map(([name, cmd]) => (
                  <li key={name}><strong>{name}</strong>: {cmd}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}
