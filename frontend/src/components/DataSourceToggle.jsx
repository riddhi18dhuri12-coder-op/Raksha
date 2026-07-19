export default function DataSourceToggle({ mode, setMode }) {
  return (
    <div className="datasource-toggle">
      <span className="datasource-label">Data Source</span>
      <div className="datasource-options">
        <button
          className={`datasource-btn ${mode === 'demo' ? 'active' : ''}`}
          onClick={() => setMode('demo')}
        >
          <i className="ds-dot ds-dot-demo" /> Demo Mode
        </button>
        <button
          className={`datasource-btn ${mode === 'live' ? 'active' : ''}`}
          onClick={() => setMode('live')}
        >
          <i className="ds-dot ds-dot-live" /> Live Mode
        </button>
      </div>
    </div>
  );
}
