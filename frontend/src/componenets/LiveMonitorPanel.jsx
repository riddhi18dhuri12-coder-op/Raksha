import { useEffect, useRef, useState } from 'react';
import { startLiveMonitor, stopLiveMonitor, fetchLiveState } from '../api';

const KIND_COLOR = {
  process: 'var(--signal-amber)',
  connection: 'var(--signal-red)',
  resource: 'var(--signal-blue)',
};

function formatTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString('en-IN', { hour12: false });
}

export default function LiveMonitorPanel() {
  const [state, setState] = useState(null);
  const [starting, setStarting] = useState(false);
  const pollRef = useRef(null);

  const poll = async () => {
    try {
      const s = await fetchLiveState();
      setState(s);
    } catch {
      // backend not reachable, ignore for this panel
    }
  };

  useEffect(() => {
    poll();
    pollRef.current = setInterval(poll, 3000);
    return () => clearInterval(pollRef.current);
  }, []);

  const handleStart = async () => {
    setStarting(true);
    await startLiveMonitor();
    await poll();
    setStarting(false);
  };

  const handleStop = async () => {
    await stopLiveMonitor();
    await poll();
  };

  return (
    <div className="live-monitor-page">
      <div className="live-disclaimer">
        <strong>Read-only monitoring.</strong> This watches real processes, network
        connections, and CPU load on this machine and learns what's normal for it —
        it never kills a process, blocks a connection, or changes anything on your
        system. Safe to run alongside whatever else you're doing.
      </div>

      <div className="panel live-control-panel">
        <div className="panel-header">
          <span className="panel-title">Live System Monitor — this computer</span>
          {state?.running ? (
            <button className="btn-reset" onClick={handleStop}>Stop monitoring</button>
          ) : (
            <button className="btn-generate-report" onClick={handleStart} disabled={starting}>
              {starting ? 'Starting…' : 'Start monitoring'}
            </button>
          )}
        </div>

        {!state?.running && (
          <div className="empty-state">
            Not currently monitoring. Click "Start monitoring" to begin building a
            behavioral baseline of this machine.
          </div>
        )}

        {state?.running && state.baseline_building && (
          <div className="baseline-banner">
            <span className="prediction-eyebrow">Learning this machine's baseline</span>
            <span className="prediction-text">
              {state.baseline_seconds_remaining.toFixed(0)}s remaining
            </span>
            <span className="prediction-rationale">
              Observing normal processes, connections, and CPU load before flagging
              anything as a deviation — this avoids false alarms on things that were
              already running when monitoring started.
            </span>
          </div>
        )}

        {state?.running && !state.baseline_building && (
          <div className="live-stats-grid">
            <div className="ml-metric">
              <span className="ml-metric-value">{state.stats.process_count}</span>
              <span className="ml-metric-label">Processes now</span>
            </div>
            <div className="ml-metric">
              <span className="ml-metric-value">{state.stats.connection_count}</span>
              <span className="ml-metric-label">Connections now</span>
            </div>
            <div className="ml-metric">
              <span className="ml-metric-value">{state.known_process_count}</span>
              <span className="ml-metric-label">Known baseline processes</span>
            </div>
            <div className="ml-metric">
              <span className="ml-metric-value" style={{ color: state.events.length ? 'var(--signal-amber)' : 'var(--signal-green)' }}>
                {state.events.length}
              </span>
              <span className="ml-metric-label">Real deviations flagged</span>
            </div>
          </div>
        )}

        {state?.permission_note && (
          <div className="permission-note">{state.permission_note}</div>
        )}
      </div>

      <div className="panel live-feed-panel">
        <div className="panel-header">
          <span className="panel-title">Real Anomaly Feed</span>
          <span className="panel-count">this machine, live</span>
        </div>
        <div className="timeline-list">
          {(!state || state.events.length === 0) && (
            <div className="empty-state">
              {state?.running
                ? 'No deviations from baseline yet — try opening a new application to see it get flagged.'
                : 'Start monitoring to see real events from this machine appear here.'}
            </div>
          )}
          {state?.events.map((e) => (
            <div key={e.id} className="timeline-item">
              <div className="timeline-marker">
                <div className="timeline-dot" style={{ background: KIND_COLOR[e.kind] }} />
                <div className="timeline-line" />
              </div>
              <div className="timeline-content">
                <div className="timeline-top">
                  <span className="timeline-time">{formatTime(e.timestamp)}</span>
                  <span className="timeline-technique" style={{ color: KIND_COLOR[e.kind] }}>
                    {e.kind.toUpperCase()}
                  </span>
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
    </div>
  );
}
