import { useEffect, useState, useCallback } from 'react';
import { fetchState, resetScenario } from './api';
import Sidebar from './components/Sidebar';
import DataSourceToggle from './components/DataSourceToggle';
import MissionControl from './components/MissionControl';
import ExecutiveDashboard from './components/ExecutiveDashboard';
import AttackTimelinePage from './components/AttackTimelinePage';
import MitreMatrix from './components/MitreMatrix';
import AiInvestigation from './components/AiInvestigation';
import DigitalTwin from './components/DigitalTwin';
import ResilienceScore from './components/ResilienceScore';
import IncidentsEvidence from './components/IncidentsEvidence';
import ReportsPage from './components/ReportsPage';
import PhishingDemo from './components/PhishingDemo';
import UrlAnalyzer from './components/UrlAnalyzer';
import PackageTrustScanner from './components/PackageTrustScanner';
import LiveMonitorPanel from './components/LiveMonitorPanel';
import './App.css';

const HEALTH_COLOR = (score) => {
  if (score >= 80) return 'var(--signal-green)';
  if (score >= 50) return 'var(--signal-amber)';
  return 'var(--signal-red)';
};

const LOADING_MESSAGES = [
  'Establishing behavioral baseline…',
  'Loading threat intelligence…',
  'Building attack graph…',
  'Mapping MITRE ATT&CK techniques…',
];

function LoadingScreen() {
  const [i, setI] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setI((n) => (n + 1) % LOADING_MESSAGES.length), 1100);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="loading-screen">
      <div className="brand-mark loading-mark">R</div>
      <div>{LOADING_MESSAGES[i]}</div>
    </div>
  );
}

export default function App() {
  const [state, setState] = useState(null);
  const [error, setError] = useState(false);
  const [dataSource, setDataSource] = useState('demo'); // 'demo' | 'live'
  const [page, setPage] = useState('mission');

  const poll = useCallback(async () => {
    try {
      const s = await fetchState();
      setState(s);
      setError(false);
    } catch {
      setError(true);
    }
  }, []);

  useEffect(() => {
    poll();
    const id = setInterval(poll, 2000);
    return () => clearInterval(id);
  }, [poll]);

  const handleReset = async () => {
    await resetScenario();
    poll();
  };

  if (error) {
    return (
      <div className="connection-error">
        <p>Cannot reach the RAKSHA backend at localhost:8420.</p>
        <p className="dim">Make sure the FastAPI server is running.</p>
      </div>
    );
  }

  if (!state) {
    return <LoadingScreen />;
  }

  const renderPage = () => {
    switch (page) {
      case 'mission':
        return <MissionControl state={state} poll={poll} />;
      case 'executive':
        return <ExecutiveDashboard state={state} />;
      case 'timeline':
        return <AttackTimelinePage state={state} />;
      case 'mitre':
        return <MitreMatrix state={state} />;
      case 'investigation':
        return <AiInvestigation state={state} />;
      case 'twin':
        return <DigitalTwin state={state} />;
      case 'resilience':
        return <ResilienceScore state={state} />;
      case 'incidents':
        return <IncidentsEvidence state={state} />;
      case 'reports':
        return <ReportsPage state={state} />;
      case 'phishing':
        return <PhishingDemo state={state} />;
      case 'url-analyzer':
        return <UrlAnalyzer />;
      case 'pkg-scanner':
        return <PackageTrustScanner />;
      default:
        return <MissionControl state={state} poll={poll} />;
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-left">
          <div className="brand-mark">R</div>
          <div>
            <div className="brand-name">RAKSHA</div>
            <div className="brand-subtitle">AI-Driven Cyber Resilience — Critical National Infrastructure</div>
          </div>
        </div>

        <DataSourceToggle mode={dataSource} setMode={setDataSource} />

        <div className="topbar-right">
          {dataSource === 'demo' && (
            <>
              <div className="health-score">
                <span className="health-label">Cyber Health</span>
                <span className="health-value" style={{ color: HEALTH_COLOR(state.cyber_health_score) }}>
                  {state.cyber_health_score}
                </span>
              </div>
              <div className="health-score">
                <span className="health-label">Resilience</span>
                <span className="health-value" style={{ color: HEALTH_COLOR(state.resilience.overall) }}>
                  {state.resilience.overall}
                </span>
              </div>
              <div className="stage-indicator">
                Stage {state.current_stage + 1} / {state.total_stages} · {state.stage_name}
              </div>
              <button className="btn-reset" onClick={handleReset}>Reset scenario</button>
            </>
          )}
        </div>
      </header>

      {dataSource === 'demo' ? (
        <div className="app-body">
          <Sidebar page={page} setPage={setPage} />
          <div className="page-scroll">{renderPage()}</div>
        </div>
      ) : (
        <main className="live-main">
          <LiveMonitorPanel />
        </main>
      )}
    </div>
  );
}
