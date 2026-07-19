import { useState } from 'react';
import { queryCopilot } from '../api';

const SUGGESTIONS = [
  'Why was the workstation isolated?',
  'Any suspicious OT activity?',
  'What is the predicted next stage?',
  'What is the current risk score?',
];

function buildRiskFactors(state) {
  if (state.events.length === 0) return [];
  const factors = [];
  const latest = state.events[state.events.length - 1];
  factors.push(`${latest.mitre_technique} detected (${latest.mitre_tactic})`);
  factors.push(latest.description);
  const compromised = state.nodes.filter((n) => n.status === 'compromised');
  if (compromised.length > 0) {
    factors.push(`${compromised.length} asset${compromised.length > 1 ? 's' : ''} currently compromised: ${compromised.map((n) => n.label).join(', ')}`);
  }
  const pending = state.pending_approvals;
  if (pending.length > 0) {
    factors.push(`${pending.length} response action${pending.length > 1 ? 's' : ''} awaiting analyst approval`);
  }
  return factors;
}

function RiskCard({ state }) {
  const factors = buildRiskFactors(state);
  const riskScore = state.events.length
    ? Math.round(Math.max(...state.events.map((e) => e.anomaly_score)) * 100)
    : 0;
  const recommended = state.pending_approvals.length > 0
    ? state.pending_approvals.map((a) => a.action)
    : state.soar_actions.length > 0
      ? ['Continue monitoring resolved actions for recurrence']
      : ['No action needed — continue baseline monitoring'];

  return (
    <div className="panel risk-card">
      <div className="panel-header">
        <span className="panel-title">Why is this critical?</span>
      </div>
      {factors.length === 0 ? (
        <div className="empty-state">No active incident. Nothing to explain yet.</div>
      ) : (
        <div className="risk-card-body">
          <ul className="risk-factor-list">
            {factors.map((f, i) => (
              <li key={i}>{f}</li>
            ))}
          </ul>
          <div className="risk-score-row">
            <span className="risk-score-label">Risk Score</span>
            <span className="risk-score-value">{riskScore}/100</span>
          </div>
          <div className="risk-actions">
            <div className="risk-actions-label">Recommended Action{recommended.length > 1 ? 's' : ''}</div>
            <ul className="risk-actions-list">
              {recommended.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

export default function AiInvestigation({ state }) {
  const [messages, setMessages] = useState([
    { role: 'assistant', text: 'Ask me about anything in the current incident — I can see the full graph, timeline, and audit log.' },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const ask = async (text) => {
    if (!text.trim() || loading) return;
    setMessages((m) => [...m, { role: 'user', text }]);
    setInput('');
    setLoading(true);
    try {
      const res = await queryCopilot(text);
      setMessages((m) => [...m, { role: 'assistant', text: res.answer }]);
    } catch {
      setMessages((m) => [...m, { role: 'assistant', text: 'Could not reach the analysis engine.' }]);
    }
    setLoading(false);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>AI Investigation</h1>
        <p className="page-subtitle">Explainable reasoning over the live incident, plus a copilot for open-ended questions.</p>
      </div>

      <RiskCard state={state} />

      <div className="panel copilot-panel">
        <div className="panel-header">
          <span className="panel-title">Cyber Copilot</span>
        </div>
        <div className="copilot-messages">
          {messages.map((m, i) => (
            <div key={i} className={`copilot-msg ${m.role}`}>
              {m.text}
            </div>
          ))}
          {loading && <div className="copilot-msg assistant loading">analyzing…</div>}
        </div>
        <div className="copilot-suggestions">
          {SUGGESTIONS.map((s) => (
            <button key={s} className="suggestion-chip" onClick={() => ask(s)}>
              {s}
            </button>
          ))}
        </div>
        <form
          className="copilot-input-row"
          onSubmit={(e) => {
            e.preventDefault();
            ask(input);
          }}
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about this incident…"
            className="copilot-input"
          />
          <button type="submit" className="copilot-send">Ask</button>
        </form>
      </div>
    </div>
  );
}
