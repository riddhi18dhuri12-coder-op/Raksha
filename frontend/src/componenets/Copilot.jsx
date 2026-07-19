import { useState } from 'react';
import { queryCopilot } from '../api';

const SUGGESTIONS = [
  'Why was the workstation isolated?',
  'Any suspicious OT activity?',
  'What is the predicted next stage?',
  'What is the current risk score?',
];

export default function Copilot() {
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
  );
}
