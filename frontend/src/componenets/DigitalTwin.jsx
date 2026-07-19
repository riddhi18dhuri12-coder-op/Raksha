const STATUS_COLOR = {
  normal: '#3A4256',
  suspicious: '#F5A623',
  compromised: '#FF4D4F',
  contained: '#3DD68C',
};

const KIND_LABEL = {
  user: 'USER',
  endpoint: 'ENDPOINT',
  server: 'SERVER',
  segment: 'SEGMENT',
  ot_asset: 'OT ASSET',
};

// Fixed vertical layout for this environment's topology (5 real assets,
// plus a static perimeter "Internet" node for visual framing only --
// it carries no live status of its own).
const LAYOUT = {
  'user.rkumar': { x: 260, y: 130 },
  'ep.wks-fin-014': { x: 260, y: 230 },
  'srv.dc-01': { x: 260, y: 330 },
  'seg.ot-a': { x: 260, y: 430 },
  'ot.plc-water-03': { x: 260, y: 530 },
};

export default function DigitalTwin({ state }) {
  const nodeById = Object.fromEntries(state.nodes.map((n) => [n.id, n]));

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Digital Twin</h1>
        <p className="page-subtitle">
          A live mirror of the water utility network topology. Node color reflects real detection status;
          the pulse animates the path an active attack is taking through the environment. Nothing is
          altered on the twin itself — it visualizes the same state as the attack graph.
        </p>
      </div>

      <div className="panel twin-panel">
        <svg viewBox="0 0 520 620" className="twin-svg" xmlns="http://www.w3.org/2000/svg">
          {/* perimeter node */}
          <rect x="185" y="20" width="150" height="46" rx="8" fill="#161C29" stroke="#232A38" strokeWidth="1.5" />
          <text x="260" y="48" textAnchor="middle" className="twin-node-text">INTERNET</text>
          <line x1="260" y1="66" x2="260" y2="105" stroke="#2A3242" strokeWidth="2" />

          {/* edges between real nodes */}
          {state.edges.map((e) => {
            const from = LAYOUT[e.source];
            const to = LAYOUT[e.target];
            if (!from || !to) return null;
            const sourceNode = nodeById[e.source];
            const active = sourceNode && sourceNode.status !== 'normal';
            return (
              <g key={e.id}>
                <line
                  x1={from.x} y1={from.y + 25} x2={to.x} y2={to.y - 25}
                  stroke={active ? '#F5A623' : '#2A3242'}
                  strokeWidth="2"
                />
                <text x={from.x + 14} y={(from.y + to.y) / 2 + 5} className="twin-edge-label">
                  {e.relation}
                </text>
                {active && (
                  <circle r="4" fill="#FF4D4F">
                    <animateMotion
                      dur="1.6s"
                      repeatCount="indefinite"
                      path={`M ${from.x} ${from.y + 25} L ${to.x} ${to.y - 25}`}
                    />
                  </circle>
                )}
              </g>
            );
          })}

          {/* real asset nodes */}
          {state.nodes.map((n) => {
            const pos = LAYOUT[n.id];
            if (!pos) return null;
            const color = STATUS_COLOR[n.status] || STATUS_COLOR.normal;
            return (
              <g key={n.id}>
                <rect
                  x={pos.x - 100} y={pos.y - 25} width="200" height="50" rx="8"
                  fill="#161C29" stroke={color} strokeWidth={n.status === 'normal' ? 1.5 : 2.5}
                />
                {n.status !== 'normal' && (
                  <rect
                    x={pos.x - 100} y={pos.y - 25} width="200" height="50" rx="8"
                    fill={color} opacity="0.08"
                  />
                )}
                <text x={pos.x} y={pos.y - 4} textAnchor="middle" className="twin-node-text">{n.label}</text>
                <text x={pos.x} y={pos.y + 14} textAnchor="middle" className="twin-node-sub" fill={color}>
                  {KIND_LABEL[n.kind] || n.kind} · {n.status.toUpperCase()}
                </text>
              </g>
            );
          })}
        </svg>
        <div className="graph-legend twin-legend">
          <span><i className="dot" style={{ background: '#3A4256' }} /> Normal</span>
          <span><i className="dot" style={{ background: '#F5A623' }} /> Suspicious / active path</span>
          <span><i className="dot" style={{ background: '#FF4D4F' }} /> Compromised</span>
          <span><i className="dot" style={{ background: '#3DD68C' }} /> Contained</span>
        </div>
      </div>
    </div>
  );
}
