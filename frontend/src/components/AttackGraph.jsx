import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

const STATUS_COLOR = {
  normal: '#3A4256',
  suspicious: '#F5A623',
  compromised: '#FF4D4F',
  contained: '#3DD68C',
};

const KIND_SHAPE = {
  user: 'ellipse',
  endpoint: 'round-rectangle',
  server: 'round-rectangle',
  segment: 'hexagon',
  ot_asset: 'diamond',
};

export default function AttackGraph({ nodes, edges }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const elements = [
      ...nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.label,
          status: n.status,
          kind: n.kind,
          score: n.anomaly_score,
        },
      })),
      ...edges.map((e) => ({
        data: { id: e.id, source: e.source, target: e.target, label: e.relation },
      })),
    ];

    if (!cyRef.current) {
      cyRef.current = cytoscape({
        container: containerRef.current,
        elements,
        layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.4, padding: 30 },
        style: [
          {
            selector: 'node',
            style: {
              'background-color': (ele) => STATUS_COLOR[ele.data('status')] || '#3A4256',
              shape: (ele) => KIND_SHAPE[ele.data('kind')] || 'ellipse',
              label: 'data(label)',
              color: '#E6E9EF',
              'font-family': 'IBM Plex Mono, monospace',
              'font-size': '11px',
              'text-valign': 'bottom',
              'text-margin-y': 10,
              width: 46,
              height: 46,
              'border-width': 2,
              'border-color': (ele) => (ele.data('status') === 'compromised' ? '#FF4D4F' : '#232A38'),
              'transition-property': 'background-color, border-color',
              'transition-duration': 300,
            },
          },
          {
            selector: 'edge',
            style: {
              width: 2,
              'line-color': '#2A3242',
              'target-arrow-color': '#2A3242',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              label: 'data(label)',
              'font-family': 'IBM Plex Mono, monospace',
              'font-size': '9px',
              color: '#5A6377',
              'text-rotation': 'autorotate',
              'text-margin-y': -8,
            },
          },
        ],
      });
    } else {
      const cy = cyRef.current;
      cy.batch(() => {
        nodes.forEach((n) => {
          const el = cy.getElementById(n.id);
          if (el.length) {
            el.data('status', n.status);
            el.data('score', n.anomaly_score);
          }
        });
      });
    }
  }, [nodes, edges]);

  useEffect(() => {
    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, []);

  return <div ref={containerRef} className="attack-graph-canvas" />;
}
