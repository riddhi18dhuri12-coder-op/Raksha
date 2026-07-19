// Minimal 16x16-grid pixel-art icon set (blocky rects, currentColor) so the
// sidebar and status badges read as one consistent retro icon system
// instead of mismatched platform emoji.

const common = { viewBox: '0 0 16 16', shapeRendering: 'crispEdges' };

const PATHS = {
  mission: (
    <>
      <rect x="2" y="9" width="3" height="5" />
      <rect x="6.5" y="6" width="3" height="8" />
      <rect x="11" y="2" width="3" height="12" />
    </>
  ),
  executive: (
    <>
      <rect x="2" y="2" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="4" y="9" width="2" height="3" />
      <rect x="7" y="6" width="2" height="6" />
      <rect x="10" y="4" width="2" height="8" />
    </>
  ),
  timeline: (
    <>
      <rect x="1" y="7" width="14" height="2" />
      <rect x="1" y="7" width="3" height="3" />
      <rect x="6.5" y="6" width="3" height="4" />
      <rect x="12" y="7" width="3" height="3" />
    </>
  ),
  mitre: (
    <>
      <rect x="6.5" y="1" width="3" height="14" />
      <rect x="1" y="6.5" width="14" height="3" />
    </>
  ),
  investigation: (
    <>
      <circle cx="6.5" cy="6.5" r="4.5" fill="none" stroke="currentColor" strokeWidth="1.7" />
      <rect x="10.5" y="10.5" width="4" height="2" transform="rotate(45 10.5 10.5)" />
    </>
  ),
  twin: (
    <>
      <rect x="1" y="1" width="6" height="6" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="9" y="9" width="6" height="6" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="7" y="7" width="2" height="2" />
    </>
  ),
  resilience: (
    <path d="M8 1 L14 3.5 V8 C14 11.5 11.5 14 8 15 C4.5 14 2 11.5 2 8 V3.5 Z" />
  ),
  incidents: (
    <>
      <rect x="2" y="3" width="12" height="10" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="2" y="3" width="12" height="3" />
    </>
  ),
  reports: (
    <>
      <rect x="3" y="1" width="10" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="5" y="4" width="6" height="1.4" />
      <rect x="5" y="7" width="6" height="1.4" />
      <rect x="5" y="10" width="4" height="1.4" />
    </>
  ),
  phishing: (
    <>
      <rect x="1" y="4" width="14" height="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <path d="M1.5 4.5 L8 9 L14.5 4.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="10" y="9.5" width="4.5" height="4.5" fill="var(--signal-red)" stroke="#000" strokeWidth="1" />
    </>
  ),
  'url-analyzer': (
    <>
      <circle cx="6.5" cy="6.5" r="4.5" fill="none" stroke="currentColor" strokeWidth="1.7" />
      <rect x="10" y="10" width="4.5" height="2" transform="rotate(45 10 10)" />
    </>
  ),
  'pkg-scanner': (
    <>
      <rect x="2" y="5" width="12" height="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <path d="M2 5 L8 1.5 L14 5" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <rect x="7" y="8" width="2" height="4" />
    </>
  ),
};

export default function PixelIcon({ id, size = 18 }) {
  const glyph = PATHS[id];
  if (!glyph) return null;
  return (
    <svg
      {...common}
      width={size}
      height={size}
      fill="currentColor"
      style={{ imageRendering: 'pixelated', flexShrink: 0 }}
      aria-hidden="true"
    >
      {glyph}
    </svg>
  );
}
