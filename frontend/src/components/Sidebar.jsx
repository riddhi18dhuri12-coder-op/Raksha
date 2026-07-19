import PixelIcon from './PixelIcon';

const NAV_ITEMS = [
  { id: 'mission', label: 'Mission Control' },
  { id: 'executive', label: 'Executive Dashboard' },
  { id: 'timeline', label: 'Attack Timeline' },
  { id: 'mitre', label: 'MITRE ATT&CK' },
  { id: 'investigation', label: 'AI Investigation' },
  { id: 'twin', label: 'Digital Twin' },
  { id: 'resilience', label: 'Resilience Score' },
  { id: 'incidents', label: 'Incidents & Evidence' },
  { id: 'reports', label: 'Reports' },
  { id: 'phishing', label: 'Phishing Demo' },
  { id: 'url-analyzer', label: 'URL Analyzer' },
  { id: 'pkg-scanner', label: 'Package Trust Scanner' },
];

export default function Sidebar({ page, setPage }) {
  return (
    <nav className="sidebar">
      {NAV_ITEMS.map((item) => (
        <button
          key={item.id}
          className={`sidebar-item ${page === item.id ? 'active' : ''}`}
          onClick={() => setPage(item.id)}
        >
          <span className="sidebar-icon"><PixelIcon id={item.id} /></span>
          <span className="sidebar-label">{item.label}</span>
        </button>
      ))}
    </nav>
  );
}
