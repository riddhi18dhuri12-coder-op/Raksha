const BASE = 'http://localhost:8420';

export async function fetchState() {
  const res = await fetch(`${BASE}/api/state`);
  if (!res.ok) throw new Error('Failed to fetch state');
  return res.json();
}

export async function resetScenario() {
  const res = await fetch(`${BASE}/api/reset`, { method: 'POST' });
  return res.json();
}

export async function sendSoarDecision(actionId, approved) {
  const res = await fetch(`${BASE}/api/soar/decision`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action_id: actionId, approved }),
  });
  return res.json();
}

export async function queryCopilot(query) {
  const res = await fetch(`${BASE}/api/copilot/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  });
  return res.json();
}

export async function fetchIncidentReport() {
  const res = await fetch(`${BASE}/api/incident-report`);
  return res.json();
}

export async function fetchMlMetrics() {
  const res = await fetch(`${BASE}/api/ml/metrics`);
  return res.json();
}

export async function fetchMlSamplePrediction() {
  const res = await fetch(`${BASE}/api/ml/sample-prediction`);
  return res.json();
}

export async function startLiveMonitor() {
  const res = await fetch(`${BASE}/api/live/start`, { method: 'POST' });
  return res.json();
}

export async function stopLiveMonitor() {
  const res = await fetch(`${BASE}/api/live/stop`, { method: 'POST' });
  return res.json();
}

export async function fetchLiveState() {
  const res = await fetch(`${BASE}/api/live/state`);
  return res.json();
}

export async function fetchPhishingCaptures() {
  const res = await fetch(`${BASE}/api/phishing-demo/captures`);
  return res.json();
}

export async function resetPhishingCaptures() {
  const res = await fetch(`${BASE}/api/phishing-demo/reset`, { method: 'POST' });
  return res.json();
}

export async function scanUrl(url) {
  const res = await fetch(`${BASE}/api/url-analyzer/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  return res.json();
}

export async function scanPackage(pkg) {
  const res = await fetch(`${BASE}/api/pkg-sentinel/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: pkg }),
  });
  return res.json();
}
