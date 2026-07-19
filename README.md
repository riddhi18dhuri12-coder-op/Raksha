# RAKSHA — AI-Driven Cyber Resilience for Critical National Infrastructure

A working full-stack prototype for the ET AI Hackathon (2nd Edition), Problem Statement 7.

RAKSHA simulates a realistic multi-stage attack against a mixed IT/OT critical
infrastructure environment (a water utility) and demonstrates behavioral
anomaly detection, attack prediction, MITRE ATT&CK mapping, trust-gated
autonomous containment, a tamper-evident audit log, and an AI copilot — all
driven by a live, self-advancing scenario so the demo plays out on its own.

**New: real live monitoring of your own machine.** Beyond the scripted attack
demo and the offline NSL-KDD benchmark, RAKSHA now has a **Live Monitor** tab
that does real, read-only behavioral monitoring of the computer it's running
on — real processes, real network connections, real CPU load. It learns a
short baseline of what's normal for that machine, then flags genuine
deviations as they happen (a new process appearing, a connection to an IP
never seen before, an unexplained CPU spike). This never takes any action on
your real system — it only observes and reports, by design.

If you're new to any of this, **start with `SETUP_GUIDE.md`** — it assumes no
prior experience with Python, Node, or terminals.

## What's included

- **backend/** — FastAPI service. `scenario.py` is the scripted-demo simulation
  engine (attack graph, anomaly events, predictions, SOAR actions, hash-chained
  audit log). `live_agent.py` is the **real** monitoring engine — watches actual
  processes/connections/CPU on the host machine via `psutil` and flags real
  deviations from a learned baseline. `copilot.py` answers analyst questions and
  generates incident reports. `ml_service.py` loads the trained ML model and
  serves its metrics and live predictions. `main.py` exposes it all as REST
  endpoints.
- **ml/** — `train_anomaly_model.py` trains a real, unsupervised anomaly
  detector on the real NSL-KDD dataset (included in `ml/data/`) and saves the
  trained model + evaluation metrics. This is what backs the "ML Model
  Validation" panel on the dashboard.
- **frontend/** — React (Vite) dashboard. A top-right **Data Source** toggle
  switches between **Demo Mode** (the scripted scenario, below) and **Live
  Mode** (the Live Monitor panel — real-time behavioral monitoring of your
  own machine, with a start/stop control and a live event feed). Demo Mode is
  organized as a full SOC-platform navigation rather than a single dashboard:
  - **Mission Control** — live attack graph, threat timeline, SOAR panel, ML
    validation, audit log (this is the original single-page dashboard)
  - **Executive Dashboard** — CISO/board-level KPI tiles (current risk,
    critical assets at risk, time to detection, containment success, etc.)
  - **Attack Timeline** — kill-chain stepper showing which stages of the
    intrusion have been reached, plus the full event log
  - **MITRE ATT&CK** — tactic coverage bar chart with click-through
    technique detail (confidence, mapped technique, reasoning)
  - **AI Investigation** — an explainable "why is this critical?" risk card
    (factors, risk score, recommended actions) plus the Cyber Copilot chat
  - **Digital Twin** — an animated SVG mirror of the network topology; node
    color reflects real detection status and a pulse animates the path an
    active attack is taking
  - **Resilience Score** — a dedicated Cyber Resilience Score (recovery
    readiness, attack resistance, backup health, patch compliance, critical
    asset protection, zero-trust maturity) with recommendations — this is
    the "beyond detection" metric problem statement 7 asks for
  - **Incidents & Evidence Vault** — a case-file view (ID, severity,
    assigned team, status) plus the underlying evidence artifacts (event
    log, audit trail, IOC list, response action log)
  - **Reports** — one-click report generation with a downloadable `.txt`
    export
  - **Phishing Demo** — launches the simulated "SecureTrust Bank" login page
    (moved to `frontend/public/phishing_demo/` so Vite actually serves it;
    it previously sat outside `public/` and had no route) and lists captured
    submissions live, pulled from the same masked-password endpoint in
    `backend/routes/phishing.py` and mirrored into the hash-chained audit log
  - **URL Analyzer** — ported from a standalone phishing-URL detector
    project: a trained logistic-regression model (`backend/models/url_analyzer_model.pkl`)
    plus live WHOIS, SSL, and DNS checks against the real domain
    (`backend/routes/url_analyzer.py`), combined into one risk score
  - **Package Trust Scanner** — ported from an npm supply-chain security CLI
    (`pkg-sentinel`): live typosquat detection (Levenshtein distance +
    pattern matching against a curated popular-package list) plus
    install-script risk heuristics, run against a package's real, live
    npm registry metadata (`backend/routes/pkg_sentinel.py`). This ports the
    core detection logic (typosquatting + script pattern heuristics); it
    does not replicate pkg-sentinel's full AST-based analysis of arbitrary
    JS files inside a package's tarball, which is a much larger standalone
    toolchain — see the docstring in `pkg_sentinel.py` for the exact scope.

  The whole UI is skinned as a full 8-bit/16-bit retro interface (bitmap
  font, chunky black borders, hard offset pixel shadows, blocky palette,
  square swatches instead of circles) — see the "PIXEL / 8-BIT THEME
  OVERRIDE" section at the bottom of `frontend/src/App.css` and the palette
  in `frontend/src/index.css`.

  All of these pages read from the same `/api/state` payload the original
  dashboard used (extended with `executive_summary`, `mitre_coverage`, and
  `resilience` fields in `scenario.py`) — no new simulated inputs were
  introduced, just new views over the same real underlying data.

## Running it

Full beginner walkthrough: see `SETUP_GUIDE.md`. Quick version below.

**1. Train the ML model** (one-time step, needs Python 3.10+):
```bash
cd ml
pip install -r requirements.txt
python train_anomaly_model.py
```

**2. Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8420
```

**3. Frontend** (needs Node 18+, in a separate terminal):
```bash
cd frontend
npm install
npm run dev
```

Open the URL Vite prints (default `http://localhost:5173`). The backend must
be running on port 8420 — the frontend polls `http://localhost:8420` directly
(see `frontend/src/api.js` if you need to change the port).

## How the demo works

The scenario auto-advances through 5 attack stages every ~18 seconds from the
moment the backend starts (phishing → PowerShell execution → credential
dumping → lateral movement to the domain controller → OT command injection
attempt). Each stage:

1. Lights up a node/edge on the live attack graph
2. Fires an anomaly event mapped to a MITRE ATT&CK technique
3. Updates the "predicted next stage" banner with a confidence score
4. May trigger a SOAR action — auto-executed if confidence is high and blast
   radius is low, otherwise held for your approval in the SOAR panel

Use the **Reset scenario** button to replay it from the start at any time —
useful for live demos/judging so you can control exactly when it begins.

Try asking the Copilot things like:
- "Why was the workstation isolated?"
- "Any suspicious OT activity?"
- "What's the predicted next stage?"

Click **Generate incident report** at any point to see the auto-compiled
compliance report drawn from the current timeline and audit log.

## Using the Live Monitor tab (real data, your machine)

Click the **"Live Monitor — this computer"** tab at the top, then **Start
monitoring**. For the first 30 seconds it silently learns what's normal for
your machine right now (running processes, active connections, typical CPU
load) — this baseline window avoids flagging things that were already
running before you started as if they were new. After that, real deviations
appear in the feed as they happen:

- Open a new application → watch a new process get flagged within a few seconds
- It also picks up new outbound network connections and unusual CPU spikes

This is genuinely live and genuinely read-only — it will never close a
program, block a connection, or change anything on your system. It's the
"real computer" counterpart to the scripted demo: same behavioral-baseline
philosophy, applied to data that's actually yours instead of a canned script.

## What's simulated vs. real here

This is a hackathon-stage prototype. The **scenario itself** (which attack
happens, its timing, its scores) is scripted rather than inferred from live
telemetry — that's deliberate, so the demo is reliable and repeatable in
front of judges. The **architecture around it is real**: the graph
correlation model, the trust-gating logic (confidence + blast radius +
approval threshold), the hash-chained audit log, and the copilot's
retrieval-based reasoning over live state are all functioning exactly as
they would with real ML models and real telemetry feeding in. The natural
next step is swapping the scripted stage generator in `scenario.py` for
real anomaly-detection models (LSTM-Autoencoder / Isolation Forest) trained
on the public CICIDS2017 (IT) and SWaT/WADI (OT) datasets referenced in the
project plan.

## Next build priorities (not yet implemented)

- Feed the trained NSL-KDD model's real-time verdicts into the live scenario
  itself (currently they run side-by-side as an independent validation panel,
  not yet driving the scripted attack's anomaly scores)
- An OT-specific model trained on SWaT/WADI (ICS telemetry) to complement the
  IT-side NSL-KDD model, matching the "IT + OT unified" pitch
- Graph DB (Neo4j) backing the attack graph instead of an in-memory dict, so
  it can scale beyond one scripted scenario
- WebSocket push instead of polling, for lower-latency updates at scale
- Role-based dashboard views (SOC analyst vs. CISO vs. executive)
- Digital twin simulation mode (test a containment action without applying it)
