# RAKSHA — Setup Guide (No prior experience assumed)

This walks you through everything from an empty laptop to the full dashboard
running in your browser, plus the real ML model. Follow it top to bottom.

---

## Part 0 — What you're installing and why

| Tool | What it's for |
|---|---|
| **Python** | Runs the backend (the server that simulates the attack and serves data) and the ML training script |
| **Node.js** | Runs the frontend (the dashboard you see in the browser) |
| **A code editor (VS Code)** | Lets you open and read/edit the project files. Not strictly required to just *run* it, but strongly recommended |
| **A terminal** | Where you type the commands below. On Windows this is "Command Prompt" or "PowerShell" (or better, "Git Bash" / WSL). On Mac it's the "Terminal" app |

You will end up running **two servers at once** (backend + frontend), so you'll
need two terminal windows/tabs open at the same time. That's normal.

---

## Part 1 — Install Python

1. Go to **https://www.python.org/downloads/** and download the latest Python 3 installer for your OS.
2. Run the installer.
   - **Windows:** on the first install screen, tick the box **"Add Python to PATH"** before clicking Install. This step is easy to miss and causes most setup problems.
   - **Mac:** just run the installer normally.
3. Verify it worked — open a terminal and run:
   ```bash
   python3 --version
   ```
   You should see something like `Python 3.12.x`. (On Windows it may just be `python --version`.)

---

## Part 2 — Install Node.js

1. Go to **https://nodejs.org** and download the **LTS** version (the one marked "recommended for most users").
2. Run the installer with default settings.
3. Verify:
   ```bash
   node --version
   npm --version
   ```
   You should see version numbers for both (Node 18 or higher is fine).

---

## Part 3 — Install a code editor (optional but recommended)

1. Download **VS Code** from **https://code.visualstudio.com**.
2. Install it normally.
3. Once installed, you can right-click the unzipped `raksha` project folder and choose "Open with Code" to browse the files, or open VS Code and use File → Open Folder.

---

## Part 4 — Unzip the project

1. Unzip `raksha-prototype.zip` somewhere easy to find, e.g. your Desktop.
2. You should see two main folders inside: `backend/`, `frontend/`, plus an `ml/` folder and this guide.
3. Open a terminal and navigate into the project folder. For example, if it's on your Desktop:
   ```bash
   cd Desktop/raksha
   ```
   (On Windows with Command Prompt, use backslashes or just `cd Desktop\raksha`.)

---

## Part 5 — Run the backend (Terminal window #1)

```bash
cd backend
pip install -r requirements.txt
```

Wait for it to finish (installs FastAPI, scikit-learn, pandas, etc — this can
take a minute or two the first time).

Then start the server:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8420
```

(Using `python -m uvicorn` instead of plain `uvicorn` avoids a common Windows
issue where the command isn't found even after installing successfully.)

You should see something like:
```
Uvicorn running on http://0.0.0.0:8420
```

**Leave this terminal window open and running.** This is your backend server —
closing this window stops the whole system.

**Troubleshooting:**
- `pip: command not found` → try `pip3` instead of `pip`.
- `uvicorn: command not found` → try `python3 -m uvicorn main:app --host 0.0.0.0 --port 8420`.
- Permission errors on install → try adding `--user` to the pip install command.

---

## Part 6 — Train the real ML model (Terminal window #2, one-time step)

The dashboard's "ML Model Validation" panel needs a trained model file to exist.
Open a **new** terminal window (keep the backend one running) and:

```bash
cd ml
pip install -r requirements.txt
python train_anomaly_model.py
```

This trains a real anomaly detection model on the included NSL-KDD dataset
(a real, public intrusion-detection benchmark) and takes under a minute. When
it finishes you'll see printed metrics like detection rate and false positive
rate, and it saves `model.joblib`, `metrics.json`, and `sample_rows.csv` into
the `ml/` folder.

You only need to do this once — the backend picks up these files automatically
the next time you (re)start it. If you already started the backend in Part 5
*before* running this step, restart it (Ctrl+C in that terminal, then run the
`uvicorn` command again) so it picks up the trained model.

---

## Part 7 — Run the frontend (Terminal window #3)

Open another new terminal window and:

```bash
cd frontend
npm install
```

Wait for it to finish (downloads React, the graph library, etc — a minute or
two the first time).

Then start it:

```bash
npm run dev
```

You'll see something like:
```
➜  Local:   http://localhost:5173/
```

Open that URL in your browser (Chrome or Edge recommended). You should see the
RAKSHA dashboard, with the attack scenario already playing out.

**Leave this terminal open too.** You now have three things running:
1. Backend (terminal #1) — must stay running
2. Frontend (terminal #3) — must stay running
3. Terminal #2 (ML training) — already finished, can be closed

---

## Part 8 — Using the dashboard

- The attack plays out automatically, one stage every ~18 seconds.
- Click **Reset scenario** (top right) to replay it from the beginning — useful right before you present to judges.
- When a red/amber "pending approval" action shows up in the Response Orchestrator panel, click **Approve** or **Reject** to see the trust-gating in action.
- Try the Copilot chat with things like "why was the workstation isolated?"
- Click **Generate incident report** any time to see the auto-compiled report.
- The **ML Model Validation** panel on the right shows the real detection rate/false-positive rate from Part 6, and has a button to test the model live on a random real record.
- Click the **Live Mode** toggle at the top to switch to real, read-only monitoring of your own machine — click **Start monitoring**, wait ~30 seconds for it to learn your machine's normal baseline, then try opening a new application and watch it get flagged as a real deviation within a few seconds. This never takes any action on your system — it only observes.
- The **Phishing Demo** page in the sidebar opens a self-contained, clearly-labeled fake bank login page in a new tab — it's a training tool, not a real site, and nothing leaves your machine. Anything typed into it shows up live on that page and in the audit log, the same way a real detection pipeline would react to a credential-harvesting attempt.

---

## Part 9 — Stopping everything

In each terminal window, press `Ctrl+C` to stop that server. Closing the
terminal windows also stops them.

To run it again later, you just repeat Part 5 and Part 7 (you don't need to
run `pip install`/`npm install` again unless you change dependencies, and you
don't need to retrain the ML model again unless you want to).

---

## Common problems

| Problem | Fix |
|---|---|
| Dashboard says "Cannot reach the RAKSHA backend" | The backend (Part 5) isn't running, or crashed. Check terminal #1 for errors. |
| `npm install` fails with permission errors | On Mac/Linux, avoid using `sudo npm install` — instead reinstall Node via nodejs.org rather than a system package manager. |
| Port already in use (`8420` or `5173`) | Something else is using that port. Close other terminals running the project, or restart your computer. |
| ML panel says "Model not trained yet" | Repeat Part 6, then restart the backend (Ctrl+C in terminal #1, then run the `uvicorn` command again). |
| Blank page in browser | Hard-refresh the page (Ctrl+Shift+R / Cmd+Shift+R). Make sure both backend and frontend terminals show no errors. |
| **Windows: `pip install` fails trying to build scikit-learn** with errors mentioning `meson`, `Unknown compiler`, or `Microsoft Visual C++` | This means pip couldn't find a pre-built package for your Python version and tried to compile it from source (which needs a C++ compiler you likely don't have). Fix: run `pip install --upgrade pip` first, then retry `pip install -r requirements.txt`. If it still fails, check `python --version` — if it's a very new release (e.g. 3.13+), install Python 3.12 instead from python.org and use that to run the project, since library authors take time to publish pre-built packages for brand-new Python versions. |
| Windows: `uvicorn : The term 'uvicorn' is not recognized` | This happens when `pip install` didn't fully succeed (see above — fix that first) or when Python's Scripts folder isn't on PATH. Workaround that always works: run `python -m uvicorn main:app --host 0.0.0.0 --port 8420` instead of `uvicorn main:app ...`. |

---

## For the hackathon demo itself

- Start the backend and frontend **5–10 minutes before** your slot, so `npm install`/`pip install` delays don't eat into your time.
- Click **Reset scenario** right before you start talking, so the attack begins from stage 1 while you're presenting — it lines up nicely with a "watch this unfold live" narrative.
- Have the ML Model Validation panel ready to point at — real numbers on a real dataset is a strong, concrete answer if judges ask "is this actually detecting anything or is it just a mockup?"
