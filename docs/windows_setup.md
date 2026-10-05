# Windows Setup & Execution Guide

The complete 15-step local workflow (project-brief section 41). Every step
is automated by the scripts in `scripts/`.

## Quick start (automated)

```bat
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
scripts\setup_windows.bat        :: steps 1-3: venv + dependencies (+ .env)
scripts\generate_data.bat        :: step 4:  regenerate the synthetic dataset
scripts\start_backend.bat        :: steps 5-6: init DB + start API server
scripts\start_frontend.bat       :: steps 7-8: open the dashboard
scripts\run_tests.bat            :: run the 72-test automated suite
scripts\generate_evidence.bat    :: regenerate local evidence screenshots
```

## The 15 required steps, exactly

| # | Step | Command / action |
|---|------|------------------|
| 1 | Create project folder | download/extract the project ZIP |
| 2 | Create Python virtual environment | `scripts\setup_windows.bat` (creates `venv\`) |
| 3 | Install dependencies | done by the same script (`pip install -r requirements.txt`) |
| 4 | Generate synthetic threat data | `scripts\generate_data.bat` |
| 5 | Initialize database | `scripts\start_backend.bat` (auto-initializes if missing) — or `venv\Scripts\python -m scripts.init_database` |
| 6 | Start backend | `scripts\start_backend.bat` → http://127.0.0.1:8000 (API at /api, docs at /docs) |
| 7 | Start frontend | `scripts\start_frontend.bat` → opens the dashboard in your browser |
| 8 | Open threat dashboard | Threat Dashboard page — 7 KPI cards + 10 charts |
| 9 | Search synthetic IOC | IOC Search → `198.51.100.25` |
| 10 | Open threat details | click any row, e.g. `THR-2026-001` |
| 11 | Review ATT&CK mapping | MITRE ATT&CK page — click a technique to drill into records |
| 12 | Review vulnerabilities | Vulnerabilities page — contextual priority vs CVSS |
| 13 | Open Awareness Center | Awareness Center — 15 modules |
| 14 | Complete quiz | Security Quiz — answer the 36 questions and submit |
| 15 | View awareness score | result screen: score, band, category scores, weakest areas, recommendations |

Then explore the **Alert Queue**, **Executive View**, and **SOC Workflow**
pages, and sign in with a demo API key (from `.env.example`) to use analyst
functions (notes, status changes).

## Manual commands (if you prefer typing)

```bat
:: 1-3 : environment
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env

:: 4 : data (2,200 threat records + 60 synthetic CVEs)
python data\generate_threat_data.py

:: 5 : database
python -m scripts.init_database

:: 6 : backend (serves API + frontend on one port)
cd backend
..\venv\Scripts\python -m uvicorn app:app --host 127.0.0.1 --port 8000
cd ..

:: 7-8 : open the app
start http://127.0.0.1:8000

:: tests
venv\Scripts\python -m pytest tests -v
```

## Optional: separate static frontend server

The backend already serves the frontend, but if you want the "separate
frontend" arrangement:

```bat
python -m http.server 5500 --directory frontend
start http://127.0.0.1:5500
```
The frontend auto-detects this and calls the API at `127.0.0.1:8000` (CORS
is enabled for local development).

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` not recognized | Install Python 3.9+ from python.org and tick "Add to PATH", or use `py` instead of `python` |
| Port 8000 busy | change the port in `scripts\start_backend.bat` and open the matching URL |
| Data looks different from screenshots | regenerate: `scripts\generate_data.bat` then `python -m scripts.init_database` (dataset is seeded and deterministic) |
| Browser shows "Cannot reach the backend" | start the backend first; if using the separate frontend server, check the API URL printed in the error |
| Analyst actions return 401 | sign in with a demo key from `.env.example` (top-right button) |
