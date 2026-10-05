# Evidence — 37 Items (37/37 checklist)

Evidence that the **Cybersecurity Awareness & Threat Intelligence Dashboard**
was actually built, executed and tested. Items **01–34 were generated from the
real running application** (real API responses, real database queries, real
test-suite output, real browser sessions). Items **35–37 are manual-only**
(GitHub screenshots and the rendered README preview) — they **cannot be
auto-generated and are never fabricated**; instructions for capturing them
are below.

> All data in every screenshot is **SYNTHETIC / DEMO ONLY** — safe
> documentation-range indicators (RFC 5737 / RFC 3849 / example.com /
> *.invalid / synthetic hashes / fictional CVE-format IDs).

---

## How items 01–34 were produced

From the project root with the backend running (`scripts\start_backend.bat`):

```
python scripts/generate_evidence.py     # data + API + browser evidence
python -m pytest tests -v --junitxml=reports/junit_results.xml
python scripts/make_test_report.py      # reports/test_report.md
```

The generator only captures **real output**: it calls the live API on
`127.0.0.1:8000`, queries the real SQLite database, imports the real service
functions, executes the real test suite, and drives a real headless-browser
session against the served frontend.

---

## Auto-generated evidence (01–34)

| # | File | What it shows | How it was captured |
|---|------|---------------|---------------------|
| 01 | `01_project_structure.png` | Full project directory tree | real filesystem listing |
| 02 | `02_generated_dataset.png` | 2,200-record dataset, columns, distributions | pandas read of the real CSV |
| 03 | `03_dataset_generator.png` | Deterministic data generator source | real source file `data/generate_threat_data.py` |
| 04 | `04_database_schema.png` | 11 tables, columns, FKs, row counts, indexes | `sqlite_master` + `PRAGMA table_info` on the real DB |
| 05 | `05_sample_threats_data.png` | Sample THREATS rows + pinned demo record | real SQL SELECT |
| 06 | `06_risk_scores_output.png` | 6-factor risk calculation → 78/HIGH | real call to `calculate_threat_risk()` |
| 07 | `07_confidence_scores_output.png` | Confidence model A/B/C/D + staleness | real call to `calculate_confidence()` |
| 08 | `08_ioc_validation_results.png` | IOC validation: 8 valid + 3 invalid cases | real call to `validate_indicator()` |
| 09 | `09_ioc_search_api.png` | IOC search UI after searching `198.51.100.25` | Playwright browser session |
| 10 | `10_threat_dashboard.png` | 7 KPI cards + 10 charts + filterable table | Playwright browser session |
| 11 | `11_threat_details.png` | THR-2026-001 investigation view (risk factors, ATT&CK, cluster, notes, timeline) | Playwright (analyst session) |
| 12 | `12_alerts_dashboard.png` | SOC alert queue with status cards + filters | Playwright browser session |
| 13 | `13_vulnerability_dashboard.png` | Vulnerability module + priority scoring | Playwright browser session |
| 14 | `14_mitre_attack.png` | ATT&CK concepts + tactic/technique analytics | Playwright browser session |
| 15 | `15_awareness_modules.png` | All 15 awareness modules grid | Playwright browser session |
| 16 | `16_awareness_module_detail.png` | Phishing module detail (5 required sections) | Playwright deep link `?module=phishing-awareness` |
| 17 | `17_quiz_page.png` | 36-question quiz UI | Playwright browser session |
| 18 | `18_quiz_results.png` | Score, band, category breakdown, recommendations | Playwright — all questions answered + submitted for real |
| 19 | `19_executive_summary.png` | Executive summary for non-technical stakeholders | Playwright browser session |
| 20 | `20_risk_calculation_code.png` | Risk engine source | real source `backend/services/risk_engine.py` |
| 21 | `21_ioc_validator_code.png` | IOC validator source | real source `backend/services/ioc_validator.py` |
| 22 | `22_alert_engine_code.png` | Alert rules + generation logic | real source `backend/services/alert_engine.py` |
| 23 | `23_correlation_output.png` | RELATED THREAT CLUSTER for THR-2026-001 | real call to `correlate_threats()` |
| 24 | `24_api_documentation.png` | Interactive API docs (Swagger UI) | Playwright on `/docs` served by FastAPI |
| 25 | `25_api_threats_response.png` | `GET /api/threats?limit=2&sort=risk` | real HTTP response |
| 26 | `26_api_dashboard_stats.png` | `GET /api/dashboard/stats` | real HTTP response |
| 27 | `27_api_alerts_response.png` | `GET /api/alerts?limit=2&sort=risk` | real HTTP response |
| 28 | `28_authentication_demo.png` | 401 (no key) / 403 (viewer) / 201 (analyst) + RBAC | real HTTP responses |
| 29 | `29_rate_limiting.png` | 240-request burst → 429 + `Retry-After` | real HTTP responses |
| 30 | `30_input_validation.png` | 422 validation rejections (enums, fields, indicator) | real HTTP responses |
| 31 | `31_audit_log.png` | AUDIT_LOG rows for a real status change | real SQL after a real audited action |
| 32 | `32_test_results.png` | Full pytest run → **72 passed** | real `pytest -v` execution |
| 33 | `33_test_coverage_scenarios.png` | T-001…T-035 coverage + security suite map | analysis of the real run |
| 34 | `34_security_verification.png` | S-01…S-13b security test verdicts | real `pytest -v` execution |

## Manual-only evidence (35–37) — NEVER fabricated

| # | File | What it must show | How to capture |
|---|------|-------------------|----------------|
| 35 | `35_github_commits.png` | Git commit history pushed to GitHub | After pushing: GitHub repo → **Commits** page → browser screenshot |
| 36 | `36_github_repository.png` | The GitHub repository page (files, README, topics) | GitHub repo main page → browser screenshot |
| 37 | `37_readme_preview.png` | README.md rendered on GitHub (top portion) | Repo main page (README rendered) → screenshot; or render locally |

Steps for 35–37 are in **docs/github_setup.md**. Do **not** create these files
artificially — if you have not pushed yet, leave them uncaptured; the project
is honest about what exists.

---

*Evidence regenerated at any time with `scripts/generate_evidence.bat`
(Windows) or `python scripts/generate_evidence.py`. The generator never
fakes output — if the backend is not running it fails loudly instead.*
