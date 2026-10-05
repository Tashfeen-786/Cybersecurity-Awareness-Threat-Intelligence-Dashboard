# Cybersecurity Awareness & Threat Intelligence Dashboard

**A complete, defensive, offline-capable security project** — a SOC-style
threat-intelligence analysis platform combined with an interactive security
awareness training program. Built with Python (FastAPI, SQLite, pandas) and a
static HTML/CSS/JS frontend with Chart.js.

> **All data in this project is SYNTHETIC / DEMO ONLY.** Every indicator is a
> safe documentation-range value (RFC 5737 IPv4, RFC 3849 IPv6,
> example.com/.org/.net, *.invalid, synthetic hashes, fictional CVE-format
> IDs). The application never contacts, visits, resolves, or executes any
> indicator.

---

## 1. Ethical Disclaimer

> **This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.**

No real infrastructure is ever contacted. IOC "enrichment" is a local
database lookup only. The project contains zero attack tooling and zero real
indicators of compromise.

---

## 2. What this project is

A dual-purpose defensive platform:

1. **Threat Intelligence Dashboard** — ingest, validate, enrich, score,
   correlate, alert and investigate 2,200+ synthetic threat records through a
   realistic Tier-1 SOC workflow, with MITRE ATT&CK mapping and contextual
   vulnerability prioritization.
2. **Security Awareness Center** — 15 training modules, a 36-question scored
   quiz across 10 categories, personalized learning recommendations, and an
   executive summary for non-technical stakeholders.

Everything runs locally, offline, on Windows with double-click scripts.

---

## 3. Key capabilities at a glance

| Capability | Where |
|---|---|
| 2,200-record synthetic threat dataset (+60 synthetic CVEs) | `data/` |
| Syntactic IOC validation — 7 indicator types, never connects | `ioc_search.html` |
| Explainable 6-factor **risk** scoring (0–100 + bands) | every threat record |
| Evidence-based **confidence** scoring (distinct from risk) | every threat record |
| Threat **correlation** clusters (campaign / shared indicators / window) | threat details |
| Alert engine with **anti-alert-fatigue** merging | `alerts.html` |
| SOC Tier-1 workflow: triage → investigate → notes → status (audited) | `threat-details.html` |
| MITRE ATT&CK mapping — only with sufficient behavioural context | `mitre_attack.html` |
| Vulnerability priority: CVSS **+** asset/exposure/exploitation context | `vulnerabilities.html` |
| Dashboard: 7 KPI cards + 10 charts + filters + sorts + pagination | `threat-dashboard.html` |
| 15 awareness modules (5 required sections each) | `awareness.html` |
| 36-question quiz, 10 categories, 4 score bands, recommendations | `quiz.html` |
| Executive summary in plain language | `executive_summary.html` |
| REST API with authentication, RBAC, rate limiting, validation | `/docs` |
| **72 automated tests** (35 required scenarios + security suite) | `tests/` |
| **37-item evidence package** from real application output | `screenshots/` |

---

## 4. Demo API keys (role-based access control)

Keys are demo values defined in `.env` (copy from `.env.example`). Change
them for any shared deployment.

| Role | Key (demo) | Can do |
|---|---|---|
| Viewer | `demo-viewer-key` | read endpoints, read notes |
| Analyst | `demo-analyst-key` | + create/updated threats, notes, alert triage |
| Admin | `demo-admin-key` | + audit log access |

In the UI, click the key badge (top right) → **Sign in** and paste a key.

---

## 5. Quick start (Windows — 4 steps)

```
1. scripts\setup_windows.bat      ← venv + dependencies + .env + data (steps 1–4)
2. scripts\start_backend.bat      ← init DB + start API server (step 5)
3. scripts\start_frontend.bat     ← open the dashboard in your browser
4. scripts\run_tests.bat          ← run all 72 automated tests
```

That's the whole setup. No cloud account, no external API key, no internet
required after install (Chart.js is vendored locally).

## 6. Quick start (macOS / Linux)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python data/generate_threat_data.py        # synthetic datasets
python -m scripts.init_database            # SQLite from CSVs
cd backend && python -m uvicorn app:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000/
```

---

## 7. Project structure

```
Cybersecurity-Awareness-Threat-Intelligence-Dashboard/
├── backend/            FastAPI app: routes, services, models, SQLite DB
│   ├── routes/         threats, indicators, dashboard, alerts, vulnerabilities,
│   │                   awareness, quiz, attack, executive, admin
│   ├── services/       ioc_validator, risk_engine, correlation_engine,
│   │                   alert_engine, enrichment_engine, threat_service,
│   │                   vulnerability_service, attack_mapper, security, …
│   └── app.py          CORS, rate-limit middleware, routers, static mount
├── frontend/           static HTML/CSS/JS (11 pages) + vendored Chart.js
├── awareness/          15 modules JSON + 36 quiz questions JSON
├── data/               deterministic dataset generator + CSVs + meta
├── tests/              72 automated tests (T-001…T-035, S-01…S-13b)
├── scripts/            Windows .bat automation + Python utilities
├── docs/               13 documentation files
├── reports/            test report + project report
└── screenshots/        37-item evidence package + README
```

## 8. Technology stack (and why)

| Layer | Choice | Why |
|---|---|---|
| Backend | **FastAPI** | automatic OpenAPI docs, Pydantic validation, async, Windows-easy `pip install` |
| Database | **SQLite** | zero-config single file, FK support, perfect for a local demo |
| Data | **pandas** | dataset generation + analysis |
| Frontend | **static HTML/CSS/JS + Chart.js (vendored)** | no build step, works offline, beginner-friendly |
| Tests | **pytest** + httpx | fast, real in-process API testing |
| Evidence | **Playwright** (dev-only) | real browser screenshots from the real app |

---

## 9. The synthetic dataset

`data/generate_threat_data.py` deterministically generates (seed `20260930`):

* **2,200 threat records** — `threat_id … cve_id_optional` plus
  `campaign_id` and `observation_count`; statuses NEW / UNDER_REVIEW /
  MONITORING / CLOSED / FALSE_POSITIVE
* **60 synthetic vulnerabilities** — fictional CVE-format IDs
  (CVE-2024/2025/2026-9xxxxxx), CVSS scores, patch/exploitation fields
* 10 threat categories, 6 indicator types, 5 severities, 97 campaigns,
  ~1,700 unique indicators, dates 2025-04 → 2026-09

**Safety of every indicator value:**

| Type | Safe range used |
|---|---|
| IPv4 | RFC 5737 — 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 |
| IPv6 | RFC 3849 — 2001:db8::/32 |
| Domains | example.com/.org/.net, *.invalid (e.g. `login-check.invalid`) |
| URLs | fictional hosts on those domains only |
| Hashes | synthetic hex strings (not real malware hashes) |
| CVEs | fictional CVE-format IDs, never real CVEs |

---

## 10. Threat-intelligence vocabulary (as implemented)

The project keeps five concepts strictly distinct:

```
OBSERVATION  a single sighting of an artifact
INDICATOR    a validated, normalized artifact (IP/domain/URL/hash/CVE/email-sender)
ALERT        an analyst-facing notification generated from rules
THREAT       an assessed record combining indicator + context + scores
INCIDENT     a confirmed compromise event (this project STOPS at investigation)
```

And two honesty rules repeated across the UI:

* **An IOC match is NOT a confirmed compromise** — it is evidence to investigate.
* **Correlation is NOT attribution** — a cluster suggests relationship, not who did it.

## 11. IOC validation & search

`backend/services/ioc_validator.py` — `validate_indicator(value)` performs
**syntactic-only** validation (8 supported types: ipv4, ipv6, domain, url,
md5, sha1, sha256, cve) and returns `valid`, `indicator_type`,
`normalized_value`, `validation_notes`. It uses `urllib.parse` for string
parsing only — the module is AST-scanned by tests to prove it contains **no
network-capable imports**.

Search (`ioc_search.html`, `GET /api/indicators/search?q=`) is a **local
database lookup** — the app never auto-connects to an indicator. Enrichment
(`enrich_indicator()`) adds first/last seen, risk & confidence, related
observations, ATT&CK mapping and analyst notes — all from the local DB.

## 12. Risk scoring (explainable, deterministic)

`calculate_threat_risk()` — six weighted factors, bands
0–20 INFORMATIONAL · 21–40 LOW · 41–60 MEDIUM · 61–80 HIGH · 81–100 CRITICAL:

| Factor | Weight |
|---|---|
| Severity | 30% |
| Confidence | 25% |
| Recency | 15% |
| Observation frequency | 10% |
| Source reliability | 10% |
| Context / correlation | 10% |

Every score returns its full factor breakdown. Demo recipe
(HIGH/85/15 days/3 obs/B/cluster+related) → **78 = HIGH**, factor sum exact.

## 13. Confidence scoring & source reliability

`calculate_confidence()` measures **evidence quality** (not danger):
base by source grade (A=85, B=70, C=55, D=30) + corroboration (+5/source,
max +15) + repeated observations (+5) − staleness (−10/−20). The six
synthetic sources carry A–D grades (Internal SOC Feed = A … Unknown = D).
Risk and confidence are deliberately separate models: a high-risk/low-
confidence item is treated as *unverified but worth watching*, never as fact.

## 14. Threat correlation

`correlate_threats()` groups records into **RELATED THREAT CLUSTERS** by
campaign_id, shared indicator values, observation window and category.
Weak links (same category/time window, no direct connection) are flagged
`analyst_review_required`. The demo campaign `SYN-CAMP-2026-001` links 9
records including the shared infrastructure IP `198.51.100.25`.

## 15. Alerts & anti-alert-fatigue

`generate_threat_alert()` fires on five rules (risk ≥ 75; risk ≥ 60 with
confidence ≥ 80; high-priority vulnerability; repeated observations ≥ 10;
correlated indicators), with statuses NEW / INVESTIGATING / MONITORING /
RESOLVED / FALSE_POSITIVE. `correlate_alerts()` then merges duplicate
signals: 100 observations of one indicator produce **one** alert with
`observation_count=100` — not 100 alerts.

## 16. SOC Tier-1 workflow

`soc_workflow.html` documents the 12-step pipeline (see architecture doc),
and the app implements it: alert queue → prioritize (severity, risk,
confidence) → open investigation view → validate indicator → review
enrichment/ATT&CK → add notes → update status (every change audited and
added to the threat timeline). The incident-response lifecycle
(Preparation → Lessons Learned) and a user incident checklist are included.

## 17. MITRE ATT&CK mapping

`attack_mapper.py` maps a record to a tactic/technique **only when the
behavioural context justifies it** (e.g. a phishing lure domain →
Initial Access / T1566.002 Spearphishing Link). 1,282 of 2,200 records
(~58%) are mapped; the rest are explicitly `UNMAPPED` rather than guessed.
Only well-known public technique IDs are used — **no invented IDs**. The
ATT&CK page shows top tactics, technique frequency, and drill-downs
(`?technique=T1566.002`).

## 18. Vulnerability prioritization (beyond CVSS)

`calculate_vulnerability_priority()` = **CVSS 35% + asset criticality 20% +
exposure 20% + exploitation evidence 15% + business context 10%**.
Teaching pair baked into the dataset:

| CVE | CVSS | Context | Priority |
|---|---|---|---|
| CVE-2026-900001 | 9.8 CRITICAL | isolated lab asset, no exploit evidence | **52/100** |
| CVE-2026-900002 | 8.1 HIGH | internet-facing VPN, mission-critical, actively exploited | **93/100** |

Fix the 8.1 first — that's risk-based vulnerability management.

## 19. Dashboard

`threat-dashboard.html`: **7 KPI cards** (Total threats, Critical, High,
Active indicators, Open investigations, Avg confidence, Vulnerabilities
tracked) and **10 charts** (threats over time, by severity, category,
indicator type, ATT&CK tactics, risk bands, confidence bands, vulnerability
severity, top categories, status). The recent-threats table (10 columns)
filters by severity, category, indicator type, risk, confidence, status and
date, and sorts by newest / highest risk / highest confidence / most
observed. Row click → full investigation view with ~20 field groups,
related indicators, alerts, ATT&CK, CVE, notes and recommended actions.

## 20. Awareness Center — 15 modules

Phishing · Password Security · MFA · Social Engineering · Safe Browsing ·
Secure Wi-Fi · Software Updates · Ransomware · USB/Removable Media ·
Data Privacy · Mobile Security · Remote Work · Cloud Account Security ·
Incident Reporting · AI-Enabled Scam Awareness.

Each module has exactly the five required sections: **What is it / Why it
matters / Warning signs / Safe practices / What to do if it happens**.
Deep-linkable (`awareness.html?module=phishing-awareness`).

## 21. Quiz & learning recommendations

36 questions, 10 categories, graded **server-side only** (answers are never
sent to the browser). Bands: 0–40 Needs Improvement · 41–60 Basic ·
61–80 Good · 81–100 Strong Awareness. Results include per-category scores,
weakest areas and `generate_learning_recommendations()` — e.g. a Phishing
score of 40% recommends the Phishing module, 55% suggests review, 90%
requires nothing. The score is **educational only**. No PII is collected —
the optional label is a free-text name, and the schema stores no email,
real name or IP.

## 22. Executive summary

`executive_summary.html` translates the data for non-technical leadership:
current threat landscape in plain language, critical/high counts, top
categories, top vulnerability categories, awareness-score trend, awareness
weaknesses, and five prioritized defensive recommendations (P1–P5).

---

## 23. REST API (summary)

Interactive docs: **http://127.0.0.1:8000/docs** (Swagger). Full reference:
`docs/api_documentation.md`.

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /api/threats` | – | list + filters/sort/pagination |
| `POST /api/threats` | analyst | create (validated; 24h-duplicate merge) |
| `PUT /api/threats/{id}` | analyst | update |
| `GET /api/threats/{id}` | – | full detail (notes masked unless analyst) |
| `GET /api/indicators/search?q=` | – | validate + local-DB lookup |
| `GET /api/dashboard/stats` / `trends` | – | cards, charts, trends |
| `GET /api/alerts` | – | alert queue + filters |
| `PUT /api/alerts/{id}/status` | analyst | audited status change |
| `POST /api/threats/{id}/notes` | analyst | add investigation note |
| `GET /api/vulnerabilities` | – | prioritized CVE list |
| `GET /api/awareness/modules` | – | 15 modules |
| `GET /api/quiz` · `POST /api/quiz/submit` | – | questions / server-side grading |
| `GET /api/attack/…` · `GET /api/executive/summary` | – | ATT&CK + executive data |
| `GET /api/admin/audit-log` · `GET /api/admin/whoami` | admin / any key | audit trail / current role |

Errors are honest status codes: **401** unauthenticated (enforced *before*
body validation), **403** insufficient role, **422** invalid input with
machine-readable detail, **429** rate-limited with `Retry-After`.

## 24. Database design

SQLite, 11 tables — the 9 required (THREATS, INDICATORS, SOURCES,
ATTACK_MAPPINGS, VULNERABILITIES, ALERTS, ANALYST_NOTES, AWARENESS_MODULES,
QUIZ_RESULTS) plus TIMELINE_EVENTS and AUDIT_LOG — with primary/foreign keys
and 21 named indexes. Referential integrity enforced on every connection
(`PRAGMA foreign_keys=ON`). Schema-integrity is asserted by test T-035b.
See `docs/database_design.md` (includes a PostgreSQL migration note).

## 25. Security & privacy controls (implemented, not just documented)

* API-key **authentication** + **RBAC** (viewer/analyst/admin)
* **Rate limiting** (default 240 req/60s per key) → 429 + `Retry-After`
* **Input validation** everywhere (Pydantic enums/lengths; 401 before 422)
* **Sanitization** of all stored/rendered text + frontend `escapeHtml`
* **Protected analyst notes** (masked for unauthenticated responses)
* **Audit log** of every state change (actor **role**, never the raw key)
* **Secrets via environment** (`.env` in `.gitignore`; `SECRET_KEY` has no
  hardcoded fallback)
* **Data minimization** — quiz stores no PII; anonymous labels only
* **No outbound network capability** in any analysis service (AST-verified)
* HTTPS-terminated deployment documented for shared use

All verified by the automated security suite — `docs/security_privacy.md`
lists all controls and *why threat-intelligence data itself needs access
control* (it reveals what you have detected and what remains unpatched).

## 26. Testing — 72 automated tests, all passing

```
scripts\run_tests.bat        (Windows)
python -m pytest tests -v    (any OS)     →   72 passed
```

* **T-001 … T-035** — the 35 required functional scenarios (validation,
  risk, confidence, enrichment, correlation, duplicates, alerts, ATT&CK,
  vulnerabilities, dashboard, filters, sorting, awareness, quiz,
  recommendations, empty dataset, validation, persistence) plus companion
  edge-case tests (T-012b … T-035b)
* **S-01 … S-13b** — security & privacy verification: sockets-blocked
  proofs that URLs/IPs are never contacted, AST import scans, XSS payload
  tests, auth-before-validation, RBAC matrix, note protection, rate limit,
  environment secrets, audit trail, PII minimization

`reports/test_report.md` maps every Test ID → scenario → input → expected →
**actual result from the real run** → pass/fail (regenerated from JUnit XML
via `python scripts/make_test_report.py` — nothing fabricated).

## 27. Evidence package — 37 items

`screenshots/` holds the required **exactly-37-item** evidence checklist
(`01_project_structure.png` … `37_readme_preview.png`), documented in
`screenshots/README.md`. Items 01–34 are generated from the **real running
application** (`scripts\generate_evidence.bat`). Items 35–37 (GitHub
commits, GitHub repository, README preview) are **manual-only and never
fabricated** — capture instructions are in `docs/github_setup.md`.

## 28. Demo scenario — THR-2026-001

Open `threat-details.html?id=THR-2026-001` (or search `login-check.invalid`):

* **Synthetic Credential Phishing Campaign** — DOMAIN `login-check.invalid`
* Severity HIGH · **risk 78** · **confidence 85** · status MONITORING
* Cluster `SYN-CAMP-2026-001` (9 members) with shared infrastructure IP
  `198.51.100.25`
* Pinned analyst note: *"Indicator appears in multiple synthetic phishing
  observations."*
* Five recommended defensive actions (user training, mail filtering,
  DNS monitoring, MFA enforcement, reporting guidance)
* **Never visit the domain** — the app certainly never does.

## 29. Limitations & false-positive discipline

Synthetic data demonstrates the workflow, not live intelligence. Indicators
go stale; infrastructure gets reassigned; feeds disagree; correlation is
not attribution; an IOC match is not a compromise. The system therefore
never auto-closes the loop: humans investigate, statuses record outcomes,
and FALSE_POSITIVE is a first-class outcome. Full discussion:
`docs/false_positives_limitations.md`.

## 30. Documentation index

| File | Contents |
|---|---|
| `docs/architecture.md` | system diagram, 11-step pipeline, stack rationale |
| `docs/api_documentation.md` | every endpoint, parameters, errors, RBAC |
| `docs/database_design.md` | ER model, tables, indexes, PostgreSQL note |
| `docs/security_privacy.md` | all verified controls + TI access-control rationale |
| `docs/threat_intelligence_concepts.md` | glossary (simple + technical) |
| `docs/threat_categories.md` | the 10 categories: indicators/impact/controls/awareness |
| `docs/soc_workflow.md` | Tier-1 steps, alert fatigue, IR lifecycle, user checklist |
| `docs/false_positives_limitations.md` | the 5-concept honesty discipline |
| `docs/windows_setup.md` | 15-step Windows guide + troubleshooting |
| `docs/github_setup.md` | commit sequence, topics, manual evidence 35–37 |
| `docs/future_improvements.md` | defensive-only roadmap |
| `docs/interview_preparation.md` | 10 questions & strong answers |
| `docs/resume_linkedin_material.md` | resume bullets, LinkedIn text, skills, repo description |
| `reports/project_report.md` (+ `.docx`) | full 31-section project report |
| `reports/test_report.md` | Test-ID table with real results |
| `reports/validation_summary.md` | fresh-ZIP from-scratch verification (PASS) |

## 31. Windows scripts reference

| Script | Purpose |
|---|---|
| `scripts\setup_windows.bat` | venv + dependencies + `.env` + dataset (steps 1–4) |
| `scripts\generate_data.bat` | regenerate synthetic datasets |
| `scripts\start_backend.bat` | init DB (if needed) + start API on :8000 |
| `scripts\start_frontend.bat` | open the dashboard in the browser |
| `scripts\run_tests.bat` | run all 72 tests (+ JUnit XML) |
| `scripts\generate_evidence.bat` | regenerate evidence items 01–34 |

Python utilities: `scripts/init_database.py` (idempotent DB build),
`scripts/make_test_report.py` (JUnit → markdown report),
`scripts/generate_evidence.py` (evidence generator).

## 32. Future improvements (defensive only)

Authorized feed integration, STIX/TAXII, IOC expiration, SIEM/SOAR
integration, CISA-KEV awareness, ATT&CK Navigator layers, Docker, CI —
always with the same safety rules. Full list: `docs/future_improvements.md`.

## 33. Publishing to GitHub

Repo name: **`Cybersecurity-Awareness-Threat-Intelligence-Dashboard`**.
`docs/github_setup.md` has the exact commit sequence, topics, and the
manual steps for evidence items 35–37. *(This README makes no claim that
the repository has been pushed — check the GitHub URL.)*

## 34. Credits & licenses

* **Chart.js 4.4.3** — MIT license, vendored at
  `frontend/js/vendor/chart.umd.js` (works fully offline)
* Safe documentation ranges: **RFC 5737**, **RFC 3849**, reserved domains
  per RFC 2606, and fictional CVE-format IDs
* MITRE ATT&CK® is a registered trademark of The MITRE Corporation — this
  educational project references only public, well-known technique IDs

---

### Final reminder

> **This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.**

**SYNTHETIC / DEMO ONLY** — every indicator, hash, domain, IP and CVE in this
repository is fake. If any value accidentally resembles real infrastructure,
do not interact with it — open an issue and it will be replaced.
