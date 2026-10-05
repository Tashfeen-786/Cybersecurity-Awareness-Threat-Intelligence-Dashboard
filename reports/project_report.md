# Project Report — Cybersecurity Awareness & Threat Intelligence Dashboard

**A defensive cybersecurity education platform**
Python · FastAPI · SQLite · pandas · Chart.js · pytest — fully offline, 100% synthetic data

> **This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.**

---

## 1. Abstract

This project delivers a complete, defensively-oriented cybersecurity platform
that combines a threat-intelligence analysis dashboard with a security
awareness training center. The system ingests a deterministic synthetic
dataset of 2,200 threat records and 60 vulnerabilities built exclusively
from safe documentation-range indicators (RFC 5737 IPv4, RFC 3849 IPv6,
reserved domains, synthetic hashes, fictional CVE-format identifiers).
It validates indicators of compromise syntactically, enriches them from a
local database (never contacting any indicator), scores each record with
two deliberately separate models — a six-factor explainable **risk** score
and an evidence-based **confidence** score — correlates related
observations into threat clusters, generates analyst-facing alerts with
anti-fatigue merging, and maps threats to MITRE ATT&CK techniques only
where behavioural context justifies the mapping. A SOC-style workflow
(authenticated notes, audited status changes, investigation timelines) is
exposed through a static frontend with seven KPI cards, ten charts and a
filterable threat table, alongside fifteen awareness modules, a
36-question server-graded quiz with personalized learning
recommendations, and a plain-language executive summary. The system
implements authentication, role-based access control, rate limiting, input
validation, output sanitization and a full audit trail, and is verified by
72 automated tests covering 35 required functional scenarios and a
security & privacy suite. The result is a realistic, safe, offline,
placement-ready demonstration of how modern security operations blend
technical threat intelligence with human awareness.

## 2. Introduction

Organizations defend against two failure modes at once: technical blind
spots (unanalyzed indicators, unprioritized vulnerabilities, alert fatigue)
and human error (phishing, weak authentication, poor reporting habits).
Most educational projects address only one side. This project builds both
into a single local application: a threat-intelligence dashboard modeled on
a Tier-1 Security Operations Center (SOC) workflow, and an awareness center
that measures and improves the human layer. Everything runs offline on a
laptop with double-click Windows scripts, uses only synthetic data, and
implements production-grade security controls (authentication, RBAC, rate
limiting, validation, sanitization, auditing) so the tool itself models the
defensive practices it teaches.

## 3. Problem Statement

1. Raw threat data does not drive action: feeds, spreadsheets and PDFs
   present indicators without context, scoring, or next steps.
2. Alert fatigue: repeated observations of the same indicator bury analysts
   in duplicates instead of one actionable cluster.
3. CVSS-only patching misallocates effort: a 9.8 on an isolated lab asset
   outranks an actively exploited 8.1 on an internet-facing VPN.
4. Uncertainty is hidden: systems that display a single "score" conflate
   how dangerous something might be with how well-evidenced it is.
5. The human layer is unmeasured: awareness training rarely connects to
   data-driven weaknesses or executive reporting.

The project addresses each: contextual scoring with explicit factor
breakdowns, alert correlation, risk-based vulnerability prioritization,
separate risk vs confidence models, and an awareness program with scored
quizzes and executive summaries.

## 4. Objectives

- Build a complete defensive threat-intelligence pipeline: ingest →
  validate → enrich → score → correlate → alert → investigate.
- Keep every indicator synthetic and safe; never contact, resolve or
  execute anything.
- Implement explainable, deterministic risk scoring and a distinct
  confidence scoring model with source reliability grades.
- Provide MITRE ATT&CK mapping with evidence discipline (no invented IDs).
- Prioritize vulnerabilities by business context, not CVSS alone.
- Implement a realistic SOC Tier-1 workflow with authentication, RBAC and
  audit logging.
- Deliver a Security Awareness Center: 15 modules, 36-question quiz,
  personalized recommendations.
- Provide an executive summary for non-technical stakeholders.
- Verify everything with automated tests and a 37-item evidence package
  generated from the real application.

## 5. Cybersecurity Awareness

Security awareness is the practice of equipping people to recognize and
respond to security threats. Technical controls fail when users click
convincing lures, reuse passwords, or stay silent about mistakes — the
human layer is the control that every attacker must pass. This project
treats awareness as measurable infrastructure: fifteen modules cover
phishing, passwords, MFA, social engineering, safe browsing, Wi-Fi,
updates, ransomware, removable media, privacy, mobile, remote work, cloud
accounts, incident reporting and AI-enabled scams; a scored quiz measures
comprehension by category; and the recommendation engine converts
weaknesses into specific next lessons. Awareness content deliberately
mirrors the technical data (the phishing module explains the same lure
patterns the threat dataset demonstrates).

## 6. Cyber Threat Intelligence

Cyber Threat Intelligence (CTI) is validated, contextualized and
analyzed information about threats that supports defensive decisions.
Raw data (an IP seen once) becomes intelligence through a pipeline:
validation (is this a well-formed indicator?), enrichment (what else do we
know?), scoring (how concerning, how well-evidenced?), correlation (what
is related?), and action (alert, hunt, patch, train). This project
implements that full pipeline locally on synthetic data, with every stage
inspectable in the UI and every score explainable.

## 7. Threat Intelligence Types

- **Strategic** — broad trends informing leadership (this project's
  executive summary: top categories, trends, prioritized recommendations).
- **Tactical** — how adversaries operate: TTPs (this project's MITRE
  ATT&CK module: tactics, techniques, sub-techniques).
- **Operational** — specific campaigns and indicators (this project's
  correlation clusters and campaign IDs, e.g. SYN-CAMP-2026-001).
- **Technical** — atomic indicators: IPs, domains, URLs, hashes, CVEs
  (this project's INDICATORS table and IOC search).

The dashboard demonstrates all four levels against one dataset.

## 8. IOC and IOA Concepts

An **IOC (Indicator of Compromise)** is a technical artifact associated
with suspicious activity — an IP, domain, URL, file hash or CVE-format ID.
IOCs are *atomic and retrospective*: they tell you what already happened.
An **IOA (Indicator of Attack)** is a behavioural precursor — the chain of
actions an adversary must perform (also modeled by ATT&CK techniques).
This project's dataset is IOC-centric (six indicator types) while its
ATT&CK mapping adds the behavioural layer, and the UI repeats the honesty
rule everywhere: **an IOC match is evidence to investigate, not proof of
compromise** — indicators age, infrastructure is reassigned, and feeds
contain false positives.

## 9. Threat Intelligence Lifecycle

The project implements the classic six-phase lifecycle:

1. **Planning & direction** — define the 10 categories, 6 indicator types
   and scoring policy (this repository's design).
2. **Collection** — deterministic synthetic dataset generation (seed
   20260930) and API-based threat creation.
3. **Processing & normalization** — validation, normalization (e.g.
   `cve-2026-900001` → `CVE-2026-900001`), source grading, deduplication.
4. **Analysis & production** — enrichment, risk/confidence scoring,
   correlation, ATT&CK mapping, alerting.
5. **Dissemination** — REST API, dashboard, alert queue, awareness center,
   executive summary.
6. **Feedback** — analyst statuses (FALSE_POSITIVE is a first-class
   outcome), notes, timeline and audit trail feed back into the record.

## 10. Proposed System

A local, offline, three-tier application:

- **Data layer** — SQLite with 11 tables (THREATS, INDICATORS, SOURCES,
  ATTACK_MAPPINGS, VULNERABILITIES, ALERTS, ANALYST_NOTES,
  AWARENESS_MODULES, QUIZ_RESULTS, TIMELINE_EVENTS, AUDIT_LOG), foreign
  keys enforced, 21 named indexes.
- **Service layer** — pure-Python engines: IOC validator, risk engine,
  confidence engine, enrichment engine, correlation engine, alert engine,
  ATT&CK mapper, vulnerability prioritizer, awareness/quiz/executive
  services, and security (authentication, RBAC, rate limiting, auditing).
- **Presentation layer** — FastAPI REST API plus a static HTML/CSS/JS
  frontend (11 pages) with vendored Chart.js; one server serves both.

The system is defensive-only by construction: the analysis services are
AST-verified to contain no network-capable or process-execution imports.

## 11. Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │                BROWSER (static)             │
                    │  index · dashboard · details · ioc_search   │
                    │  alerts · vulnerabilities · mitre_attack    │
                    │  awareness · quiz · executive · soc_workflow│
                    └───────────────────┬─────────────────────────┘
                              fetch() + X-API-Key
                                        │
┌──────────────┐  HTTP   ┌──────────────▼──────────────┐  sqlite3 ┌───────────┐
│ data/        │ ──────► │ FastAPI backend (app.py)    │ ───────► │ SQLite DB │
│ generator +  │ import  │  middleware: CORS, rate     │          │ 11 tables │
│ CSV datasets │         │  limit, exception handlers  │          └───────────┘
└──────────────┘         │  routes/ → services/        │
                         │  (validator, risk, confidence,        │
                         │   enrichment, correlation, alerts,    │
                         │   ATT&CK, vulnerability, security)    │
                         │  static mount "/" serves frontend     │
                         └─────────────────────────────┘
```

Eleven-step data flow: generate → validate → normalize → store → enrich →
score (risk + confidence) → correlate → map (ATT&CK) → alert → investigate
(audited) → report (dashboard / executive).

## 12. Synthetic Dataset

`data/generate_threat_data.py` (deterministic, seed 20260930) produces:

- **2,200 threat records** with the full field set (`threat_id`,
  `timestamp`, `threat_name`, `threat_category`, `indicator_type`,
  `indicator_value`, `source_name`, `confidence_score`, `severity`,
  `risk_score`, `status`, `first_seen`/`last_seen`, region, description,
  optional MITRE tactic/technique, `cve_id_optional`, `campaign_id`,
  `observation_count`)
- **60 vulnerabilities** with fictional CVE-format IDs, CVSS, exposure,
  asset criticality, exploitation status, patch availability
- Distributions: 10 categories (Phishing largest, ~476), 6 indicator types
  (IP ADDRESS largest, ~774), 97 campaigns, ~1,732 unique indicators,
  risk bands 2/296/1,241/629/32 (INFO…CRITICAL), statuses NEW /
  UNDER_REVIEW / MONITORING / CLOSED / FALSE_POSITIVE
- A pinned demo campaign: THR-2026-001 "Synthetic Credential Phishing
  Campaign" (domain `login-check.invalid`, HIGH, risk 78, confidence 85,
  MONITORING) with the shared infrastructure IP `198.51.100.25`

Every value is safe by construction: RFC 5737 (192.0.2/24,
198.51.100/24, 203.0.113/24), RFC 3849 (2001:db8::/32), example.com/.org/
.net and *.invalid domains, synthetic hex hashes (64-char demo value
`a1b2…f90`), fictional CVEs (CVE-{2024|2025|2026}-9xxxxxx).

## 13. IOC Validation

`validate_indicator()` is **syntactic-only**: it checks well-formedness of
8 types (ipv4, ipv6, domain, url, md5, sha1, sha256, cve — plus email
sender-domain coarse typing) and returns `valid`, `indicator_type`,
`normalized_value`, `validation_notes`. Examples: `198.51.100.25` → valid
ipv4; `999.999.999.999` → invalid; `cve-2026-900001` → normalized to
`CVE-2026-900001`. Crucially, validation answers "is this well-formed?",
never "is this malicious?" — a different question requiring different
evidence. The module imports only `urllib.parse` (string parsing); an AST
scan in the test suite proves no network or execution modules are
imported anywhere in the analysis services.

## 14. Threat Enrichment

`enrich_indicator()` adds local context to a validated indicator:
indicator type, first/last seen (earliest record is primary),
associated threat categories, risk/confidence (shown as ranges across
records), source reliability, related indicators from the same
correlation cluster, related threats, justified ATT&CK mappings, and
analyst notes. All of it is a **local database lookup** — tests S-01 and
S-02 run enrichment with Python's socket layer monkeypatched to fail
loudly, proving the code path never attempts a connection.

## 15. Risk Scoring

`calculate_threat_risk()` — deterministic, explainable, 0–100:

| Factor | Weight | Model |
|---|---|---|
| Severity | 30% | INFO=20 … CRITICAL=100 |
| Confidence | 25% | evidence quality input (distinct model) |
| Recency | 15% | decays with age; stale loses weight |
| Observation frequency | 10% | grows with sightings |
| Source reliability | 10% | grade A=100 … D=40 |
| Context / correlation | 10% | cluster +40, related indicator +40, base 20 |

Bands: 0–20 INFORMATIONAL, 21–40 LOW, 41–60 MEDIUM, 61–80 HIGH,
81–100 CRITICAL. Every result carries the six-factor breakdown and an
interpretation note ("a high risk score does NOT automatically mean
confirmed compromise"). The demo recipe (HIGH, 85, 15 days, 3
observations, grade B, cluster+related) scores exactly **78 = HIGH** and
the factor sum reproduces it to the decimal.

## 16. Confidence Scoring

`calculate_confidence()` measures **evidence quality**, not danger:
base 85/70/55/30 for source grades A/B/C/D, +5 per corroborating
independent source (max +15), +5 for ≥3 observations, −10 stale (>180
days), −20 very stale (>365 days) or unknown. Examples: A+3 sources+5
observations = 100; D+1 = 30; B+2 sources, 400 days old = 50. The two
scores are deliberately separate: a risk-90/confidence-25 item is treated
as *potentially serious but unverified* — the system never lets weak
evidence masquerade as fact, and the UI renders both with a dedicated
explainer.

## 17. Source Reliability

Six synthetic sources carry Admiralty-style grades: Internal SOC Feed (A),
Security Vendor Research (B), Open Threat Exchange — Demo (B), CERT
Advisory Feed (A/B), Automated Sensor Network (C), Unknown (D). Grade
feeds both scoring models and is displayed on every record. The report
score of the source is kept conceptually distinct from confidence in an
individual item — the classic information-evaluation discipline.

## 18. Threat Correlation

`correlate_threats()` builds **RELATED THREAT CLUSTERS** on four bases:
shared campaign_id, shared indicator value, overlapping observation
window, and category. For the demo record it returns cluster
SYN-CAMP-2026-001 with 9 members, the correlation basis list
("Same campaign ID", "Same indicator value observed in multiple
records"), shared indicators, distinct sources, time span and total
observations. Records that merely share category + window without a
direct link are returned as **weak links flagged `analyst_review_required`**.
The API and UI attach the standing caveat: **correlation indicates
relationship/evidence — it does NOT prove attribution.**

## 19. MITRE ATT&CK

ATT&CK organizes adversary behaviour into tactics (objectives, e.g.
Initial Access) and techniques/sub-techniques (methods, e.g. T1566.002
Spearphishing Link). The `attack_mapper` maps a record **only when
behavioural context justifies it** — a phishing lure domain maps to
Initial Access/T1566.002, but a bare IP with no behavioural description
stays UNMAPPED. Result: 1,282 of 2,200 records (~58%) mapped; the
remainder explicitly unmapped rather than guessed. Only well-known public
technique IDs appear — **no invented IDs**. The ATT&CK page renders
concept cards, a top-tactics chart, technique-frequency analytics and
drill-downs (`mitre_attack.html?technique=T1566.002`).

## 20. Vulnerability Awareness

The vulnerability module teaches **risk-based prioritization**:
`calculate_vulnerability_priority()` = CVSS 35% + asset criticality 20% +
exposure 20% + exploitation evidence 15% + business context 10%, banded
85+ CRITICAL / 70–84 HIGH / 40–69 MEDIUM / <40 LOW. The dataset's teaching
pair makes the point: CVE-2026-900001 (CVSS 9.8, isolated lab asset, no
exploitation evidence) scores **52/100**, while CVE-2026-900002 (CVSS 8.1,
internet-facing, mission-critical VPN, actively exploited) scores
**93/100** — fix the lower CVSS first. The UI shows the five-factor
breakdown and weight bars, and the awareness modules connect
vulnerability hygiene (Software Updates, Secure Wi-Fi) to the technical
view.

## 21. Alert Management

`generate_threat_alert()` fires on five rules: risk ≥ 75 (HIGH_RISK);
risk ≥ 60 with confidence ≥ 80; high-priority vulnerability; ≥10 repeated
observations; correlated indicators. Alerts carry status NEW /
INVESTIGATING / MONITORING / RESOLVED / FALSE_POSITIVE and land in a SOC
queue with status cards, filters and pagination. `correlate_alerts()`
provides anti-fatigue merging: 100 observations of one indicator become a
**single** alert with `observation_count=100`, and when rules overlap the
highest-severity, highest-priority rule becomes the primary alert
(HIGH_RISK outranks all). The dataset yields 784 alerts across statuses
(NEW 146 / INVESTIGATING 116 / MONITORING 265 / RESOLVED 179 /
FALSE_POSITIVE 78) — realistic ratios including false positives.

## 22. SOC Workflow

The alert queue → investigation view implements the Tier-1 loop:
prioritize by severity/risk/confidence → open investigation → validate
the indicator → review enrichment, ATT&CK and cluster → add notes (analyst
role required) → update status (every change audited and appended to the
threat timeline). `soc_workflow.html` documents the 12-step pipeline,
Tier-1 duties, the IOC lifecycle, the six-phase incident-response
lifecycle (Preparation → Lessons Learned) and a plain-language user
incident checklist. Status changes and note additions are recorded in
AUDIT_LOG with the actor's **role** (never the raw key).

## 23. Awareness Center

Fifteen modules — Phishing, Password Security, MFA, Social Engineering,
Safe Browsing, Secure Wi-Fi, Software Updates, Ransomware, USB/Removable
Media, Data Privacy, Mobile Security, Remote Work, Cloud Account
Security, Incident Reporting, AI-Enabled Scam Awareness — each with
exactly the five required sections: What is it / Why it matters / Warning
signs / Safe practices / What to do if it happens. Modules are
deep-linkable (`awareness.html?module=phishing-awareness`) and stored in
`awareness/modules.json`, served via `GET /api/awareness/modules`.

## 24. Quiz System

36 questions across 10 categories (Phishing 6; Passwords, Social
Engineering, Incident Reporting 4 each; MFA, Safe Browsing, Ransomware,
Privacy, Wi-Fi, Mobile 3 each). Answers are graded **server-side only**
— `GET /api/quiz` never includes correct answers. Bands: 0–40 Needs
Improvement, 41–60 Basic, 61–80 Good, 81–100 Strong Awareness. Results
include the total score, band, per-category bars, weakest areas and
`generate_learning_recommendations()` (Phishing 40% → "complete the
Phishing module"; 55% → "review"; 90% → nothing required). The score is
**educational only**; data minimization applies (no email, no real name,
no IP stored — the optional label is free text, capped at 60 characters).

## 25. Executive Dashboard

`executive_summary.html` speaks to non-technical leadership: the threat
landscape in plain language, critical/high counts, top threat categories,
top vulnerability categories, the awareness-score trend (from 48 seeded
synthetic quiz attempts plus live submissions), awareness weaknesses, and
five prioritized defensive recommendations (P1 phishing defense and user
training first). A reading guide explains risk-vs-confidence in one
paragraph.

## 26. Testing

**72 automated tests, all passing** (`python -m pytest tests -v`, ~2 s):

- **T-001…T-035** — the 35 required functional scenarios: validation
  (T-001–011), creation/risk/confidence/reliability (T-012–015),
  enrichment/search/correlation/duplicates (T-016–019), alerts/notes/
  ATT&CK (T-020–024), vulnerabilities/dashboard/filters/sorting
  (T-025–029), awareness/quiz/recommendations (T-030–032), empty dataset,
  API validation, persistence + schema integrity (T-033–035)
- **Companion edge cases** (T-012b…T-035b) — invalid inputs, band
  boundaries, monotonicity, unknown indicators, over-merging guards
- **S-01…S-13b** — security & privacy suite (next section)

`reports/test_report.md` maps every Test ID → scenario → input →
expected → **actual result from the real run** → pass/fail, regenerated
from JUnit XML (`scripts/make_test_report.py`). Results are never
fabricated.

## 27. Security

Verified controls, each backed by an automated test:

| Control | Verification |
|---|---|
| URLs/IPs never visited; no file execution | S-01/S-02/S-03 — enrichment runs with sockets monkeypatched to fail; no connection attempted |
| No network/exec code in analysis services | S-03b/S-03c — AST import scans (urllib.parse allowed; socket/requests/httpx/subprocess banned) |
| Output sanitization & XSS protection | S-04/S-05 — `<script>`/`<img onerror>` payloads stored and rendered as inert text |
| API input validation | S-06 — 401 before validation; 422 with detail on bad enums/lengths/indicators |
| Authenticated analyst functions | S-07 — all write endpoints reject missing/unknown keys |
| Role-based access control | S-08 — viewer read-only (403 on writes), analyst triage, admin-only audit log |
| Protected analyst notes | S-09 — notes masked with `authentication_required` for unauthenticated readers |
| Rate limiting | S-10 — 8-request window: 8×200 then 429 + `Retry-After` |
| Secrets from environment | S-11 — subprocess-isolated env-var check; `SECRET_KEY` has no hardcoded fallback; `.env` git-ignored |
| Key material never exposed | S-11b — no key material in any response |
| Audited administrative changes | S-12 — AUDIT_LOG rows record actor role, action, target, details, IP |
| PII minimization | S-13 — quiz schema has no email/name/IP columns; oversized labels rejected (422) |

**Why threat-intelligence data itself needs access control (S-13b):** a TI
platform aggregates what an organization has detected and what remains
unpatched; leaked notes, alert queues or patch-gap data are a reconnaissance
gift to an attacker. Hence authentication, RBAC, masking, auditing and rate
limiting are requirements, not decorations. HTTPS-terminated reverse-proxy
deployment is documented for shared use.

## 28. Results

- **72/72 automated tests pass** (35 required scenarios + companions +
  security suite), ~1.9 s suite runtime.
- Dataset: 2,200 threats, 1,282 ATT&CK mappings (58%), 60 vulnerabilities,
  784 alerts, 8,844 timeline events, 15 modules, 36 quiz questions,
  48 seeded synthetic quiz attempts.
- Dashboard KPIs: 2,200 total / 177 critical / 398 high / 1,751 active
  indicators / 751 open investigations / 60.8 average confidence / 60
  vulnerabilities tracked.
- Demo record THR-2026-001 reproduces exactly: risk 78 (HIGH), confidence
  85, cluster SYN-CAMP-2026-001 (9 members, shared IP 198.51.100.25),
  ATT&CK T1566.002, pinned note, five recommended defensive actions.
- Vulnerability teaching pair: lab CVE 9.8→52 vs VPN CVE 8.1→93.
- 11/11 frontend pages verified error-free in a real browser (zero console
  errors), all 10 dashboard charts rendering, all interactive flows
  (search, sign-in, note, status change, quiz, drill-downs) exercised.
- **37-item evidence package**: 34 items generated from the real running
  application (API responses, DB queries, code, test output, browser
  sessions); 3 manual-only (GitHub commits/repository, README preview) —
  never fabricated.

## 29. Limitations

1. **Synthetic data** — demonstrates the workflow, not live intelligence;
   distributions are plausible, not real.
2. **Indicators age** — without live feeds, confidence decay is modeled
   but not refreshed by real sightings.
3. **Correlation ≠ attribution** — clustering suggests relationships;
   actor attribution requires evidence beyond this dataset.
4. **IOC match ≠ compromise** — a match is a lead; false positives are
   expected and must be closed as such.
5. **Demo credentials** — the API keys ship as documented demo values;
   shared deployments must replace them and terminate HTTPS.
6. **Single-node SQLite** — ideal for education; a production rollout
   needs PostgreSQL, pooling and centralized logging (documented in
   database_design.md).

## 30. Future Scope (defensive only)

Authorized live threat-feed integration; STIX/TAXII exchange; threat-feed
deduplication and provenance; IOC expiration and confidence decay; SIEM
forwarding and sighting feedback; SOAR playbooks with human approval
gates; CVE feed + CISA KEV awareness; EPSS-style exploitation
probability; automated enrichment from approved internal sources; graph
threat clustering; ATT&CK Navigator layer exports and detection-coverage
mapping; email-security and endpoint telemetry correlation; cloud
security intelligence; a threat-hunting workbench; scheduled executive
reports; role-based dashboards; Docker deployment, CI/CD and centralized
logging. All improvements remain strictly defensive — the safety rules
(no contact, no execution, no attack tooling) are permanent.

## 31. Conclusion

This project demonstrates that a realistic, industry-oriented
threat-intelligence and awareness platform can be built safely,
offline, and completely: synthetic data generation, syntactic IOC
validation, local enrichment, explainable risk and confidence scoring,
campaign correlation, disciplined ATT&CK mapping, contextual
vulnerability prioritization, anti-fatigue alerting, an audited SOC
workflow, a measured awareness program, an executive summary, and
production-style security controls — verified end-to-end by 72 automated
tests and a 37-item evidence package generated from the real application.
Every design choice encodes the discipline the field demands: risk is not
confidence, a match is not a compromise, correlation is not attribution,
and a defensive tool must itself be defended. The project is beginner
friendly to run (double-click scripts), rigorous to inspect (docs, tests,
evidence), and honest about its limits — placement-ready in substance,
not just in appearance.

---

*All data is SYNTHETIC / DEMO ONLY. This project is designed exclusively
for defensive cybersecurity education, threat-intelligence analysis, and
security awareness. It does not execute, deploy, or interact with
malicious payloads or unauthorized systems.*
