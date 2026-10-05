# REST API Documentation

Base URL (local): `http://127.0.0.1:8000`
Interactive docs: `http://127.0.0.1:8000/docs` (Swagger UI, auto-generated)

**Authentication:** protected endpoints require the header
`X-API-Key: <key>`. Demo keys (roles: viewer / analyst / admin) are listed
in `.env.example`. 401 = missing/unknown key; 403 = insufficient role.

**Common error handling:** all endpoints return proper status codes —
`200` OK, `201` Created, `400` invalid query parameter, `401` authentication
required, `403` forbidden (RBAC), `404` not found, `422` validation error
(with field details), `429` rate limited (with `Retry-After`), `500`
server error. Responses are JSON. Input is validated (pydantic schemas) and
free text is sanitized server-side.

---

## Threats

### GET /api/threats — list/filter/sort/paginate (public)
**Request** query parameters: `severity`, `category`, `indicator_type`,
`status`, `min_risk`, `max_risk`, `min_confidence`, `date_from` (YYYY-MM-DD),
`date_to`, `q` (text search), `sort` (`newest|oldest|risk|confidence|observed`),
`page`, `page_size` (≤200).
**Response:** `{total, page, page_size, pages, items: [threat…], data_notice}`
**Example:** `GET /api/threats?severity=CRITICAL&sort=risk&page_size=10`

### GET /api/threats/{threat_id} — full detail (public, notes masked)
**Response:** all threat fields + `risk_breakdown` (explainable factors),
`analyst_notes` (masked unless authenticated — `notes_access` field),
`related_indicators`, `related_threats`, `weak_links`, `related_alerts`,
`attack_mapping` (or explicit "insufficient context" object), `cve_association`,
`timeline`, `recommended_defensive_actions`, `correlation_note`.
**Errors:** 404 unknown ID.

### POST /api/threats — create (analyst role)
**Request:** `{threat_name, threat_category, indicator_type, indicator_value,
severity, confidence_score, description?, source_name?}`
**Validation:** category/severity enums, confidence 0-100, indicator must
pass IOC validation, text sanitized (max lengths enforced).
**Duplicate handling:** the same indicator+category observed within 24h is
merged into the existing record (observation_count + 1, timeline event) —
`duplicate_observation: true`.
**Response:** `201 {created, duplicate_observation, threat}` · `422` on
invalid payload · `401` without key.

### PUT /api/threats/{threat_id} — update (analyst role)
**Request:** any of `{status, severity, description, threat_name,
country_or_region}`. Status changes append a timeline event. Audited.
**Response:** `200` updated threat · `404` · `422` · `401/403`.

### POST /api/threats/{threat_id}/notes — add analyst note (analyst role)
**Request:** `{note (3-2000 chars), anonymous_author?}`
**Response:** `201 {threat_id, notes: [...]}` · sanitization applied · audited.

---

## Indicators (IOC)

### GET /api/indicators/validate?q=... (public)
Syntactic validation only — returns
`{valid, indicator_type, normalized_value, validation_notes}`. Makes clear
that valid ≠ malicious and that no network connection is made.

### GET /api/indicators/search?q=... (public)
**DATABASE LOOKUP ONLY** — the application never contacts the indicator.
**Response:** `{indicator_type, coarse_type, known_in_demo_dataset, risk,
risk_range, severity, confidence, confidence_range, associated_categories,
first_seen, last_seen, status, observation_count, distinct_sources,
related_threats, related_alerts, related_indicators, analyst_notes,
mitre_mapping, safety_notice}`.
**Errors:** `400` when the input fails validation (validation payload
included), `422` for empty/oversized query.

---

## Dashboard

### GET /api/dashboard/stats (public)
Top cards (total records, critical, high, active indicators, open
investigations, average confidence, vulnerabilities tracked) + chart data:
threats by severity/category, IOC type distribution, status distribution,
top ATT&CK tactics, vulnerabilities by severity, top categories.

### GET /api/dashboard/trends (public)
Time series: threats over time (monthly), risk distribution (5 bands),
confidence distribution (5 bands), alerts over time.

---

## Alerts

### GET /api/alerts (public)
Query: `status`, `severity`, `alert_type`, `page`, `page_size`. Returns
status counts and the alert-fatigue explanation. Ordered by severity then
recency.

### GET /api/alerts/{alert_id} (public)
Investigation detail: alert fields + linked threat + correlation basis +
attribution note.

### PUT /api/alerts/{alert_id}/status (analyst role)
**Request:** `{status: NEW|INVESTIGATING|MONITORING|RESOLVED|FALSE_POSITIVE}`
**Response:** `200` updated alert · `404` · `422` invalid status · audited;
timeline event added to the linked threat.

### POST /api/alerts/correlate-demo (analyst role)
Educational demonstration of alert correlation: `?observations=100&minutes=5`
→ one correlated alert with observation count 100.

---

## Vulnerabilities

### GET /api/vulnerabilities (public)
Query: `severity`, `product_category`, `patch_available`,
`sort` (`priority|cvss|newest`). Returns items + priority band counts +
the contextual-prioritization note. All records are synthetic.

### GET /api/vulnerabilities/{cve_id} (public)
Detail + full priority breakdown (5 weighted factors) + recommended
defensive actions. `404` for unknown IDs.

---

## Awareness

### GET /api/awareness/modules (public)
The 15 learning modules (id, title, category, summary, reading time).

### GET /api/awareness/modules/{module_id} (public)
Full module content: what_is_it, why_it_matters, warning_signs,
safe_practices, if_it_happens.

---

## Quiz

### GET /api/quiz (public)
36 questions **without** correct answers or explanations (answers never leak
to the client), scoring bands, educational note.

### POST /api/quiz/submit (public)
**Request:** `{answers: [{question_id, selected_option}], anonymous_user_id?}`
**Response:** `{overall_score, band, correct_count, question_count,
category_scores, category_breakdown, weakest_areas, recommendations,
educational_note}` — scored **server-side** and persisted (anonymous).
**Errors:** `422` for empty/invalid submissions or oversized labels.

---

## MITRE ATT&CK

### GET /api/attack/summary (public)
Top tactics, technique frequency, mapped vs unmapped counts, mapping policy.
### GET /api/attack/tactics/{tactic} (public)
Threat records grouped under a tactic. `404` when none mapped.
### GET /api/attack/techniques/{technique_id} (public)
Records associated with a technique (click-through from the charts).

---

## Executive

### GET /api/executive/summary (public)
Plain-language threat landscape summary, counts, top threat/vulnerability
categories, awareness trend + weaknesses, recommended defensive priorities.

---

## Admin / meta

### GET /api/admin/health (public)
Service health, record counts, offline notice.
### GET /api/admin/whoami (any valid key)
Returns the role for the presented key (used by the frontend sign-in).
### GET /api/admin/audit-log (admin role)
The audit trail (timestamp, actor role, action, target, details, IP).
### GET /api (public)
Endpoint index.

---

## Rate limiting

All `/api/*` routes share a sliding-window limiter (default 240 requests per
60s per client, configurable via `RATE_LIMIT_REQUESTS`). Exceeding it returns
`429` with a `Retry-After` header.
