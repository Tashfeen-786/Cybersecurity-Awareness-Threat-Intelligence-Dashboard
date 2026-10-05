# Security & Privacy Design

This document explains — and shows how to verify — every security and privacy
control in the **Cybersecurity Awareness & Threat Intelligence Dashboard**.
Each control is backed by an automated test in `tests/test_security.py`
(run `scripts\run_tests.bat` to re-verify everything).

> **Defensive-security rule #1:** this application treats every indicator as
> **data only**. It never contacts, resolves, visits, downloads or executes
> anything derived from the threat-intelligence dataset.

---

## 1. Suspicious URLs are never automatically visited

* URL validation (`backend/services/ioc_validator.py`) parses the string with
  `urllib.parse.urlparse` — a **pure string parser** that performs **no
  network I/O**.
* IOC search and enrichment query the **local SQLite database only**.
* There is no `urllib.request`, `requests`, `httpx` or `socket` code anywhere
  in the services layer (verified by the AST-based test `test_S03b`).
* **Runtime proof:** `test_S01` monkey-patches `socket.socket` to raise an
  exception, then validates and enriches a URL. If the app ever tried to
  fetch it, the test would fail.

## 2. Suspicious IPs are never contacted

* IP validation uses `ipaddress.ip_address()` — offline parsing only.
* No ping, DNS lookup, port check or traceroute functionality exists.
* **Runtime proof:** `test_S02` blocks all sockets and enriches
  `198.51.100.25` (a documentation-range IP) successfully — no connection
  attempted.

## 3. Suspicious files are never executed

* File hashes are stored and compared as **strings**. There is no download or
  execution path anywhere in the codebase (AST-verified: no `subprocess`,
  no `os.system`, no `exec`/`eval`).
* Hashes are never submitted to online lookup services.
* **Proof:** `test_S03`, `test_S03b`, `test_S03c`.

## 4. Threat descriptions are sanitized

* All free-text input (descriptions, notes, names, quiz labels) passes
  through `sanitize_text()` (`backend/utils/helpers.py`), which:
  * strips control characters (log-forging defence),
  * HTML-escapes `<` and `>` so **no HTML tags can form** when rendered,
  * neutralizes `javascript:` URI text,
  * enforces a maximum length.
* **Proof:** `test_S04` submits `<script>` / `<img onerror=...>` payloads and
  asserts the stored text contains no raw tags.

## 5. XSS protection (defence-in-depth)

* **Backend:** sanitization at write time (above).
* **API layer:** JSON responses encode text; no HTML is ever generated
  server-side from user data.
* **Frontend:** every dynamic value is rendered through `escapeHtml()`
  (`frontend/js/common.js`); user data is never concatenated into raw HTML
  unescaped. See `test_S05`.

## 6. API input is validated

* Pydantic schemas (`backend/models/schemas.py`) enforce types, lengths,
  enums and ranges on every request body.
* Query parameters are validated (invalid `severity`/`sort`/`status` values
  return `400`).
* All SQL uses **parameterized queries** — string interpolation of user
  input into SQL never occurs.
* **Proof:** `test_S06`, `test_T034`.

## 7. Analyst functions are authenticated

All write endpoints (`POST /api/threats`, `PUT /api/threats/{id}`,
`POST /api/threats/{id}/notes`, `PUT /api/alerts/{id}/status`) require a
valid `X-API-Key` header. Missing/unknown keys receive **401**.
Demo keys are documented in `.env.example` and configured via environment
variables. **Proof:** `test_S07`.

## 8. RBAC is implemented

Three roles, checked by a FastAPI dependency (`require_permission`):

| Role    | Permissions |
|---------|-------------|
| viewer  | read everything, including protected analyst notes |
| analyst | viewer rights + create notes, triage statuses, create threats |
| admin   | analyst rights + audit-log access + administrative actions |

Insufficient role → **403 Forbidden**. **Proof:** `test_S08`.

## 9. Analyst notes are protected

Threat-detail responses **mask analyst notes** for unauthenticated requests
(`notes_access: "authentication_required"`). Notes contain investigation
findings — exactly the kind of content that must not leak. **Proof:**
`test_S09`, `test_T023`.

## 10. APIs are rate-limited

A sliding-window limiter (configurable via `RATE_LIMIT_REQUESTS` /
`RATE_LIMIT_WINDOW_SECONDS`) protects every `/api/*` route. Excess requests
receive **429** with a `Retry-After` header. **Proof:** `test_S10`.

## 11. API keys and secrets are protected

* Secrets come **only** from environment variables / `.env` (never
  hard-coded, never returned by any API, never written to logs).
* `.env` is in `.gitignore`; `.env.example` documents every variable.
* A missing `SECRET_KEY` does **not** fall back to an embedded default.
* **Proof:** `test_S11` (runs in an isolated interpreter), `test_S11b`.

## 12. Administrative changes are auditable

Every analyst/admin write action appends a row to the `AUDIT_LOG` table
(timestamp, actor **role**, action, target, details, client IP). The raw API
key is never stored — only the acting role. **Proof:** `test_S12`, endpoint
`GET /api/admin/audit-log` (admin only).

## 13. Unnecessary personal data is minimized

* The quiz collects **no personal data**: no name, email, IP or department —
  only an optional self-chosen anonymous label (≤ 60 chars).
* The `QUIZ_RESULTS` schema has no PII columns.
* IOC e-mail indicators use only the **sender domain** — the full address is
  unnecessary (data minimization).
* **Proof:** `test_S13`.

## 14. HTTPS is documented for production

The local demo runs plain HTTP on `127.0.0.1`. For any shared/production
deployment, terminate TLS in front of the app, e.g.:

```bash
# Option A - uvicorn with certificates (dev/staging)
uvicorn app:app --host 0.0.0.0 --port 8443 \
    --ssl-keyfile ./certs/key.pem --ssl-certfile ./certs/cert.pem

# Option B - reverse proxy (recommended): nginx/Caddy -> uvicorn on 127.0.0.1
# Caddy example (automatic HTTPS):
#   reverse_proxy 127.0.0.1:8000
```

Also for production: set `CORS_ALLOW_ORIGINS` to the real frontend origin,
replace demo API keys with per-user credentials from a secret store, and put
the app behind an authenticating gateway.

---

## Why threat-intelligence data itself requires access control

Threat-intelligence data looks "just analytical", but it reveals an
organization's **defensive posture**:

* **IOC lists** tell an adversary *what you have already detected* — allowing
  them to switch infrastructure you haven't seen yet.
* **Analyst notes and alert queues** reveal *what you know, what you
  mis-detect, and how fast you respond* — a roadmap for evading your SOC.
* **Vulnerability data** (especially prioritization scores) is effectively a
  **map of your weakest, most critical systems** — the exact list an attacker
  wants.
* **False-positive records** reveal which detections can be safely ignored.

That is why this project enforces authentication, RBAC, note masking,
rate limiting and audit logging even on a synthetic educational dataset —
it demonstrates the same controls a real CTI platform needs.

---

## Privacy considerations

* **Data minimization:** the system stores only what the analytics need.
* **Anonymous quiz results:** no user identification is required or stored.
* **Local-only storage:** the SQLite database stays on the analyst's machine;
  nothing is transmitted externally.
* **No telemetry:** the application makes no outbound connections at all.
