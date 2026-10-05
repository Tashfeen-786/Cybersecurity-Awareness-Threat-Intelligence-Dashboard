# Automated Test Report

**Generated:** 2026-09-29 19:53 UTC  
**Command:** `python -m pytest tests -v --junitxml=reports/junit_results.xml`  
**Result:** 72 passed / 0 failed / 0 errors / 0 skipped — **72 automated tests**

Results below are read from the real JUnit XML produced by the
actual test execution — nothing is fabricated.

| Test ID | Scenario | Input | Expected Result | Actual Result | Pass/Fail |
|---|---|---|---|---|---|
| S-01 | Security: URLs never visited | socket blocked + URL enrichment | no exception (no connection attempted) | PASSED | ✅ PASS |
| S-02 | Security: IPs never contacted | socket blocked + IP enrichment | no exception (no connection attempted) | PASSED | ✅ PASS |
| S-03 | Security: files never executed | hash validation + blocked sockets | data-only analysis, no fetch, no execution | PASSED | ✅ PASS |
| S-03b | Security: no process execution | AST scan of services | no subprocess/os.system imports | PASSED | ✅ PASS |
| S-03c | Security: no outbound calls in validator | AST scan of ioc_validator.py | only urllib.parse (string parsing) allowed | PASSED | ✅ PASS |
| S-04 | Security: descriptions sanitized | <script>/<img onerror> payloads | angle brackets escaped, no tag formation | PASSED | ✅ PASS |
| S-04b | Sanitize unit behaviour | markup/control chars via sanitize_text | escaped or stripped | PASSED | ✅ PASS |
| S-05 | Security: XSS protection | escapeHtml + payload rendering | payloads neutralized backend + frontend | PASSED | ✅ PASS |
| S-06 | Security: API input validated | empty/oversized/enum payloads | 401 before validation; 422 with key; 422/400 params | PASSED | ✅ PASS |
| S-07 | Security: analyst functions authenticated | all write endpoints without key | 401 for missing/unknown key | PASSED | ✅ PASS |
| S-08 | Security: RBAC | viewer/analyst/admin key matrix | 403 for insufficient role; admin-only audit log | PASSED | ✅ PASS |
| S-09 | Security: analyst notes protected | unauthenticated detail view | notes masked with authentication_required | PASSED | ✅ PASS |
| S-10 | Security: rate limiting | 12 requests with limit 8 | 8x200 + 429 with Retry-After | PASSED | ✅ PASS |
| S-11 | Security: secrets from environment | isolated interpreter with env vars | values from env; no hardcoded fallback | PASSED | ✅ PASS |
| S-11b | API keys never exposed | public endpoint responses | no key material in any response | PASSED | ✅ PASS |
| S-12 | Security: administrative changes audited | alert status change | AUDIT_LOG row with actor role, no raw key | PASSED | ✅ PASS |
| S-13 | Security: PII minimized | quiz schema + oversized label | no PII columns; 422 on oversized labels | PASSED | ✅ PASS |
| S-13b | Why TI data needs access control | dataset fields review | notes/patch gaps reveal defensive posture - documented | PASSED | ✅ PASS |
| T-001 | Valid IPv4 | 198.51.100.25 | valid=True, type=ipv4 | PASSED | ✅ PASS |
| T-002 | Invalid IPv4 | 192.0.2.999 / 999.999.999.999 | valid=False | PASSED | ✅ PASS |
| T-003 | Valid IPv6 | 2001:db8::1 | valid=True, type=ipv6 | PASSED | ✅ PASS |
| T-004 | Valid domain | login-check.invalid | valid=True, type=domain | PASSED | ✅ PASS |
| T-005 | Invalid domain | -bad-.com / *.example.com | valid=False | PASSED | ✅ PASS |
| T-006 | Valid URL | https://login-check.invalid/verify-account.html | valid=True, type=url | PASSED | ✅ PASS |
| T-007 | Valid MD5-format hash | d41d8cd98f00b204e9800998ecf8427e | valid=True, type=md5 | PASSED | ✅ PASS |
| T-008 | Valid SHA-1-format hash | da39a3ee...afd80709 | valid=True, type=sha1 | PASSED | ✅ PASS |
| T-009 | Valid SHA-256-format hash | 64-char synthetic hex | valid=True, type=sha256 | PASSED | ✅ PASS |
| T-010 | Valid CVE format | cve-2026-900001 | valid=True, normalized=CVE-2026-900001 | PASSED | ✅ PASS |
| T-011 | Invalid CVE format | CVE-26-1 / CVE-2026-abc | valid=False | PASSED | ✅ PASS |
| T-012 | Threat creation | valid payload via threat_service | created=True, NEW status, indicator row | PASSED | ✅ PASS |
| T-012b | Threat creation rejects bad indicator | invalid indicator value | creation refused | PASSED | ✅ PASS |
| T-013 | Risk calculation | demo factors (HIGH/85/15d/3/B/full ctx) | risk=78, HIGH band, 6-factor breakdown | PASSED | ✅ PASS |
| T-013b | Risk bands | boundary scores 20/21/40/41/60/61/80/81 | INFO/LOW/MEDIUM/HIGH/CRITICAL bands | PASSED | ✅ PASS |
| T-013c | Risk factor monotonicity | raise each factor independently | risk never decreases | PASSED | ✅ PASS |
| T-014 | Confidence calculation | A+3src+5obs / D+1src / stale-B | 100 / 30 / 50 (staleness penalty applied) | PASSED | ✅ PASS |
| T-014b | Risk vs confidence distinct | identical inputs to both engines | different models, both 0-100, independent | PASSED | ✅ PASS |
| T-015 | Source reliability | grades A,B,C,D + dataset sources | 100/80/60/40; Internal SOC=A; Unknown=D | PASSED | ✅ PASS |
| T-015b | Dataset sources graded | SOURCES table | all 6 synthetic sources have reliability grade | PASSED | ✅ PASS |
| T-016 | IOC enrichment | login-check.invalid | known=True, risk 78, related indicators, ATT&CK, notes | PASSED | ✅ PASS |
| T-016b | Enrichment of unknown indicator | not-in-database value | known=False, no crash, safe response | PASSED | ✅ PASS |
| T-017 | Indicator search | GET /api/indicators/search?q=198.51.100.25 | 200 with all brief-required fields | PASSED | ✅ PASS |
| T-017b | Indicator search rejects invalid | malformed query | 400/422, never auto-connects | PASSED | ✅ PASS |
| T-018 | Threat correlation | THR-2026-001 | cluster SYN-CAMP-2026-001, members>=3, attribution disclaimer | PASSED | ✅ PASS |
| T-018b | Correlation summary | correlate_threats() output | cluster stats + shared-indicator links | PASSED | ✅ PASS |
| T-019 | Duplicate observation | create same indicator twice | merged: observation_count+1, no new record, timeline event | PASSED | ✅ PASS |
| T-020 | Alert generation | demo record / low-risk record | HIGH_RISK alert created; low-risk none | PASSED | ✅ PASS |
| T-020b | Dataset alerts generated | full DB alert engine run | alert coverage of dataset rules | PASSED | ✅ PASS |
| T-021 | Alert correlation | 100 same-indicator observations | 1 merged alert, observation_count=100 | PASSED | ✅ PASS |
| T-021b | Distinct indicators not merged | different indicator values | separate alerts, no over-merging | PASSED | ✅ PASS |
| T-022 | Alert status update | PUT /api/alerts/{id}/status | 401 unauth; 200 analyst; 422 invalid; timeline event | PASSED | ✅ PASS |
| T-023 | Analyst notes | POST /api/threats/{id}/notes | masked unauth; 401 unauth POST; 201 analyst | PASSED | ✅ PASS |
| T-024 | ATT&CK mapping | attack_mappings for demo record | T1566.002/Initial Access; only real IDs; unmapped when insufficient | PASSED | ✅ PASS |
| T-024b | ATT&CK API summary | GET /api/attack/summary | tactic counts, technique frequency | PASSED | ✅ PASS |
| T-025 | Vulnerability scoring | CVSS 9.8 lab vs 8.1 internet VPN | 52 vs 93 - context outranks CVSS | PASSED | ✅ PASS |
| T-025b | CVSS severity bands | 9.8 / 7.5 / 5.0 / 2.1 | CRITICAL/HIGH/MEDIUM/LOW mapping | PASSED | ✅ PASS |
| T-025c | Vulnerability API | GET /api/vulnerabilities | priorities + filters + 401 protection | PASSED | ✅ PASS |
| T-026 | Dashboard statistics | GET /api/dashboard/stats + trends | 7 cards populated; 10 chart datasets | PASSED | ✅ PASS |
| T-027 | Severity filtering | ?severity=CRITICAL | only CRITICAL items; 400 on invalid value | PASSED | ✅ PASS |
| T-028 | Category filtering | ?category=Phishing | only Phishing items | PASSED | ✅ PASS |
| T-029 | Threat sorting | sort=risk|confidence|observed|newest | each ordering verified descending/newest | PASSED | ✅ PASS |
| T-030 | Awareness module retrieval | GET /api/awareness/modules | 15 modules; 5 required sections each | PASSED | ✅ PASS |
| T-030b | Quiz question shape | GET /api/quiz | 36 questions, options without answers | PASSED | ✅ PASS |
| T-031 | Quiz scoring | all-correct submission | score 100, Strong Awareness band | PASSED | ✅ PASS |
| T-031b | Quiz partial scoring + bands | half-correct / empty / oversize label | 50 Basic; 422 invalid; band boundaries | PASSED | ✅ PASS |
| T-032 | Learning recommendation | Phishing 40% / Passwords 90% / SocEng 55% | module recommended / none required / review | PASSED | ✅ PASS |
| T-033 | Empty dataset | initialized empty DB | zero stats, no crash, clean 404s | PASSED | ✅ PASS |
| T-033b | Empty dataset API | dashboard/stats + threats on empty DB | zeroed cards, empty list, 200s | PASSED | ✅ PASS |
| T-034 | API validation | missing fields / bad enums / bad indicator | 422 with details; 400 bad query; valid create 201 | PASSED | ✅ PASS |
| T-035 | Database persistence | create via API, reopen connection | record + indicator + timeline persist | PASSED | ✅ PASS |
| T-035b | Schema integrity | all tables, PKs, FKs, indexes | 11 tables present, referential integrity enforced | PASSED | ✅ PASS |

### Additional edge-case tests (beyond the required 35)

| Test | Status | Note |
|---|---|---|
| `test_empty_and_oversized_inputs` | PASSED |  |
| `test_email_sender_domain` | PASSED |  |

### Required-scenario coverage check

All 35 required functional scenarios (T-001 … T-035), their edge-case companions (T-012b … T-035b), and the security suite (S-01 … S-13b) are covered by executed tests.