"""
Generate the human-readable test report (reports/test_report.md) from a real
pytest JUnit XML run.

Usage:
    python -m pytest tests -v --junitxml=reports/junit_results.xml
    python -m scripts.make_test_report

The report maps every test to its Test ID, scenario, input, expected result,
actual result (from the real run) and pass/fail. Results are NEVER
fabricated - the XML is produced by actually executing the suite.
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
JUNIT_XML = PROJECT_ROOT / "reports" / "junit_results.xml"
REPORT_MD = PROJECT_ROOT / "reports" / "test_report.md"

TEST_ID_RE = re.compile(r"^([TS])(\d{2,3})([bc]?)_")

# Test ID -> (Scenario, Input, Expected Result)
# (order follows the 35 required scenarios, then the security suite)
SCENARIOS = {
    "T-001": ("Valid IPv4", "198.51.100.25", "valid=True, type=ipv4"),
    "T-002": ("Invalid IPv4", "192.0.2.999 / 999.999.999.999", "valid=False"),
    "T-003": ("Valid IPv6", "2001:db8::1", "valid=True, type=ipv6"),
    "T-004": ("Valid domain", "login-check.invalid", "valid=True, type=domain"),
    "T-005": ("Invalid domain", "-bad-.com / *.example.com", "valid=False"),
    "T-006": ("Valid URL", "https://login-check.invalid/verify-account.html", "valid=True, type=url"),
    "T-007": ("Valid MD5-format hash", "d41d8cd98f00b204e9800998ecf8427e", "valid=True, type=md5"),
    "T-008": ("Valid SHA-1-format hash", "da39a3ee...afd80709", "valid=True, type=sha1"),
    "T-009": ("Valid SHA-256-format hash", "64-char synthetic hex", "valid=True, type=sha256"),
    "T-010": ("Valid CVE format", "cve-2026-900001", "valid=True, normalized=CVE-2026-900001"),
    "T-011": ("Invalid CVE format", "CVE-26-1 / CVE-2026-abc", "valid=False"),
    "T-012": ("Threat creation", "valid payload via threat_service", "created=True, NEW status, indicator row"),
    "T-012b": ("Threat creation rejects bad indicator", "invalid indicator value", "creation refused"),
    "T-013": ("Risk calculation", "demo factors (HIGH/85/15d/3/B/full ctx)", "risk=78, HIGH band, 6-factor breakdown"),
    "T-013b": ("Risk bands", "boundary scores 20/21/40/41/60/61/80/81", "INFO/LOW/MEDIUM/HIGH/CRITICAL bands"),
    "T-013c": ("Risk factor monotonicity", "raise each factor independently", "risk never decreases"),
    "T-014": ("Confidence calculation", "A+3src+5obs / D+1src / stale-B", "100 / 30 / 50 (staleness penalty applied)"),
    "T-014b": ("Risk vs confidence distinct", "identical inputs to both engines", "different models, both 0-100, independent"),
    "T-015": ("Source reliability", "grades A,B,C,D + dataset sources", "100/80/60/40; Internal SOC=A; Unknown=D"),
    "T-015b": ("Dataset sources graded", "SOURCES table", "all 6 synthetic sources have reliability grade"),
    "T-016": ("IOC enrichment", "login-check.invalid", "known=True, risk 78, related indicators, ATT&CK, notes"),
    "T-016b": ("Enrichment of unknown indicator", "not-in-database value", "known=False, no crash, safe response"),
    "T-017": ("Indicator search", "GET /api/indicators/search?q=198.51.100.25", "200 with all brief-required fields"),
    "T-017b": ("Indicator search rejects invalid", "malformed query", "400/422, never auto-connects"),
    "T-018": ("Threat correlation", "THR-2026-001", "cluster SYN-CAMP-2026-001, members>=3, attribution disclaimer"),
    "T-018b": ("Correlation summary", "correlate_threats() output", "cluster stats + shared-indicator links"),
    "T-019": ("Duplicate observation", "create same indicator twice", "merged: observation_count+1, no new record, timeline event"),
    "T-020": ("Alert generation", "demo record / low-risk record", "HIGH_RISK alert created; low-risk none"),
    "T-020b": ("Dataset alerts generated", "full DB alert engine run", "alert coverage of dataset rules"),
    "T-021": ("Alert correlation", "100 same-indicator observations", "1 merged alert, observation_count=100"),
    "T-021b": ("Distinct indicators not merged", "different indicator values", "separate alerts, no over-merging"),
    "T-022": ("Alert status update", "PUT /api/alerts/{id}/status", "401 unauth; 200 analyst; 422 invalid; timeline event"),
    "T-023": ("Analyst notes", "POST /api/threats/{id}/notes", "masked unauth; 401 unauth POST; 201 analyst"),
    "T-024": ("ATT&CK mapping", "attack_mappings for demo record", "T1566.002/Initial Access; only real IDs; unmapped when insufficient"),
    "T-024b": ("ATT&CK API summary", "GET /api/attack/summary", "tactic counts, technique frequency"),
    "T-025": ("Vulnerability scoring", "CVSS 9.8 lab vs 8.1 internet VPN", "52 vs 93 - context outranks CVSS"),
    "T-025b": ("CVSS severity bands", "9.8 / 7.5 / 5.0 / 2.1", "CRITICAL/HIGH/MEDIUM/LOW mapping"),
    "T-025c": ("Vulnerability API", "GET /api/vulnerabilities", "priorities + filters + 401 protection"),
    "T-026": ("Dashboard statistics", "GET /api/dashboard/stats + trends", "7 cards populated; 10 chart datasets"),
    "T-027": ("Severity filtering", "?severity=CRITICAL", "only CRITICAL items; 400 on invalid value"),
    "T-028": ("Category filtering", "?category=Phishing", "only Phishing items"),
    "T-029": ("Threat sorting", "sort=risk|confidence|observed|newest", "each ordering verified descending/newest"),
    "T-030": ("Awareness module retrieval", "GET /api/awareness/modules", "15 modules; 5 required sections each"),
    "T-030b": ("Quiz question shape", "GET /api/quiz", "36 questions, options without answers"),
    "T-031": ("Quiz scoring", "all-correct submission", "score 100, Strong Awareness band"),
    "T-031b": ("Quiz partial scoring + bands", "half-correct / empty / oversize label", "50 Basic; 422 invalid; band boundaries"),
    "T-032": ("Learning recommendation", "Phishing 40% / Passwords 90% / SocEng 55%", "module recommended / none required / review"),
    "T-033": ("Empty dataset", "initialized empty DB", "zero stats, no crash, clean 404s"),
    "T-033b": ("Empty dataset API", "dashboard/stats + threats on empty DB", "zeroed cards, empty list, 200s"),
    "T-034": ("API validation", "missing fields / bad enums / bad indicator", "422 with details; 400 bad query; valid create 201"),
    "T-035": ("Database persistence", "create via API, reopen connection", "record + indicator + timeline persist"),
    "T-035b": ("Schema integrity", "all tables, PKs, FKs, indexes", "11 tables present, referential integrity enforced"),
    "S-01": ("Security: URLs never visited", "socket blocked + URL enrichment", "no exception (no connection attempted)"),
    "S-02": ("Security: IPs never contacted", "socket blocked + IP enrichment", "no exception (no connection attempted)"),
    "S-03": ("Security: files never executed", "hash validation + blocked sockets", "data-only analysis, no fetch, no execution"),
    "S-03b": ("Security: no process execution", "AST scan of services", "no subprocess/os.system imports"),
    "S-03c": ("Security: no outbound calls in validator", "AST scan of ioc_validator.py", "only urllib.parse (string parsing) allowed"),
    "S-04": ("Security: descriptions sanitized", "<script>/<img onerror> payloads", "angle brackets escaped, no tag formation"),
    "S-04b": ("Sanitize unit behaviour", "markup/control chars via sanitize_text", "escaped or stripped"),
    "S-05": ("Security: XSS protection", "escapeHtml + payload rendering", "payloads neutralized backend + frontend"),
    "S-06": ("Security: API input validated", "empty/oversized/enum payloads", "401 before validation; 422 with key; 422/400 params"),
    "S-07": ("Security: analyst functions authenticated", "all write endpoints without key", "401 for missing/unknown key"),
    "S-08": ("Security: RBAC", "viewer/analyst/admin key matrix", "403 for insufficient role; admin-only audit log"),
    "S-09": ("Security: analyst notes protected", "unauthenticated detail view", "notes masked with authentication_required"),
    "S-10": ("Security: rate limiting", "12 requests with limit 8", "8x200 + 429 with Retry-After"),
    "S-11": ("Security: secrets from environment", "isolated interpreter with env vars", "values from env; no hardcoded fallback"),
    "S-11b": ("API keys never exposed", "public endpoint responses", "no key material in any response"),
    "S-12": ("Security: administrative changes audited", "alert status change", "AUDIT_LOG row with actor role, no raw key"),
    "S-13": ("Security: PII minimized", "quiz schema + oversized label", "no PII columns; 422 on oversized labels"),
    "S-13b": ("Why TI data needs access control", "dataset fields review", "notes/patch gaps reveal defensive posture - documented"),
}


def test_name_to_id(name: str):
    """Extract T-001 / S-01 style IDs from test node names."""
    name = name.split("[")[0]
    if not name.startswith("test_"):
        return None
    match = TEST_ID_RE.match(name[len("test_"):])
    if not match:
        return None
    kind, number, suffix = match.groups()
    return f"{kind}-{number}{suffix}"


def main() -> int:
    if not JUNIT_XML.exists():
        print("JUnit XML not found. Run first:")
        print("  python -m pytest tests -v --junitxml=reports/junit_results.xml")
        return 1

    tree = ET.parse(JUNIT_XML)
    root = tree.getroot()

    suites = root.iter("testsuite")
    results = {}          # test id -> (status, message, name)
    extras = []           # tests without a scenario ID
    totals = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}

    for suite in suites:
        for case in suite.iter("testcase"):
            name = case.get("name", "")
            status = "PASSED"
            message = ""
            failure = case.find("failure")
            error = case.find("error")
            skipped = case.find("skipped")
            if failure is not None:
                status = "FAILED"
                message = (failure.get("message") or failure.text or "")[:180]
            elif error is not None:
                status = "ERROR"
                message = (error.get("message") or error.text or "")[:180]
            elif skipped is not None:
                status = "SKIPPED"
            totals[status.lower() if status != "ERROR" else "errors"] += 1

            test_id = test_name_to_id(name)
            if test_id:
                results[test_id] = (status, message, name)
            elif status != "PASSED" or True:
                extras.append((name, status, message))

    total_tests = sum(totals.values())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# Automated Test Report")
    lines.append("")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Command:** `python -m pytest tests -v --junitxml=reports/junit_results.xml`  ")
    lines.append(f"**Result:** {totals['passed']} passed / {totals['failed']} failed / "
                 f"{totals['errors']} errors / {totals['skipped']} skipped — "
                 f"**{total_tests} automated tests**")
    lines.append("")
    lines.append("Results below are read from the real JUnit XML produced by the")
    lines.append("actual test execution — nothing is fabricated.")
    lines.append("")
    lines.append("| Test ID | Scenario | Input | Expected Result | Actual Result | Pass/Fail |")
    lines.append("|---|---|---|---|---|---|")
    for test_id in sorted(SCENARIOS):
        scenario, inp, expected = SCENARIOS[test_id]
        if test_id in results:
            status, message, name = results[test_id]
            actual = status if status == "PASSED" else f"{status}: {message}"
            verdict = "✅ PASS" if status == "PASSED" else f"❌ {status}"
        else:
            actual = "(no test executed for this ID)"
            verdict = "—"
        lines.append(f"| {test_id} | {scenario} | {inp} | {expected} | "
                     f"{actual.replace('|', '/')} | {verdict} |")

    if extras:
        lines.append("")
        lines.append("### Additional edge-case tests (beyond the required 35)")
        lines.append("")
        lines.append("| Test | Status | Note |")
        lines.append("|---|---|---|")
        for name, status, message in extras:
            lines.append(f"| `{name}` | {status} | {message.replace('|', '/')[:120]} |")

    lines.append("")
    lines.append("### Required-scenario coverage check")
    lines.append("")
    missing = [tid for tid in SCENARIOS if tid not in results]
    if not missing:
        lines.append("All 35 required functional scenarios (T-001 … T-035), their "
                     "edge-case companions (T-012b … T-035b), and the security "
                     "suite (S-01 … S-13b) are covered by executed tests.")
    else:
        lines.append(f"MISSING REQUIRED SCENARIOS: {missing}")

    REPORT_MD.parent.mkdir(exist_ok=True)
    REPORT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"Report written to {REPORT_MD}")
    print(f"Totals: {totals}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
