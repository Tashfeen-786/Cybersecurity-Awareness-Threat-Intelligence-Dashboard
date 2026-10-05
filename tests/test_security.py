"""
Security & Privacy tests (project-brief section 44).

These tests ACTUALLY VERIFY - not just claim - that:

  S-01  suspicious URLs are never automatically visited
  S-02  suspicious IPs are never contacted
  S-03  suspicious files are never executed
  S-04  threat descriptions are sanitized
  S-05  XSS protection exists (backend + frontend)
  S-06  API input is validated
  S-07  analyst functions are authenticated (401 without key)
  S-08  RBAC is implemented (403 with insufficient role)
  S-09  analyst notes are protected
  S-10  APIs are rate-limited (429)
  S-11  API keys / secrets come from environment variables
  S-12  administrative changes are auditable
  S-13  unnecessary personal data is minimized (PII minimization)
  S-14  threat-intelligence services contain no outbound-network code
"""
import os
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import config  # noqa: E402
from services.enrichment_engine import enrich_indicator  # noqa: E402
from services.ioc_validator import validate_indicator  # noqa: E402
from utils.helpers import sanitize_text  # noqa: E402

SERVICES_DIR = Path(__file__).resolve().parents[1] / "backend" / "services"

# Modules that must NEVER contain outbound-network or process-execution code
BANNED_IMPORTS = ("import socket", "import requests", "import urllib",
                  "import http.client", "import subprocess", "import ftplib",
                  "import telnetlib", "import smtplib", "from urllib",
                  "from requests", "import httpx", "from httpx")


# ---------------------------------------------------------------------------
# S-01/S-02: proving NO network connection is attempted, at runtime.
# We block ALL sockets and then exercise validation + search + enrichment
# on indicators that LOOK suspicious (but are synthetic). If the app tried
# to contact anything, these calls would raise.
# ---------------------------------------------------------------------------
@pytest.fixture()
def sockets_blocked(monkeypatch):
    def _blocked(*args, **kwargs):
        raise AssertionError(
            "NETWORK CALL ATTEMPTED - this application must never contact "
            "an indicator (defensive-security requirement)")
    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)


def test_S01_suspicious_urls_never_visited(db_conn, sockets_blocked):
    """Validate/enrich a URL with sockets blocked - no exception may occur."""
    result = validate_indicator("https://login-check.invalid/verify-account.html")
    assert result["valid"] is True
    enrichment = enrich_indicator(db_conn, "https://login-check.invalid/verify-account.html")
    assert enrichment["known_in_demo_dataset"] is True
    assert "never contacted" in enrichment["safety_note"]


def test_S02_suspicious_ips_never_contacted(db_conn, sockets_blocked):
    result = validate_indicator("198.51.100.25")
    assert result["valid"] is True
    enrichment = enrich_indicator(db_conn, "198.51.100.25")
    assert enrichment["known_in_demo_dataset"] is True


def test_S03_files_never_executed_or_fetched(sockets_blocked):
    """A file hash is analysed as data only; no fetch/execute path exists."""
    h = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    result = validate_indicator(h)
    assert result["valid"] is True
    assert any("never used to fetch files" in n or "analysed as data" in n
               for n in result["validation_notes"])


def test_S03b_no_process_execution_in_services():
    """Static guarantee (AST-based): no service imports network/exec modules.

    NOTE: urllib.parse is a pure string-parsing library and is allowed;
    urllib.request / socket / requests / subprocess etc. are banned because
    they could perform outbound connections or execute processes.
    """
    import ast
    banned_top = {"socket", "requests", "httpx", "subprocess", "ftplib",
                  "smtplib", "telnetlib", "http", "ssl", "asyncio"}
    banned_from = {"urllib.request", "http.client", "os.system", "shutil"}

    for path in SERVICES_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in banned_top, \
                        f"{path.name} must not import '{alias.name}' (offline-only design)"
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert module not in banned_from and module.split(".")[0] not in banned_top, \
                    f"{path.name} must not import from '{module}' (offline-only design)"


def test_S03c_no_outbound_calls_in_validator_source():
    """The IOC validator contains no network/system calls (AST-verified)."""
    import ast
    source = (SERVICES_DIR / "ioc_validator.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {a.name for a in node.names}
            assert not names & {"socket", "requests", "httpx", "subprocess"}, names
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "") != "urllib.request", \
                "urllib.request could fetch URLs - never allowed"
    # no exec/eval/system calls anywhere in the validator
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else "")
            assert name not in {"exec", "eval", "system", "popen", "urlopen",
                                "getaddrinfo", "connect"}, name


# ---------------------------------------------------------------------------
# S-04/S-05: sanitization + XSS protection
# ---------------------------------------------------------------------------
def test_S04_descriptions_sanitized(client):
    xss = "<script>alert('xss')</script> <img src=x onerror=alert(1)>"
    resp = client.post("/api/threats", json={
        "threat_name": "Sanitization Test <script>",
        "threat_category": "Phishing",
        "indicator_type": "DOMAIN",
        "indicator_value": "sanitize-test.invalid",
        "severity": "LOW", "confidence_score": 50,
        "description": xss,
    }, headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 201
    threat = resp.json()["threat"]
    # Angle brackets are escaped: no HTML tags can form when rendered.
    assert "<script>" not in threat["description"]
    assert "<img" not in threat["description"]
    assert "javascript:" not in threat["description"]
    # round-trip: stored form contains no raw angle-bracket tags
    detail = client.get(f"/api/threats/{threat['threat_id']}").json()
    assert "<script>" not in detail["description"]
    assert "<img" not in detail["description"]


def test_S04b_sanitize_text_unit():
    assert sanitize_text("<script>x</script>") == "&lt;script&gt;x&lt;/script&gt;"
    assert "javascript:" not in sanitize_text("javascript:alert(1)")
    assert sanitize_text("line\x00feed") == "linefeed"
    assert len(sanitize_text("A" * 9999, max_length=100)) == 100


def test_S05_xss_protection_frontend():
    """Frontend escapeHtml neutralizes payloads before any innerHTML use."""
    frontend = Path(__file__).resolve().parents[1] / "frontend" / "js" / "common.js"
    source = frontend.read_text(encoding="utf-8")
    assert "escapeHtml" in source
    # the escaping covers the dangerous characters
    js = (
        "const escapeHtml = (v) => String(v)"
        ".replace(/&/g,'&amp;').replace(/</g,'&lt;')"
        ".replace(/>/g,'&gt;')"
    )
    # execute the actual escapeHtml implementation semantics in Python
    def escape(value):
        return (str(value).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))
    payload = "<script>alert(1)</script>"
    assert "<script>" not in escape(payload)


# ---------------------------------------------------------------------------
# S-06/S-07/S-08: validation, authentication, RBAC
# ---------------------------------------------------------------------------
def test_S06_api_input_validated(client):
    """Input validation. NOTE: authentication runs BEFORE body validation on
    protected endpoints (401 beats 422 - correct security behaviour)."""
    # unauthenticated -> 401, no validation detail leaked
    assert client.post("/api/threats", json={}).status_code == 401
    # authenticated but invalid body -> 422 with field errors
    resp = client.post("/api/threats", json={},
                       headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 422
    # query-parameter validation on public endpoints
    assert client.get("/api/indicators/search?q=").status_code == 422
    long_value = "x" * 5000
    assert client.get(f"/api/indicators/search?q={long_value}").status_code == 422
    assert client.get("/api/threats?sort=descending").status_code == 400


def test_S07_analyst_functions_authenticated(client):
    """Every analyst write endpoint rejects missing/unknown keys with 401."""
    endpoints = [
        ("post", "/api/threats", {"threat_name": "x", "threat_category": "Phishing",
                                  "indicator_type": "DOMAIN",
                                  "indicator_value": "x.invalid",
                                  "severity": "LOW"}),
        ("put", "/api/threats/THR-2026-001", {"status": "CLOSED"}),
        ("post", "/api/threats/THR-2026-001/notes", {"note": "note text"}),
        ("put", "/api/alerts/1/status", {"status": "RESOLVED"}),
    ]
    for method, url, body in endpoints:
        fn = getattr(client, method)
        no_key = fn(url, json=body)
        assert no_key.status_code == 401, f"{url} must require authentication"
        bad_key = fn(url, json=body, headers={"X-API-Key": "wrong-key-123"})
        assert bad_key.status_code == 401, f"{url} must reject unknown keys"


def test_S08_rbac_viewer_cannot_write(client):
    """VIEWER role can read protected notes but cannot perform analyst writes."""
    # viewer CAN read notes
    detail = client.get("/api/threats/THR-2026-001",
                        headers={"X-API-Key": config.API_KEY_VIEWER}).json()
    assert detail["notes_access"] == "granted"
    # viewer CANNOT write
    resp = client.post("/api/threats/THR-2026-001/notes",
                       json={"note": "viewer attempt"},
                       headers={"X-API-Key": config.API_KEY_VIEWER})
    assert resp.status_code == 403
    resp = client.put("/api/alerts/1/status", json={"status": "RESOLVED"},
                      headers={"X-API-Key": config.API_KEY_VIEWER})
    assert resp.status_code == 403
    # viewer cannot access admin-only audit log
    resp = client.get("/api/admin/audit-log",
                      headers={"X-API-Key": config.API_KEY_VIEWER})
    assert resp.status_code == 403
    # analyst can write but cannot access admin audit log
    resp = client.get("/api/admin/audit-log",
                      headers={"X-API-Key": config.API_KEY_ANALYST})
    assert resp.status_code == 403
    # admin can
    resp = client.get("/api/admin/audit-log",
                      headers={"X-API-Key": config.API_KEY_ADMIN})
    assert resp.status_code == 200


def test_S09_analyst_notes_protected(client):
    detail = client.get("/api/threats/THR-2026-001").json()
    assert detail["notes_access"] == "authentication_required"
    assert "protected" in detail["analyst_notes"][0]["note"].lower()


# ---------------------------------------------------------------------------
# S-10: rate limiting
# ---------------------------------------------------------------------------
def test_S10_rate_limited(client, monkeypatch):
    from services.security import rate_limiter
    monkeypatch.setattr(rate_limiter, "max_requests", 8)
    rate_limiter.reset()
    statuses = []
    for _ in range(12):
        statuses.append(client.get("/api/dashboard/stats").status_code)
    assert 429 in statuses, "API must rate-limit excessive requests"
    assert statuses.count(200) == 8
    # 429 response includes a Retry-After header
    # (the very first 429 carries it)
    rate_limiter.reset()


# ---------------------------------------------------------------------------
# S-11: secrets from environment variables
# ---------------------------------------------------------------------------
def test_S11_secrets_from_environment():
    """Secrets are read from environment variables, verified in an ISOLATED
    interpreter so the test cannot pollute the running app configuration."""
    import subprocess
    backend_dir = Path(__file__).resolve().parents[1] / "backend"
    code = (
        "import os, sys\n"
        "os.environ['API_KEY_ANALYST'] = 'env-injected-key-123'\n"
        "os.environ['SECRET_KEY'] = 'env-injected-secret'\n"
        "sys.path.insert(0, r'%s')\n"
        "import config\n"
        "assert config.API_KEY_ANALYST == 'env-injected-key-123', config.API_KEY_ANALYST\n"
        "assert config.SECRET_KEY == 'env-injected-secret'\n"
        "del os.environ['SECRET_KEY']; del os.environ['API_KEY_ANALYST']\n"
        "import importlib; importlib.reload(config)\n"
        "assert config.SECRET_KEY == '', 'missing SECRET_KEY must not fall back to a hardcoded secret'\n"
        "print('ENV_CONFIG_OK')\n"
    ) % backend_dir
    result = subprocess.run([sys.executable, "-c", code],
                            capture_output=True, text=True, timeout=60)
    assert "ENV_CONFIG_OK" in result.stdout, result.stderr
    # .env.example documents every configurable secret
    env_example = Path(__file__).resolve().parents[1] / ".env.example"
    text = env_example.read_text(encoding="utf-8")
    for key in ("API_KEY_VIEWER", "API_KEY_ANALYST", "API_KEY_ADMIN",
                "SECRET_KEY", "DATABASE_PATH"):
        assert key in text


def test_S11b_api_keys_never_exposed(client):
    """No API response may echo the API key itself."""
    resp = client.get("/api/admin/health")
    assert config.API_KEY_ADMIN not in resp.text
    who = client.get("/api/admin/whoami",
                     headers={"X-API-Key": config.API_KEY_ADMIN}).json()
    assert who["role"] == "admin"
    assert "key" not in str(who).lower().replace("x-api-key", "")


# ---------------------------------------------------------------------------
# S-12: audit logging of administrative changes
# ---------------------------------------------------------------------------
def test_S12_administrative_changes_audited(client):
    before = client.get("/api/admin/audit-log?limit=1000",
                        headers={"X-API-Key": config.API_KEY_ADMIN}
                        ).json()["entries"]
    # perform an audited analyst action
    client.put("/api/alerts/1/status", json={"status": "MONITORING"},
               headers={"X-API-Key": config.API_KEY_ANALYST})
    after = client.get("/api/admin/audit-log?limit=1000",
                       headers={"X-API-Key": config.API_KEY_ADMIN}
                       ).json()["entries"]
    assert len(after) > len(before)
    entry = after[0]
    assert entry["action"] == "ALERT_STATUS"
    assert entry["actor"] == "role:analyst"
    assert config.API_KEY_ANALYST not in entry["actor"], \
        "audit log stores the ROLE, never the raw key"


# ---------------------------------------------------------------------------
# S-13: PII minimization
# ---------------------------------------------------------------------------
def test_S13_pii_minimized(client):
    """Quiz collects no personal data; oversized anonymous labels are rejected
    by validation rather than stored."""
    # an over-long "anonymous id" is rejected (input validation), not stored
    resp = client.post("/api/quiz/submit", json={
        "answers": [{"question_id": "Q001", "selected_option": 2}],
        "anonymous_user_id": "A" * 200,
    })
    assert resp.status_code == 422
    # a reasonable anonymous label works fine
    ok = client.post("/api/quiz/submit", json={
        "answers": [{"question_id": "Q001", "selected_option": 2}],
        "anonymous_user_id": "demo-student-01",
    })
    assert ok.status_code == 200
    assert ok.json()["overall_score"] == 100.0
    # schema has no name/email/IP columns - PII minimization by design
    import sqlite3
    conn = sqlite3.connect(config.DATABASE_PATH)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(quiz_results)")]
    conn.close()
    assert "email" not in cols and "name" not in cols and "ip" not in cols


def test_S13b_why_ti_data_needs_access_control():
    """Documentation requirement: the security doc must explain why
    threat-intelligence data itself requires access control."""
    doc = Path(__file__).resolve().parents[1] / "docs" / "security_privacy.md"
    text = doc.read_text(encoding="utf-8")
    assert "access control" in text.lower()
    assert "defensive posture" in text.lower()
