"""
Central configuration for the Cybersecurity Awareness & Threat Intelligence Dashboard.

SECURITY NOTES
--------------
* All secrets (API keys, secret key) are read from environment variables or a
  local ``.env`` file. They are NEVER hard-coded and NEVER returned by the API.
* The project runs fully offline: no external threat feeds, no API keys for
  third-party services, no outbound connections to indicators. Ever.
* This is a DEFENSIVE, education-oriented project using SYNTHETIC data only.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

try:  # Optional dependency - the app still works without python-dotenv.
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

# ---------------------------------------------------------------------------
# Paths (resolved relative to this file so the app works from any CWD/Windows)
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent          # project root
BACKEND_DIR = Path(__file__).resolve().parent              # backend/
DATA_DIR = BASE_DIR / "data"
AWARENESS_DIR = BASE_DIR / "awareness"
FRONTEND_DIR = BASE_DIR / "frontend"
SCREENSHOTS_DIR = BASE_DIR / "screenshots"
REPORTS_DIR = BASE_DIR / "reports"

THREAT_DATASET_CSV = DATA_DIR / "threat_intelligence_dataset.csv"
VULNERABILITIES_CSV = DATA_DIR / "vulnerabilities.csv"
DATASET_META_JSON = DATA_DIR / "dataset_meta.json"
AWARENESS_MODULES_JSON = AWARENESS_DIR / "modules.json"
QUIZ_QUESTIONS_JSON = AWARENESS_DIR / "quiz_questions.json"

# ---------------------------------------------------------------------------
# Load .env (local overrides). A bundled .env.example documents every key.
# ---------------------------------------------------------------------------
if load_dotenv is not None and not globals().get("_DOTENV_ALREADY_LOADED", False):
    load_dotenv(BASE_DIR / ".env", override=False)
    _DOTENV_ALREADY_LOADED = True

APP_NAME = "Cybersecurity Awareness & Threat Intelligence Dashboard"
APP_VERSION = "1.0.0"
SYNTHETIC_LABEL = "SYNTHETIC / DEMO ONLY"

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", str(BACKEND_DIR / "threat_intel.db")))

if not DATABASE_PATH.is_absolute():
    DATABASE_PATH = BASE_DIR / DATABASE_PATH

# ---------------------------------------------------------------------------
# Authentication / RBAC
# ---------------------------------------------------------------------------
# Demo API keys are configured via environment variables (see .env.example).
# In a production deployment these would be per-user credentials in a secret
# store; for this local educational project three demo keys demonstrate RBAC.
API_KEY_VIEWER = os.getenv("API_KEY_VIEWER", "demo-viewer-key")
API_KEY_ANALYST = os.getenv("API_KEY_ANALYST", "demo-analyst-key")
API_KEY_ADMIN = os.getenv("API_KEY_ADMIN", "demo-admin-key")
SECRET_KEY = os.getenv("SECRET_KEY", "")  # used to sign future session tokens

ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"

API_KEYS = {
    API_KEY_VIEWER: ROLE_VIEWER,
    API_KEY_ANALYST: ROLE_ANALYST,
    API_KEY_ADMIN: ROLE_ADMIN,
}

ROLE_PERMISSIONS = {
    # viewer  -> read everything, including protected analyst notes
    ROLE_VIEWER: {"read", "read_notes"},
    # analyst -> viewer rights + triage: create notes, update statuses, add threats
    ROLE_ANALYST: {"read", "read_notes", "write_notes", "triage", "create_threat"},
    # admin   -> analyst rights + administrative actions (audited)
    ROLE_ADMIN: {"read", "read_notes", "write_notes", "triage", "create_threat",
                 "admin"},
}


def get_role_for_api_key(api_key: str):
    """Return the role for an API key, or None when the key is unknown."""
    if not api_key:
        return None
    return API_KEYS.get(api_key)


def role_has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


# ---------------------------------------------------------------------------
# Rate limiting (simple, dependency-free sliding window per client)
# ---------------------------------------------------------------------------
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "240"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# ---------------------------------------------------------------------------
# Application tuning
# ---------------------------------------------------------------------------
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 200
MAX_NOTE_LENGTH = 2000
ALERT_RISK_THRESHOLD = int(os.getenv("ALERT_RISK_THRESHOLD", "70"))
ALERT_CONFIDENCE_RISK_THRESHOLD = int(os.getenv("ALERT_CONFIDENCE_RISK_THRESHOLD", "55"))
ALERT_CONFIDENCE_THRESHOLD = int(os.getenv("ALERT_CONFIDENCE_THRESHOLD", "80"))
ALERT_REPEATED_OBSERVATION_COUNT = int(os.getenv("ALERT_REPEATED_OBSERVATION_COUNT", "8"))
ALERT_CORRELATION_CLUSTER_SIZE = int(os.getenv("ALERT_CORRELATION_CLUSTER_SIZE", "3"))
VULN_PRIORITY_ALERT_THRESHOLD = int(os.getenv("VULN_PRIORITY_ALERT_THRESHOLD", "85"))

# CORS: local educational demo. Production deployments should restrict this.
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*")

DEMO_THREAT_ID = "THR-2026-001"  # safe demonstration scenario required by the spec


def generate_secret_key(length: int = 48) -> str:
    """Helper used by the setup script to write a strong SECRET_KEY to .env."""
    return secrets.token_urlsafe(length)
