"""
Pytest fixtures for the Cybersecurity Awareness & Threat Intelligence Dashboard.

Test isolation strategy:
  * ONE source database is built from the real synthetic CSVs per session.
  * Every test gets a pristine FILE COPY of that database, so tests that
    create/update records never affect each other.
  * API tests point the FastAPI app at the per-test copy via
    config.DATABASE_PATH (monkeypatched).
"""
from __future__ import annotations

import csv
import shutil
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

import config  # noqa: E402
from database import get_connection, init_database  # noqa: E402


@pytest.fixture(scope="session")
def source_db(tmp_path_factory):
    """Build one database from the real synthetic dataset (session scope)."""
    path = tmp_path_factory.mktemp("source") / "source.db"
    init_database(db_path=path)
    return path


@pytest.fixture()
def db_file(source_db, tmp_path):
    """Pristine per-test copy of the source database."""
    target = tmp_path / "test.db"
    shutil.copy(source_db, target)
    return target


@pytest.fixture()
def db_conn(db_file):
    """A live SQLite connection to the per-test database copy."""
    with get_connection(db_file) as conn:
        yield conn


@pytest.fixture()
def client(db_file, monkeypatch):
    """FastAPI TestClient wired to the per-test database copy."""
    monkeypatch.setattr(config, "DATABASE_PATH", db_file)
    from fastapi.testclient import TestClient
    from services.security import rate_limiter
    rate_limiter.reset()
    from app import app
    with TestClient(app) as c:
        yield c
    rate_limiter.reset()


@pytest.fixture()
def empty_db(tmp_path):
    """An initialized database with EMPTY datasets (headers only)."""
    threat_csv = tmp_path / "empty_threats.csv"
    with open(threat_csv, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows([[
            "threat_id", "timestamp", "threat_name", "threat_category",
            "indicator_type", "indicator_value", "source_name",
            "confidence_score", "severity", "risk_score", "status",
            "first_seen", "last_seen", "country_or_region_optional",
            "description", "mitre_tactic_optional", "mitre_technique_optional",
            "cve_id_optional", "campaign_id", "observation_count"]])
    vuln_csv = tmp_path / "empty_vulns.csv"
    with open(vuln_csv, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows([[
            "cve_id", "product_category", "product_name", "severity",
            "cvss_score", "published_date", "patch_available",
            "exploitation_status_demo", "asset_criticality", "exposure",
            "business_context", "priority_score", "priority_band",
            "description"]])
    db_path = tmp_path / "empty.db"
    init_database(db_path=db_path, threat_csv=threat_csv,
                  vulnerabilities_csv=vuln_csv, seed_quiz=False,
                  seed_notes=False)
    return db_path


DEMO_ANALYST_KEY = config.API_KEY_ANALYST
DEMO_VIEWER_KEY = config.API_KEY_VIEWER
DEMO_ADMIN_KEY = config.API_KEY_ADMIN
