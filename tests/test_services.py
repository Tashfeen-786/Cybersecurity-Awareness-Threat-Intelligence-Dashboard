"""
Service-level tests: enrichment, search, correlation, duplicate observations
(scenarios 16-19 from the project brief).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from services.correlation_engine import correlate_threats  # noqa: E402
from services.enrichment_engine import enrich_indicator  # noqa: E402
from services.threat_service import (  # noqa: E402
    create_threat, find_duplicate_observation, list_threats)
from utils.helpers import iso, utc_now  # noqa: E402


# T-016 - IOC enrichment
def test_T016_ioc_enrichment(db_conn):
    result = enrich_indicator(db_conn, "login-check.invalid")
    assert result["known_in_demo_dataset"] is True
    assert result["indicator_type"] == "domain"
    assert result["risk"] == 78
    assert result["confidence"] == 85
    assert "Phishing" in result["associated_categories"]
    assert result["summary"]["first_seen"] is not None
    assert result["summary"]["last_seen"] is not None
    # related indicators from the demo campaign
    values = [i["indicator_value"] for i in result["related_indicators"]]
    assert "198.51.100.25" in values
    # MITRE mapping present where justified
    assert any(m["technique_id"] == "T1566.002" for m in result["mitre_mapping"])
    # analyst notes are part of enrichment
    assert any("multiple synthetic phishing observations" in n["note"]
               for n in result["analyst_notes"])
    assert "never contacted" in result["safety_note"]


def test_T016b_enrichment_unknown_indicator(db_conn):
    result = enrich_indicator(db_conn, "never-seen-before.invalid")
    assert result["known_in_demo_dataset"] is False
    assert result["validation"]["valid"] is True
    assert "no external lookup" in " ".join(result["notes"]).lower()


# T-017 - Indicator search (service + API)
def test_T017_indicator_search_api(client):
    resp = client.get("/api/indicators/search?q=198.51.100.25")
    assert resp.status_code == 200
    data = resp.json()
    assert data["known_in_demo_dataset"] is True
    assert data["indicator_type"] == "ipv4"
    assert data["risk"] == 78
    assert data["severity"] == "HIGH"
    assert data["confidence"] == 85
    assert data["status"] == "MONITORING"
    assert "Phishing" in data["associated_categories"]
    assert data["first_seen"] and data["last_seen"]
    assert len(data["related_threats"]) >= 2
    assert "Database lookup only" in data["safety_notice"]


def test_T017b_indicator_search_rejects_invalid(client):
    resp = client.get("/api/indicators/search?q=definitely not an indicator")
    assert resp.status_code == 400
    assert "validation" in resp.json()["detail"]


# T-018 - Threat correlation
def test_T018_threat_correlation(db_conn):
    result = correlate_threats(db_conn, "THR-2026-001")
    cluster = result["cluster"]
    assert cluster is not None
    assert cluster["cluster_id"] == "SYN-CAMP-2026-001"
    assert cluster["member_count"] >= 3
    assert "198.51.100.25" in cluster["shared_indicators"]
    assert cluster["correlation_basis"], "basis must explain WHY records grouped"
    # attribution honesty is mandatory
    assert "does NOT prove attribution" in result["attribution_note"]


def test_T018b_correlation_summary(db_conn):
    summary = correlate_threats(db_conn)
    assert summary["cluster_count"] > 50
    assert "does NOT prove attribution" in summary["attribution_note"]


# T-019 - Duplicate observation handling
def test_T019_duplicate_observation(db_conn):
    payload = {
        "threat_name": "Duplicate Observation Test",
        "threat_category": "Phishing",
        "indicator_type": "DOMAIN",
        "indicator_value": "login-check.invalid",   # already recorded today
        "severity": "HIGH",
        "confidence_score": 85,
        "source_name": "Security Vendor",
    }
    # first sighting creates a fresh record (last seen NOW)
    first = create_threat(db_conn, payload)
    assert first["created"] is True
    before = db_conn.execute(
        "SELECT COUNT(*) FROM threats WHERE indicator_value = ?",
        ("login-check.invalid",)).fetchone()[0]
    # immediate re-observation of the SAME indicator+category is a duplicate
    result = create_threat(db_conn, payload)
    assert result["duplicate_observation"] is True
    assert result["created"] is False
    after = db_conn.execute(
        "SELECT COUNT(*) FROM threats WHERE indicator_value = ?",
        ("login-check.invalid",)).fetchone()[0]
    assert after == before, "duplicate must NOT create a new threat record"
    # observation count increased on the existing record
    row = db_conn.execute(
        "SELECT observation_count FROM threats WHERE threat_id = ?",
        (result["threat"]["threat_id"],)).fetchone()
    assert row["observation_count"] >= 2
    # a timeline OBSERVATION event documents the merge
    events = db_conn.execute(
        "SELECT COUNT(*) FROM timeline_events WHERE threat_id = ? "
        "AND event_type = 'OBSERVATION'",
        (result["threat"]["threat_id"],)).fetchone()[0]
    assert events >= 1, "duplicate merge must be documented on the timeline"
    merge_text = db_conn.execute(
        "SELECT description FROM timeline_events WHERE threat_id = ? "
        "AND event_type = 'OBSERVATION' ORDER BY event_id DESC LIMIT 1",
        (result["threat"]["threat_id"],)).fetchone()[0]
    assert "Duplicate observation" in merge_text
