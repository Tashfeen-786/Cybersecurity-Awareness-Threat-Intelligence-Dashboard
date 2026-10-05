"""
Risk, confidence, source-reliability and threat-creation tests
(scenarios 12-15 from the project brief).
"""
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from services.risk_engine import (  # noqa: E402
    calculate_confidence, calculate_threat_risk, classify_risk,
    observation_frequency_factor, recency_factor, severity_factor,
    source_reliability_factor)
from utils.helpers import utc_now  # noqa: E402


# T-012 - Threat creation (service level; API covered in test_api_validation)
def test_T012_threat_creation(db_conn):
    from services.threat_service import create_threat
    payload = {
        "threat_name": "Unit Test Phishing Observation",
        "threat_category": "Phishing",
        "indicator_type": "DOMAIN",
        "indicator_value": "unit-test-login.invalid",
        "severity": "MEDIUM",
        "confidence_score": 60,
        "description": "created by automated test",
        "source_name": "Internal SOC",
    }
    result = create_threat(db_conn, payload)
    assert result["created"] is True
    threat = result["threat"]
    assert threat["threat_id"].startswith("THR-")
    assert threat["status"] == "NEW"
    assert threat["indicator_value"] == "unit-test-login.invalid"
    row = db_conn.execute("SELECT COUNT(*) FROM indicators WHERE threat_id = ?",
                          (threat["threat_id"],)).fetchone()
    assert row[0] == 1  # indicator row created too


def test_T012b_threat_creation_rejects_invalid_indicator(db_conn):
    from services.threat_service import create_threat
    import pytest
    payload = {
        "threat_name": "Bad indicator test",
        "threat_category": "Phishing",
        "indicator_type": "DOMAIN",
        "indicator_value": "this is not a domain!",
        "severity": "LOW",
        "confidence_score": 40,
    }
    with pytest.raises(ValueError):
        create_threat(db_conn, payload)


# T-013 - Risk calculation (deterministic + explainable + demo record = 78)
def test_T013_risk_calculation_deterministic():
    now = utc_now()
    result = calculate_threat_risk(
        severity="HIGH", confidence=85,
        last_seen=now - timedelta(days=15), observation_count=3,
        source_reliability="B",
        context_flags={"correlated_cluster": True, "related_indicator": True},
        reference_now=now)
    assert result["risk_score"] == 78, "demonstration scenario must score 78"
    assert result["classification"] == "HIGH"
    # explainability: six weighted factors returned
    assert len(result["breakdown"]) == 6
    assert {f["factor"] for f in result["breakdown"]} == {
        "Severity", "Confidence", "Recency", "Observation Frequency",
        "Source Reliability", "Context / Correlation"}
    total = sum(f["contribution"] for f in result["breakdown"])
    assert abs(total - 78.0) < 0.01


def test_T013b_risk_bands():
    assert classify_risk(10) == "INFORMATIONAL"
    assert classify_risk(21) == "LOW"
    assert classify_risk(40) == "LOW"
    assert classify_risk(41) == "MEDIUM"
    assert classify_risk(61) == "HIGH"
    assert classify_risk(81) == "CRITICAL"
    assert classify_risk(100) == "CRITICAL"


def test_T013c_factor_monotonicity():
    """Higher severity / more recent / better source => higher factor score."""
    assert severity_factor("CRITICAL") > severity_factor("LOW")
    assert source_reliability_factor("A") > source_reliability_factor("D")
    assert observation_frequency_factor(5) > observation_frequency_factor(1)
    now = utc_now()
    assert recency_factor(now - timedelta(days=1), now) > \
        recency_factor(now - timedelta(days=400), now)


# T-014 - Confidence calculation
def test_T014_confidence_calculation():
    # Reliable source + corroboration + repetition -> high confidence
    strong = calculate_confidence(source_reliability="A",
                                  corroborating_sources=3,
                                  observation_count=5,
                                  last_seen=utc_now())
    assert strong["confidence_score"] == 100  # 85 + 10 + 5
    # Unknown source, single sighting -> low confidence
    weak = calculate_confidence(source_reliability="D",
                                corroborating_sources=1,
                                observation_count=1,
                                last_seen=utc_now())
    assert weak["confidence_score"] == 30
    # Stale intelligence loses confidence
    from datetime import datetime, timezone
    stale = calculate_confidence(
        source_reliability="B", corroborating_sources=1,
        observation_count=1,
        last_seen=datetime.now(timezone.utc) - timedelta(days=400))
    assert stale["confidence_score"] == 50  # 70 - 20 staleness (>365 days)
    # Demo record confidence is exactly 85
    demo = calculate_confidence(source_reliability="B",
                                corroborating_sources=3,
                                observation_count=3,
                                last_seen=utc_now())
    assert demo["confidence_score"] == 85


def test_T014b_risk_and_confidence_are_distinct_concepts():
    """Risk 90 / confidence 25 must be representable (weak evidence, big concern)."""
    result = calculate_threat_risk(
        severity="CRITICAL", confidence=25,
        last_seen=utc_now() - timedelta(days=2), observation_count=6,
        source_reliability="D",
        context_flags={"correlated_cluster": False, "related_indicator": False})
    assert result["risk_score"] > 60          # concerning...
    conf = calculate_confidence("D", 1, 1, utc_now() - timedelta(days=2))
    assert conf["confidence_score"] <= 30     # ...but weakly evidenced


# T-015 - Source reliability
def test_T015_source_reliability():
    grades = {r["reliability"]: r for r in db_source_rows()} if False else None
    # reliability grades A-D map monotonically to points
    points = [source_reliability_factor(g) for g in ["A", "B", "C", "D"]]
    assert points == [100, 80, 60, 40]
    assert source_reliability_factor("unknown") == 40  # unknown -> D


def db_source_rows():
    raise NotImplementedError  # placeholder never called (see test above)


def test_T015b_dataset_sources_have_reliability(db_conn):
    """Every source in the dataset carries an A-D reliability grade."""
    rows = db_conn.execute(
        "SELECT DISTINCT source_name, reliability FROM sources").fetchall()
    assert len(rows) >= 6
    for row in rows:
        assert row["reliability"] in ("A", "B", "C", "D")
    by_name = {r["source_name"]: r["reliability"] for r in rows}
    assert by_name["Internal SOC"] == "A"
    assert by_name["Unknown Source"] == "D"
