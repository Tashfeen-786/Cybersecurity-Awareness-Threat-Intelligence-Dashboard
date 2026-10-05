"""
Alert engine, alert correlation, alert workflow, analyst notes and ATT&CK
mapping tests (scenarios 20-24 from the project brief).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from services.alert_engine import (  # noqa: E402
    correlate_alerts, generate_threat_alert, status_is_valid)
from services.attack_mapper import (  # noqa: E402
    TECHNIQUE_INDEX, get_mapping_for_record)


def _threat(db_conn, threat_id="THR-2026-001"):
    return db_conn.execute("SELECT * FROM threats WHERE threat_id = ?",
                           (threat_id,)).fetchone()


# T-020 - Alert generation
def test_T020_alert_generation(db_conn):
    # high-risk demo record triggers an alert
    alert = generate_threat_alert(_threat(db_conn), context={"cluster_size": 3})
    assert alert is not None
    assert alert["alert_type"] == "HIGH_RISK"
    assert alert["severity"] == "HIGH"
    assert alert["threat_id"] == "THR-2026-001"
    assert alert["status"] == "NEW"

    # a low-risk, low-confidence record must NOT trigger the risk rules
    from utils.helpers import utc_now
    low = {"threat_id": "THR-TEST-LOW", "risk_score": 30, "confidence_score": 30,
           "observation_count": 1, "severity": "LOW"}
    assert generate_threat_alert(low, context={}) is None


def test_T020b_dataset_alerts_generated(db_conn):
    count = db_conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    assert count > 100, "alert engine must have run across the dataset"
    types = {r[0] for r in db_conn.execute(
        "SELECT DISTINCT alert_type FROM alerts")}
    assert "HIGH_RISK" in types
    assert "REPEATED_OBSERVATION" in types or "CORRELATED_INDICATORS" in types


# T-021 - Alert correlation (anti alert-fatigue)
def test_T021_alert_correlation_100_observations():
    """100 observations of the same indicator in 5 minutes -> ONE alert."""
    alerts = []
    for _ in range(100):
        alerts.append({
            "threat_id": "THR-2026-001",
            "timestamp": "2026-09-14T19:05:00+00:00",
            "alert_type": "REPEATED_OBSERVATION",
            "severity": "HIGH", "risk_score": 78, "confidence_score": 85,
            "description": "synthetic observation", "status": "NEW",
            "observation_count": 1,
            "indicator_value": "login-check.invalid",
        })
    result = correlate_alerts(alerts)
    assert len(result["alerts"]) == 1, "must merge into a single correlated alert"
    assert result["alerts"][0]["observation_count"] == 100
    assert result["merged_count"] == 99
    assert "alert fatigue" in result["explanation"].lower()


def test_T021b_distinct_indicators_not_merged():
    a = {"indicator_value": "a.invalid", "alert_type": "HIGH_RISK",
         "severity": "HIGH", "risk_score": 80, "confidence_score": 90,
         "timestamp": "2026-09-14T19:05:00+00:00", "observation_count": 1}
    b = {"indicator_value": "b.invalid", "alert_type": "HIGH_RISK",
         "severity": "HIGH", "risk_score": 80, "confidence_score": 90,
         "timestamp": "2026-09-14T19:06:00+00:00", "observation_count": 1}
    result = correlate_alerts([a, b])
    assert len(result["alerts"]) == 2, "different indicators stay separate"


# T-022 - Alert status update (API, analyst role)
def test_T022_alert_status_update(client):
    alert_id = client.get("/api/alerts").json()["items"][0]["alert_id"]

    # unauthenticated -> 401
    resp = client.put(f"/api/alerts/{alert_id}/status", json={"status": "RESOLVED"})
    assert resp.status_code == 401

    # analyst -> allowed + audited
    updated = client.put(f"/api/alerts/{alert_id}/status",
                         json={"status": "RESOLVED"},
                         headers={"X-API-Key": "demo-analyst-key"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "RESOLVED"

    # invalid status -> 422
    resp = client.put(f"/api/alerts/{alert_id}/status",
                      json={"status": "HACKED"},
                      headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 422

    # timeline documentation on the linked threat
    detail = client.get(f"/api/threats/{updated.json()['threat_id']}").json()
    assert any("alert" in e["description"].lower() for e in detail["timeline"])

    assert status_is_valid("NEW") and not status_is_valid("BAD")


# T-023 - Analyst notes (API, analyst role, protected content)
def test_T023_analyst_notes(client):
    # unauthenticated detail -> notes masked
    detail = client.get("/api/threats/THR-2026-002").json()
    assert detail["notes_access"] == "authentication_required"
    assert "protected" in detail["analyst_notes"][0]["note"].lower()

    # unauthenticated POST -> 401
    resp = client.post("/api/threats/THR-2026-002/notes", json={"note": "nope"})
    assert resp.status_code == 401

    # analyst may add
    resp = client.post("/api/threats/THR-2026-002/notes",
                       json={"note": "Corroborated by three demo sources."},
                       headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 201
    assert any("Corroborated by three demo sources" in n["note"]
               for n in resp.json()["notes"])

    # authenticated read shows notes
    detail = client.get("/api/threats/THR-2026-002",
                        headers={"X-API-Key": "demo-viewer-key"}).json()
    assert detail["notes_access"] == "granted"
    assert detail["analyst_notes"]


# T-024 - ATT&CK mapping
def test_T024_attack_mapping(db_conn):
    # demo record maps to a real technique with justification
    rows = db_conn.execute(
        "SELECT * FROM attack_mappings WHERE threat_id = 'THR-2026-001'").fetchall()
    assert rows, "demo record must have a justified mapping"
    assert rows[0]["technique_id"] == "T1566.002"
    assert rows[0]["tactic"] == "Initial Access"
    assert rows[0]["justification"]

    # every technique_id used in the DB is a REAL ATT&CK ID (never invented)
    used = {r[0] for r in db_conn.execute(
        "SELECT DISTINCT technique_id FROM attack_mappings "
        "WHERE technique_id IS NOT NULL")}
    assert used, "dataset must contain mappings"
    assert used <= set(TECHNIQUE_INDEX.keys()), \
        "only real, curated ATT&CK technique IDs are allowed"

    # unmapped when context is insufficient
    unmapped = get_mapping_for_record("Phishing",
                                      "Generic indicator with no behavioural detail.")
    assert unmapped["technique_id"] is None
    assert "Insufficient" in unmapped["justification"]


def test_T024b_attack_api_summary(client):
    data = client.get("/api/attack/summary").json()
    assert data["mapped_threats"] > 500
    assert data["unmapped_threats"] > 100, "insufficient-context records stay unmapped"
    assert data["top_tactics"][0]["tactic"] == "Initial Access"
    assert "never invented" in data["mapping_policy"]
