"""
Edge cases: empty dataset, API validation, database persistence
(scenarios 33-35 from the project brief).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import config  # noqa: E402
from database import get_connection  # noqa: E402
from services.dashboard_service import dashboard_stats, dashboard_trends  # noqa: E402


# T-033 - Empty dataset (no crash, sensible zeros)
def test_T033_empty_dataset(empty_db):
    with get_connection(empty_db) as conn:
        stats = dashboard_stats(conn)
        trends = dashboard_trends(conn)
    assert stats["cards"]["total_threat_records"] == 0
    assert stats["cards"]["critical_threats"] == 0
    assert stats["cards"]["average_confidence"] == 0
    assert all(v == [] for v in stats["charts"].values())
    assert trends["threats_over_time"] == []
    assert trends["risk_distribution"] == []


def test_T033b_empty_dataset_api(client, empty_db, monkeypatch):
    monkeypatch.setattr(config, "DATABASE_PATH", empty_db)
    resp = client.get("/api/dashboard/stats")
    assert resp.status_code == 200
    assert resp.json()["cards"]["total_threat_records"] == 0
    # threat detail on empty DB -> clean 404
    assert client.get("/api/threats/THR-0000-0000").status_code == 404
    # alert list on empty DB
    alerts = client.get("/api/alerts").json()
    assert alerts["total"] == 0 and alerts["items"] == []


# T-034 - API validation (payloads, types, enums)
def test_T034_api_validation(client):
    # missing required fields -> 422
    resp = client.post("/api/threats", json={"threat_name": "only a name"},
                       headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 422

    # invalid indicator -> 422 with helpful message
    resp = client.post("/api/threats", json={
        "threat_name": "Bad indicator", "threat_category": "Phishing",
        "indicator_type": "DOMAIN", "indicator_value": "not a domain!!",
        "severity": "LOW", "confidence_score": 50,
    }, headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 422
    assert "validation" in resp.json()["detail"].lower()

    # invalid category -> 422
    resp = client.post("/api/threats", json={
        "threat_name": "Bad category", "threat_category": "Nonsense",
        "indicator_type": "DOMAIN", "indicator_value": "ok.invalid",
        "severity": "LOW", "confidence_score": 50,
    }, headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 422

    # confidence out of range -> 422
    resp = client.post("/api/threats", json={
        "threat_name": "Bad confidence", "threat_category": "Phishing",
        "indicator_type": "DOMAIN", "indicator_value": "ok.invalid",
        "severity": "LOW", "confidence_score": 999,
    }, headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 422

    # unknown route -> 404, invalid query -> 400
    assert client.get("/api/nonexistent").status_code == 404
    assert client.get("/api/threats?sort=descending").status_code == 400

    # valid creation round-trip
    resp = client.post("/api/threats", json={
        "threat_name": "API Validation Test Record",
        "threat_category": "Network Threats",
        "indicator_type": "IP ADDRESS", "indicator_value": "203.0.113.77",
        "severity": "MEDIUM", "confidence_score": 65,
        "description": "created by test_T034", "source_name": "Internal SOC",
    }, headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 201
    threat_id = resp.json()["threat"]["threat_id"]
    assert client.get(f"/api/threats/{threat_id}").status_code == 200

    # PUT update with invalid status -> 422; valid status -> 200
    assert client.put(f"/api/threats/{threat_id}", json={"status": "BROKEN"},
                      headers={"X-API-Key": "demo-analyst-key"}).status_code == 422
    put = client.put(f"/api/threats/{threat_id}", json={"status": "UNDER_REVIEW"},
                     headers={"X-API-Key": "demo-analyst-key"})
    assert put.status_code == 200
    assert put.json()["status"] == "UNDER_REVIEW"


# T-035 - Database persistence
def test_T035_database_persistence(client, db_file):
    # create a record through the API
    resp = client.post("/api/threats", json={
        "threat_name": "Persistence Test Record",
        "threat_category": "Malware",
        "indicator_type": "FILE HASH",
        "indicator_value":
            "b7c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1",
        "severity": "HIGH", "confidence_score": 80,
        "source_name": "Internal SOC",
    }, headers={"X-API-Key": "demo-analyst-key"})
    assert resp.status_code == 201
    threat_id = resp.json()["threat"]["threat_id"]

    # open a FRESH connection directly to the file: data must still be there
    with get_connection(db_file) as conn:
        row = conn.execute("SELECT * FROM threats WHERE threat_id = ?",
                           (threat_id,)).fetchone()
        assert row is not None, "created threat must persist across connections"
        assert row["threat_name"] == "Persistence Test Record"
        assert row["severity"] == "HIGH"
        indicator = conn.execute(
            "SELECT * FROM indicators WHERE threat_id = ?", (threat_id,)
        ).fetchone()
        assert indicator is not None, "indicator row must persist too"
        timeline = conn.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE threat_id = ?",
            (threat_id,)).fetchone()[0]
        assert timeline >= 1

    # and the API still returns it (reads hit the same persisted file)
    assert client.get(f"/api/threats/{threat_id}").status_code == 200


def test_T035b_schema_integrity(db_conn):
    """Required tables, foreign keys and indexes exist."""
    tables = {r[0] for r in db_conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    required = {"threats", "indicators", "sources", "attack_mappings",
                "vulnerabilities", "alerts", "analyst_notes",
                "awareness_modules", "quiz_results"}
    assert required <= tables, f"missing tables: {required - tables}"
    indexes = {r[0] for r in db_conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")}
    assert len(indexes) >= 10, "documented indexes must exist"

    # foreign keys are enforced
    import sqlite3
    import pytest
    with pytest.raises(sqlite3.IntegrityError):
        db_conn.execute(
            "INSERT INTO indicators (threat_id, indicator_type, "
            "indicator_value) VALUES ('THR-DOES-NOT-EXIST', 'DOMAIN', 'x.invalid')")
