"""
Alert routes - SOC alert queue.

    GET /api/alerts                 public   list/filter alerts
    GET /api/alerts/{id}            public   alert investigation detail
    PUT /api/alerts/{id}/status     analyst  update status (audited)
    POST /api/alerts/correlate-demo analyst  demonstration of alert
                                            correlation (anti alert-fatigue)
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from database import get_connection
from models.schemas import AlertStatusUpdate
from services import security
from services.alert_engine import correlate_alerts
from utils.helpers import iso, utc_now

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _db():
    with get_connection() as conn:
        yield conn


@router.get("", summary="List alerts (SOC queue)")
def list_alerts(status: Optional[str] = Query(None),
                severity: Optional[str] = Query(None),
                alert_type: Optional[str] = Query(None),
                page: int = Query(1, ge=1),
                page_size: int = Query(25, ge=1, le=200),
                db=Depends(_db)):
    allowed_status = {"NEW", "INVESTIGATING", "MONITORING", "RESOLVED",
                      "FALSE_POSITIVE"}
    if status and status.upper() not in allowed_status:
        raise HTTPException(400, detail=f"Invalid status. Allowed: "
                                        f"{sorted(allowed_status)}")
    where, params = [], []
    if status:
        where.append("status = ?")
        params.append(status.upper())
    if severity:
        where.append("severity = ?")
        params.append(severity.upper())
    if alert_type:
        where.append("alert_type = ?")
        params.append(alert_type.upper())
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total = db.execute(f"SELECT COUNT(*) FROM alerts {where_sql}",
                       params).fetchone()[0]
    rows = db.execute(
        f"SELECT * FROM alerts {where_sql} "
        "ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
        "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
        "created_at DESC LIMIT ? OFFSET ?",
        (*params, page_size, (page - 1) * page_size)).fetchall()

    counts = {r["status"]: r["n"] for r in db.execute(
        "SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")}
    return {
        "total": total, "page": page, "page_size": page_size,
        "status_counts": counts,
        "alert_fatigue_note": (
            "Repeated observations of the same indicator are merged into a "
            "single correlated alert (see observation_count) to prevent "
            "alert fatigue in the SOC queue."),
        "items": [dict(r) for r in rows],
    }


@router.get("/{alert_id}", summary="Alert investigation detail")
def get_alert(alert_id: int, db=Depends(_db)):
    row = db.execute("SELECT * FROM alerts WHERE alert_id = ?",
                     (alert_id,)).fetchone()
    if row is None:
        raise HTTPException(404, detail=f"Alert {alert_id} not found")
    alert = dict(row)
    # Linked threat + cluster context for the investigation view
    threat = None
    cluster_note = None
    if alert["threat_id"]:
        t = db.execute("SELECT * FROM threats WHERE threat_id = ?",
                       (alert["threat_id"],)).fetchone()
        if t:
            threat = dict(t)
        from services.correlation_engine import correlate_threats
        correlation = correlate_threats(db, alert["threat_id"])
        cluster_note = (correlation.get("cluster") or {}).get(
            "correlation_basis", [])
    alert["linked_threat"] = threat
    alert["correlation_basis"] = cluster_note
    alert["attribution_note"] = ("Correlation indicates relationship/evidence. "
                                 "It does NOT prove attribution.")
    return alert


@router.put("/{alert_id}/status",
            summary="Update alert status (analyst role required)")
def update_status(alert_id: int, payload: AlertStatusUpdate,
                  request: Request, db=Depends(_db),
                  auth=Depends(security.require_analyst)):
    row = db.execute("SELECT * FROM alerts WHERE alert_id = ?",
                     (alert_id,)).fetchone()
    if row is None:
        raise HTTPException(404, detail=f"Alert {alert_id} not found")
    db.execute("UPDATE alerts SET status = ? WHERE alert_id = ?",
               (payload.status, alert_id))
    # Mirror lifecycle onto the threat timeline for documentation
    if row["threat_id"]:
        db.execute(
            "INSERT INTO timeline_events (threat_id, event_type, description,"
            " occurred_at) VALUES (?,'STATUS_CHANGE',?,?)",
            (row["threat_id"],
             f"Linked alert #{alert_id} status changed to {payload.status} "
             f"by {auth.actor}.", iso(utc_now())))
    security.audit(db, auth.actor, "ALERT_STATUS", f"alert:{alert_id}",
                   f"new_status={payload.status}", request)
    updated = db.execute("SELECT * FROM alerts WHERE alert_id = ?",
                         (alert_id,)).fetchone()
    return dict(updated)


@router.post("/correlate-demo",
             summary="Demonstrate alert correlation (100 observations -> 1 alert)")
def correlate_demo(observations: int = Query(100, ge=2, le=1000),
                   minutes: int = Query(5, ge=1, le=60),
                   db=Depends(_db),
                   auth=Depends(security.require_analyst)):
    """
    Educational demonstration of the anti-alert-fatigue rule required by
    the project brief: the same synthetic indicator observed N times
    within a short window produces ONE correlated alert with an
    observation count, not N separate analyst alerts.
    """
    demo_alerts = []
    for i in range(observations):
        demo_alerts.append({
            "threat_id": "THR-2026-001",
            "timestamp": f"2026-09-14T19:0{i % 10}:00+00:00",
            "alert_type": "REPEATED_OBSERVATION",
            "severity": "HIGH",
            "risk_score": 78,
            "confidence_score": 85,
            "description": "synthetic repeated observation",
            "status": "NEW",
            "observation_count": 1,
            "indicator_value": "login-check.invalid",
        })
    result = correlate_alerts(demo_alerts)
    return {
        "scenario": (f"Same indicator observed {observations} times in "
                     f"{minutes} minutes (synthetic demonstration)"),
        "alerts_created": len(result["alerts"]),
        "observation_count_on_alert": (
            result["alerts"][0]["observation_count"] if result["alerts"] else 0),
        "merged_count": result["merged_count"],
        "explanation": result["explanation"] + (
            " Alert fatigue is a real SOC problem: when analysts are flooded "
            "with duplicate alerts they start ignoring them, and genuine "
            "incidents get missed."),
    }
