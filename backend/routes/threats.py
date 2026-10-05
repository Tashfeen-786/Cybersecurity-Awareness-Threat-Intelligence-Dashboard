"""
Threat routes - the threat CRUD API.

    GET  /api/threats             public   list/filter/sort/paginate
    GET  /api/threats/{id}        public*  full detail (*analyst notes are
                                          masked unless authenticated)
    POST /api/threats             analyst  create (validated + IOC-validated;
                                          duplicate observations are merged)
    PUT  /api/threats/{id}        analyst  update (audited)

All write operations require the X-API-Key header (RBAC) and are audited.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from database import get_connection
from models.schemas import NoteCreate, ThreatCreate, ThreatUpdate
from services import security
from services import threat_service

router = APIRouter(prefix="/api/threats", tags=["threats"])


def _db():
    with get_connection() as conn:
        yield conn


@router.get("", summary="List threats with filters, sorting and pagination")
def list_threats(
    severity: Optional[str] = Query(None, description="INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL"),
    category: Optional[str] = Query(None),
    indicator_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    min_risk: Optional[int] = Query(None, ge=0, le=100),
    max_risk: Optional[int] = Query(None, ge=0, le=100),
    min_confidence: Optional[int] = Query(None, ge=0, le=100),
    date_from: Optional[str] = Query(None, description="YYYY-MM-DD"),
    date_to: Optional[str] = Query(None, description="YYYY-MM-DD"),
    q: Optional[str] = Query(None, max_length=200, description="text search"),
    sort: str = Query("newest", description="newest|oldest|risk|confidence|observed"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    db=Depends(_db),
):
    # Validate enum-like filters (input validation requirement)
    if severity and severity.upper() not in threat_service.SEVERITY_ORDER:
        raise HTTPException(400, detail=f"Invalid severity. Allowed: "
                                        f"{threat_service.SEVERITY_ORDER}")
    if status and status.upper() not in {"NEW", "UNDER_REVIEW", "MONITORING",
                                         "CLOSED", "FALSE_POSITIVE"}:
        raise HTTPException(400, detail="Invalid status filter")
    if sort not in threat_service.SORT_OPTIONS:
        raise HTTPException(400, detail=f"Invalid sort. Allowed: "
                                        f"{sorted(threat_service.SORT_OPTIONS)}")
    result = threat_service.list_threats(
        db, filters={"severity": severity, "category": category,
                     "indicator_type": indicator_type, "status": status,
                     "min_risk": min_risk, "max_risk": max_risk,
                     "min_confidence": min_confidence, "date_from": date_from,
                     "date_to": date_to, "q": q},
        sort=sort, page=page, page_size=page_size)
    result["data_notice"] = ("All records are SYNTHETIC / DEMO ONLY - "
                             "defensive cybersecurity education data.")
    return result


@router.get("/{threat_id}", summary="Threat detail (SOC investigation view)")
def get_threat(threat_id: str, request: Request, db=Depends(_db)):
    threat = threat_service.get_threat(db, threat_id)
    if threat is None:
        raise HTTPException(404, detail=f"Threat '{threat_id}' not found")

    # --- protected content: analyst notes masked without authentication ---
    key = request.headers.get("x-api-key")
    role = None
    if key:
        from services.security import AuthContext
        from config import get_role_for_api_key
        role = get_role_for_api_key(key)
    if role is not None:
        notes = [dict(n) for n in db.execute(
            "SELECT note, author_role, created_at FROM analyst_notes "
            "WHERE threat_id = ? ORDER BY created_at DESC",
            (threat_id,)).fetchall()]
        notes_access = "granted"
    else:
        notes = [{"note": "[Analyst notes are protected - authenticate with "
                          "an API key (X-API-Key header) to view them.]"}]
        notes_access = "authentication_required"

    # related indicators (correlation cluster)
    from services.correlation_engine import correlate_threats
    correlation = correlate_threats(db, threat_id)

    # related alerts
    alerts = [dict(a) for a in db.execute(
        "SELECT alert_id, alert_type, severity, risk_score, status, "
        "observation_count, description FROM alerts WHERE threat_id = ? "
        "ORDER BY created_at DESC", (threat_id,)).fetchall()]

    # ATT&CK mapping
    mappings = [dict(m) for m in db.execute(
        "SELECT tactic, technique, technique_id, justification "
        "FROM attack_mappings WHERE threat_id = ?", (threat_id,)).fetchall()]

    # timeline
    timeline = threat_service.get_timeline(db, threat_id)

    # CVE association
    cve = None
    if threat.get("cve_id"):
        row = db.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?",
                         (threat["cve_id"],)).fetchone()
        if row:
            cve = dict(row)

    # risk + confidence explainability (recomputed from the dataset's
    # generation reference date so scores stay deterministic)
    from services.risk_engine import (calculate_confidence,
                                      calculate_threat_risk)
    source = db.execute("SELECT reliability FROM sources WHERE source_id = ?",
                        (threat["source_id"],)).fetchone() if threat.get("source_id") else None
    reliability = source["reliability"] if source else "D"
    generated_at = db.execute(
        "SELECT value FROM meta WHERE key = 'dataset_generated_at'"
    ).fetchone()
    reference = generated_at["value"] if generated_at else None

    risk_detail = calculate_threat_risk(
        severity=threat["severity"], confidence=threat["confidence_score"],
        last_seen=threat["last_seen"],
        observation_count=threat["observation_count"],
        source_reliability=reliability,
        context_flags={
            "correlated_cluster": bool(correlation.get("cluster")),
            "related_indicator": len(
                (correlation.get("cluster") or {}).get("shared_indicators",
                                                       [])) > 1,
        },
        reference_now=reference)

    return {
        **threat,
        "source_reliability": f"{reliability} - " + {
            "A": "Highly Reliable", "B": "Usually Reliable",
            "C": "Fairly Reliable", "D": "Reliability Unknown"}[reliability],
        "analyst_notes": notes,
        "notes_access": notes_access,
        "related_indicators": correlation.get("cluster", {}).get(
            "shared_indicators", []) if correlation.get("cluster") else [],
        "related_threats": correlation.get("cluster", {}).get(
            "members", []) if correlation.get("cluster") else [],
        "weak_links": correlation.get("weak_links", []),
        "related_alerts": alerts,
        "attack_mapping": mappings or [{
            "tactic": None, "technique": None, "technique_id": None,
            "justification": "Insufficient behavioural context for ATT&CK "
                             "mapping - mapping is omitted rather than guessed."}],
        "cve_association": cve,
        "timeline": timeline,
        "risk_breakdown": risk_detail["breakdown"],
        "risk_interpretation": risk_detail["interpretation_note"],
        "correlation_note": correlation.get("attribution_note"),
        "recommended_defensive_actions": threat_service.recommended_actions(
            threat["threat_category"]),
    }


@router.post("", status_code=201,
             summary="Create a threat record (analyst role required)")
def create_threat(payload: ThreatCreate, request: Request,
                  db=Depends(_db),
                  auth=Depends(security.require_analyst)):
    try:
        result = threat_service.create_threat(db, payload.model_dump(),
                                              author=auth.actor)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc))
    security.audit(db, auth.actor, "CREATE_THREAT",
                   result["threat"]["threat_id"],
                   f"duplicate_observation={result['duplicate_observation']}",
                   request)
    return result


@router.put("/{threat_id}",
            summary="Update a threat record (analyst role required)")
def update_threat(threat_id: str, payload: ThreatUpdate, request: Request,
                  db=Depends(_db),
                  auth=Depends(security.require_analyst)):
    if threat_service.get_threat(db, threat_id) is None:
        raise HTTPException(404, detail=f"Threat '{threat_id}' not found")
    try:
        updated = threat_service.update_threat(db, threat_id,
                                               payload.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc))
    security.audit(db, auth.actor, "UPDATE_THREAT", threat_id,
                   str(payload.model_dump(exclude_none=True)), request)
    return updated


@router.post("/{threat_id}/notes", status_code=201,
             summary="Add an analyst note (analyst role required)")
def add_note(threat_id: str, payload: NoteCreate, request: Request,
             db=Depends(_db), auth=Depends(security.require_analyst)):
    if threat_service.get_threat(db, threat_id) is None:
        raise HTTPException(404, detail=f"Threat '{threat_id}' not found")
    from utils.helpers import iso, sanitize_text, utc_now
    db.execute(
        "INSERT INTO analyst_notes (threat_id, note, author_role, created_at) "
        "VALUES (?,?,?,?)",
        (threat_id, sanitize_text(payload.note, 2000), auth.role,
         iso(utc_now())))
    security.audit(db, auth.actor, "ADD_NOTE", threat_id,
                   f"note_length={len(payload.note)}", request)
    notes = [dict(n) for n in db.execute(
        "SELECT note, author_role, created_at FROM analyst_notes "
        "WHERE threat_id = ? ORDER BY created_at DESC",
        (threat_id,)).fetchall()]
    return {"threat_id": threat_id, "notes": notes}
