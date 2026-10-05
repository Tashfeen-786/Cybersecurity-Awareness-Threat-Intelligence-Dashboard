"""
MITRE ATT&CK routes.

    GET /api/attack/summary                 public  tactics + technique frequency
    GET /api/attack/tactics/{tactic}        public  threats by tactic
    GET /api/attack/techniques/{tech_id}    public  threats mapped to a technique
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from database import get_connection
from services import attack_mapper

router = APIRouter(prefix="/api/attack", tags=["mitre-attack"])


def _db():
    with get_connection() as conn:
        yield conn


@router.get("/summary", summary="ATT&CK overview: top tactics + technique frequency")
def summary(db=Depends(_db)):
    tactics = [dict(r) for r in db.execute(
        "SELECT tactic, COUNT(*) AS count FROM attack_mappings "
        "WHERE technique_id IS NOT NULL GROUP BY tactic "
        "ORDER BY count DESC").fetchall()]
    techniques = [dict(r) for r in db.execute(
        "SELECT technique_id, technique, tactic, COUNT(*) AS count "
        "FROM attack_mappings WHERE technique_id IS NOT NULL "
        "GROUP BY technique_id ORDER BY count DESC").fetchall()]
    unmapped = db.execute(
        "SELECT COUNT(*) FROM threats WHERE threat_id NOT IN "
        "(SELECT threat_id FROM attack_mappings WHERE technique_id IS NOT NULL)"
    ).fetchone()[0]
    total = db.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    return {
        "top_tactics": tactics,
        "technique_frequency": techniques,
        "mapped_threats": total - unmapped,
        "unmapped_threats": unmapped,
        "mapping_policy": (
            "Records are mapped ONLY when sufficient behavioural context "
            "exists. When evidence is insufficient the record is left "
            "unmapped - technique IDs are never invented or guessed."),
        "concept_note": (
            "An IOC tells us WHAT artifact was observed. ATT&CK helps "
            "describe HOW behaviour may relate to adversary techniques."),
        "reference_tactics": attack_mapper.all_tactics(),
    }


@router.get("/tactics/{tactic}", summary="Threats grouped under a tactic")
def threats_by_tactic(tactic: str, db=Depends(_db)):
    rows = db.execute(
        "SELECT t.threat_id, t.threat_name, t.threat_category, "
        "t.indicator_type, t.indicator_value, t.severity, t.risk_score, "
        "t.confidence_score, t.status, a.technique_id, a.technique "
        "FROM attack_mappings a JOIN threats t ON t.threat_id = a.threat_id "
        "WHERE a.tactic = ? AND a.technique_id IS NOT NULL "
        "ORDER BY t.risk_score DESC", (tactic,)).fetchall()
    if not rows:
        raise HTTPException(404, detail=f"Tactic '{tactic}' has no mapped "
                                        "threat records (or does not exist).")
    return {"tactic": tactic, "count": len(rows), "threats": [dict(r) for r in rows]}


@router.get("/techniques/{technique_id}",
            summary="Threat records associated with a technique (clickable)")
def threats_by_technique(technique_id: str, db=Depends(_db)):
    technique_id = technique_id.upper()
    label = attack_mapper.technique_label(technique_id)
    rows = db.execute(
        "SELECT t.threat_id, t.threat_name, t.threat_category, "
        "t.indicator_type, t.indicator_value, t.severity, t.risk_score, "
        "t.confidence_score, t.status "
        "FROM attack_mappings a JOIN threats t ON t.threat_id = a.threat_id "
        "WHERE a.technique_id = ? ORDER BY t.risk_score DESC",
        (technique_id,)).fetchall()
    return {
        "technique_id": technique_id,
        "technique_label": label,
        "count": len(rows),
        "threats": [dict(r) for r in rows],
        "note": ("Association is based on justified behavioural context in "
                 "synthetic records. It does not prove the technique "
                 "executed on any real system."),
    }
