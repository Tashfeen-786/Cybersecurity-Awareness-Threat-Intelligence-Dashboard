"""
Threat Enrichment Engine
========================

``enrich_indicator()`` adds local analytical context to a raw indicator:

    * indicator type (validated)
    * first seen / last seen
    * associated threat categories
    * confidence / severity / risk score
    * related alerts
    * related indicators (correlation cluster)
    * MITRE ATT&CK mapping where justified
    * analyst notes

100% OFFLINE: enrichment uses ONLY the local synthetic database.
There are no API keys, no external feeds and no outbound connections.
Optional future integrations (authorized feeds, STIX/TAXII, SIEM lookups)
are documented in docs/future_improvements.md - never implemented here,
because this project must never contact an indicator automatically.

An IOC match is EVIDENCE FOR INVESTIGATION, never automatic proof of
compromise.
"""
from __future__ import annotations

from typing import Dict

from services import ioc_validator


def enrich_indicator(db, raw_value: str) -> Dict:
    """
    Enrich an indicator from local data.

    Returns:
        {
          "query": ...,
          "validation": {...},          # from ioc_validator
          "known_in_demo_dataset": bool,
          "indicator_type": ...,        # fine-grained validated type
          "coarse_type": ...,           # dataset category
          "summary": {...},             # first/last seen, counts
          "records": [...],             # matching threat records
          "associated_categories": [...],
          "risk": max risk, "severity": worst severity,
          "confidence": max confidence,
          "related_alerts": [...],
          "related_indicators": [...],
          "mitre_mapping": [...],
          "analyst_notes": [...],
          "safety_note": "...",
          "notes": [...]
        }
    """
    validation = ioc_validator.validate_indicator(raw_value)
    normalized = validation["normalized_value"]

    result = {
        "query": raw_value,
        "validation": validation,
        "known_in_demo_dataset": False,
        "indicator_type": validation["indicator_type"],
        "coarse_type": ioc_validator.coarse_type(validation["indicator_type"]),
        "summary": {"first_seen": None, "last_seen": None,
                    "record_count": 0, "observation_count": 0},
        "records": [],
        "associated_categories": [],
        "risk": None,
        "severity": None,
        "confidence": None,
        "related_alerts": [],
        "related_indicators": [],
        "mitre_mapping": [],
        "analyst_notes": [],
        "safety_note": (
            "Enrichment used LOCAL synthetic data only. The indicator was "
            "never contacted, resolved, visited or submitted to any external "
            "service. An IOC match is evidence for investigation - not "
            "automatic confirmation of compromise."),
    }

    if not validation["valid"]:
        result["notes"] = ["Indicator failed validation - no lookup performed."]
        return result

    # --- database lookup (exact value, then domain-part for e-mails) ------
    rows = db.execute(
        "SELECT * FROM indicators WHERE indicator_value = ? "
        "ORDER BY first_seen", (normalized,)).fetchall()
    threat_ids = [r["threat_id"] for r in rows]

    if not threat_ids:
        result["notes"] = [
            "Indicator is valid but not present in the local demo dataset.",
            "No external lookup is performed - this application is fully "
            "offline by design.",
        ]
        return result

    placeholders = ",".join("?" * len(threat_ids))
    threats = db.execute(
        f"SELECT * FROM threats WHERE threat_id IN ({placeholders}) "
        "ORDER BY first_seen ASC, threat_id ASC", threat_ids).fetchall()

    # Representative record = the EARLIEST observation of this indicator.
    # Corroborating records may score differently; the honest range is
    # reported alongside (risk_range / confidence_range).
    primary = threats[0]

    result["known_in_demo_dataset"] = True
    result["records"] = [{
        "threat_id": t["threat_id"], "threat_name": t["threat_name"],
        "category": t["threat_category"], "severity": t["severity"],
        "risk_score": t["risk_score"],
        "confidence_score": t["confidence_score"], "status": t["status"],
        "first_seen": t["first_seen"], "last_seen": t["last_seen"],
        "source_name": t["source_name"], "source_id": t["source_id"],
    } for t in threats]

    result["associated_categories"] = sorted({
        t["threat_category"] for t in threats})
    result["risk"] = primary["risk_score"]
    result["risk_range"] = {"min": min(t["risk_score"] for t in threats),
                            "max": max(t["risk_score"] for t in threats)}
    severity_order = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    result["severity"] = max((t["severity"] for t in threats),
                             key=lambda s: severity_order.index(s))
    result["confidence"] = primary["confidence_score"]
    result["confidence_range"] = {
        "min": min(t["confidence_score"] for t in threats),
        "max": max(t["confidence_score"] for t in threats)}

    result["summary"] = {
        "first_seen": min(t["first_seen"] for t in threats),
        "last_seen": max(t["last_seen"] for t in threats),
        "record_count": len(threats),
        "observation_count": sum(t["observation_count"] for t in threats),
        "distinct_sources": sorted({t["source_name"] for t in threats}),
        "primary_record": {
            "threat_id": primary["threat_id"],
            "risk_score": primary["risk_score"],
            "confidence_score": primary["confidence_score"],
            "status": primary["status"],
        },
    }

    # --- related alerts ----------------------------------------------------
    alerts = db.execute(
        f"SELECT * FROM alerts WHERE threat_id IN ({placeholders}) "
        "ORDER BY created_at DESC LIMIT 10", threat_ids).fetchall()
    result["related_alerts"] = [{
        "alert_id": a["alert_id"], "alert_type": a["alert_type"],
        "severity": a["severity"], "status": a["status"],
        "observation_count": a["observation_count"],
    } for a in alerts]

    # --- related indicators (correlation cluster members) ------------------
    campaign_ids = {t["campaign_id"] for t in threats if t["campaign_id"]}
    related = []
    seen_values = {normalized}
    if campaign_ids:
        q = ("SELECT DISTINCT indicator_value, indicator_type, threat_id "
             "FROM indicators WHERE threat_id IN "
             f"(SELECT threat_id FROM threats WHERE campaign_id IN "
             f"({','.join('?' * len(campaign_ids))}))")
        for r in db.execute(q, tuple(campaign_ids)).fetchall():
            if r["indicator_value"] not in seen_values:
                related.append({"indicator_value": r["indicator_value"],
                                "indicator_type": r["indicator_type"],
                                "threat_id": r["threat_id"]})
                seen_values.add(r["indicator_value"])
    result["related_indicators"] = related

    # --- ATT&CK mapping where justified -------------------------------------
    mappings = db.execute(
        f"SELECT DISTINCT tactic, technique, technique_id, justification "
        f"FROM attack_mappings WHERE threat_id IN ({placeholders}) "
        "AND technique_id IS NOT NULL", threat_ids).fetchall()
    result["mitre_mapping"] = [{
        "tactic": m["tactic"], "technique": m["technique"],
        "technique_id": m["technique_id"],
        "justification": m["justification"],
    } for m in mappings]

    # --- analyst notes -------------------------------------------------------
    notes = db.execute(
        f"SELECT note, created_at, author_role FROM analyst_notes "
        f"WHERE threat_id IN ({placeholders}) ORDER BY created_at DESC",
        threat_ids).fetchall()
    result["analyst_notes"] = [{
        "note": n["note"], "created_at": n["created_at"],
        "author_role": n["author_role"]} for n in notes]

    result["notes"] = [
        "IOC match found in the local demo dataset. This is EVIDENCE for "
        "investigation, not automatic confirmation of compromise.",
    ]
    return result
