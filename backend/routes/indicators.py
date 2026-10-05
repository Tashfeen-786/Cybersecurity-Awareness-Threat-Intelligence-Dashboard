"""
Indicator routes - IOC validation and search.

    GET /api/indicators/validate?q=...   public  syntactic validation
    GET /api/indicators/search?q=...     public  DATABASE LOOKUP ONLY

SAFETY: search performs a local database lookup only. The application
NEVER connects to, resolves, visits or contacts any searched indicator.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from database import get_connection
from services import ioc_validator
from services.enrichment_engine import enrich_indicator

router = APIRouter(prefix="/api/indicators", tags=["indicators"])


def _db_dep():
    with get_connection() as conn:
        yield conn


@router.get("/validate", summary="Validate indicator syntax (is it VALID, not is it malicious)")
def validate(q: str = Query(..., min_length=1, max_length=2048)):
    result = ioc_validator.validate_indicator(q)
    result["note"] = ("Validation checks SYNTAX only. A syntactically valid "
                      "indicator is not automatically malicious, and no "
                      "network connection is ever made.")
    return result


@router.get("/search", summary="IOC search - local database lookup ONLY")
def search(q: str = Query(..., min_length=1, max_length=2048,
                          description="IP / domain / URL / hash / CVE"),
           db=Depends(_db_dep)):
    validation = ioc_validator.validate_indicator(q)
    if not validation["valid"]:
        raise HTTPException(
            400,
            detail={"message": "Indicator failed syntactic validation.",
                    "validation": validation})

    enrichment = enrich_indicator(db, q)
    # Shape the response to the fields required by the project brief:
    # Indicator Type / Known in Demo Dataset / Risk / Severity / Confidence /
    # Associated Category / First Seen / Last Seen / Status / Related
    # Threats / Related Alerts / Analyst Notes
    record = (enrichment["records"][0]
              if enrichment["records"] else None)
    return {
        "query": q,
        "indicator_type": enrichment["indicator_type"],
        "coarse_type": enrichment["coarse_type"],
        "validation_notes": validation["validation_notes"],
        "known_in_demo_dataset": enrichment["known_in_demo_dataset"],
        "risk": enrichment["risk"],
        "risk_range": enrichment["risk_range"],
        "severity": enrichment["severity"],
        "confidence": enrichment["confidence"],
        "confidence_range": enrichment["confidence_range"],
        "associated_categories": enrichment["associated_categories"],
        "category_context": (
            f"{enrichment['associated_categories'][0]} infrastructure "
            f"(synthetic)" if enrichment["associated_categories"] else None),
        "first_seen": enrichment["summary"]["first_seen"],
        "last_seen": enrichment["summary"]["last_seen"],
        "status": record["status"] if record else None,
        "observation_count": enrichment["summary"]["observation_count"],
        "distinct_sources": enrichment["summary"].get("distinct_sources", []),
        "related_threats": enrichment["records"],
        "related_alerts": enrichment["related_alerts"],
        "related_indicators": enrichment["related_indicators"],
        "analyst_notes": enrichment["analyst_notes"],
        "mitre_mapping": enrichment["mitre_mapping"],
        "safety_notice": (
            "Database lookup only. This application NEVER contacts, "
            "resolves or visits indicators. An IOC match is evidence for "
            "investigation - not automatic confirmation of compromise."),
        "synthetic_label": "SYNTHETIC / DEMO ONLY",
    }


def _db_dep():
    with get_connection() as conn:
        yield conn
