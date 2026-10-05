"""
Vulnerability routes - CVE awareness + contextual prioritization.

    GET /api/vulnerabilities            public  list/sort vulnerabilities
    GET /api/vulnerabilities/{cve_id}   public  detail + priority breakdown
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from database import get_connection
from services.vulnerability_service import recommended_actions

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


def _db():
    with get_connection() as conn:
        yield conn


@router.get("", summary="List synthetic vulnerabilities with contextual priority")
def list_vulnerabilities(
        severity: Optional[str] = Query(None),
        product_category: Optional[str] = Query(None),
        patch_available: Optional[bool] = Query(None),
        sort: str = Query("priority", description="priority|cvss|newest"),
        db=Depends(_db)):
    order = {"priority": "priority_score DESC",
             "cvss": "cvss_score DESC",
             "newest": "published_date DESC"}.get(sort)
    if order is None:
        raise HTTPException(400, detail="Invalid sort. Allowed: priority, "
                                        "cvss, newest")
    where, params = [], []
    if severity:
        where.append("severity = ?")
        params.append(severity.upper())
    if product_category:
        where.append("product_category = ?")
        params.append(product_category)
    if patch_available is not None:
        where.append("patch_available = ?")
        params.append(1 if patch_available else 0)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    rows = db.execute(
        f"SELECT * FROM vulnerabilities {where_sql} ORDER BY {order}",
        params).fetchall()
    items = [dict(r) for r in rows]
    from collections import Counter
    band_counts = Counter(i["priority_band"] for i in items)
    return {
        "total": len(items),
        "priority_band_counts": dict(band_counts),
        "prioritization_note": (
            "Prioritization uses CVSS + asset criticality + exposure + "
            "known exploitation evidence + business context. CVSS alone "
            "does not decide patch priority."),
        "items": items,
        "synthetic_notice": "All vulnerability records are SYNTHETIC / DEMO "
                            "ONLY. No exploitation instructions included.",
    }


@router.get("/{cve_id}", summary="Vulnerability detail with priority breakdown")
def get_vulnerability(cve_id: str, db=Depends(_db)):
    row = db.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?",
                     (cve_id.upper(),)).fetchone()
    if row is None:
        raise HTTPException(404, detail=f"{cve_id} not found in the "
                                        "synthetic vulnerability dataset")
    vuln = dict(row)
    from services.vulnerability_service import calculate_vulnerability_priority
    breakdown = calculate_vulnerability_priority(
        vuln["cvss_score"], vuln["asset_criticality"], vuln["exposure"],
        vuln["exploitation_status_demo"], vuln["business_context"],
        bool(vuln["patch_available"]))
    vuln["priority_breakdown"] = breakdown["breakdown"]
    vuln["priority_interpretation"] = breakdown["interpretation_note"]
    vuln["recommended_actions"] = recommended_actions(vuln)
    return vuln
