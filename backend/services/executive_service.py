"""
Executive Cybersecurity Summary Service
=======================================

Management-friendly, non-technical summary:
    * Threat landscape summary (plain language)
    * Critical/High threat counts
    * Top threat categories
    * Top vulnerability categories
    * Awareness score trend
    * Top awareness weaknesses
    * Recommended defensive priorities

Language is deliberately simple - no jargon without explanation.
"""
from __future__ import annotations

from typing import Dict, List

import config


def build_executive_summary(db) -> Dict:
    total = db.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    critical = db.execute(
        "SELECT COUNT(*) FROM threats WHERE severity = 'CRITICAL' "
        "AND status NOT IN ('CLOSED','FALSE_POSITIVE')").fetchone()[0]
    high = db.execute(
        "SELECT COUNT(*) FROM threats WHERE severity = 'HIGH' "
        "AND status NOT IN ('CLOSED','FALSE_POSITIVE')").fetchone()[0]
    open_investigations = db.execute(
        "SELECT COUNT(*) FROM threats WHERE status IN "
        "('NEW','UNDER_REVIEW')").fetchone()[0]
    monitoring = db.execute(
        "SELECT COUNT(*) FROM threats WHERE status = 'MONITORING'").fetchone()[0]
    false_positives = db.execute(
        "SELECT COUNT(*) FROM threats WHERE status = 'FALSE_POSITIVE'"
    ).fetchone()[0]

    top_categories = [dict(r) for r in db.execute(
        "SELECT threat_category AS category, COUNT(*) AS count FROM threats "
        "GROUP BY threat_category ORDER BY count DESC LIMIT 5").fetchall()]

    top_vuln_categories = [dict(r) for r in db.execute(
        "SELECT product_category AS category, COUNT(*) AS count, "
        "ROUND(AVG(priority_score),1) AS avg_priority FROM vulnerabilities "
        "GROUP BY product_category ORDER BY avg_priority DESC LIMIT 5"
    ).fetchall()]

    critical_vulns = db.execute(
        "SELECT COUNT(*) FROM vulnerabilities WHERE priority_band = 'CRITICAL'"
    ).fetchone()[0]
    unpatched = db.execute(
        "SELECT COUNT(*) FROM vulnerabilities WHERE patch_available = 0"
    ).fetchone()[0]

    # --- awareness stats (from quiz_service helpers, inline SQL here) ------
    from services.quiz_service import awareness_stats
    awareness = awareness_stats(db)

    new_alerts = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE status = 'NEW'").fetchone()[0]

    # --- plain-language narrative ------------------------------------------
    narrative = (
        f"The organisation's synthetic threat-intelligence demo feed currently "
        f"tracks {total} threat records. {critical} are classified CRITICAL "
        f"and {high} HIGH severity and remain active (not closed or marked as "
        f"false positives). {open_investigations} records await triage and "
        f"{monitoring} are under active monitoring. "
        f"The most common threat category is "
        f"{top_categories[0]['category'] if top_categories else 'n/a'}, which "
        f"usually indicates that user-facing attacks (like phishing) deserve "
        f"continued attention. "
    )
    if critical_vulns:
        narrative += (f"{critical_vuln_categories_line(top_vuln_categories)} "
                      f"{critical_vulns} vulnerabilities have CRITICAL "
                      f"contextual priority and should be patched or "
                      f"mitigated first. ")
    if awareness["attempts"]:
        narrative += (f"Awareness training participation shows "
                      f"{awareness['attempts']} quiz attempt(s) with an "
                      f"average score of {awareness['average_score']}%. ")
    narrative += ("All figures come from SYNTHETIC demonstration data and "
                  "illustrate how real executive reporting would look.")

    priorities = _recommended_priorities(
        top_categories, critical_vulns, unpatched, new_alerts, awareness)

    return {
        "generated_for": "Executive / non-technical stakeholders",
        "data_notice": ("All data is SYNTHETIC / DEMO ONLY - generated for "
                        "defensive cybersecurity education."),
        "threat_landscape_summary": narrative,
        "counts": {
            "total_threat_records": total,
            "critical_active": critical,
            "high_active": high,
            "open_investigations": open_investigations,
            "monitoring": monitoring,
            "false_positives": false_positives,
            "new_alerts": new_alerts,
        },
        "top_threat_categories": top_categories,
        "top_vulnerability_categories": top_vuln_categories,
        "vulnerability_summary": {
            "critical_priority": critical_vulns,
            "without_vendor_patch": unpatched,
        },
        "awareness": awareness,
        "recommended_defensive_priorities": priorities,
        "reading_guide": {
            "risk_vs_confidence": (
                "Risk = how concerning something may be. Confidence = how "
                "strong the evidence is. They are different."),
            "ioc_disclaimer": (
                "An indicator match is a clue for investigation - not proof "
                "of a breach."),
        },
    }


def critical_vuln_categories_line(cats: List[Dict]) -> str:
    if not cats:
        return ""
    names = ", ".join(c["category"] for c in cats[:3])
    return f"The most exposed product categories are {names}."


def _recommended_priorities(top_categories, critical_vulns, unpatched,
                            new_alerts, awareness) -> List[Dict]:
    """Rule-based, plain-language defensive priorities."""
    priorities = []
    if critical_vulns:
        priorities.append({
            "priority": "P1",
            "title": "Patch or mitigate CRITICAL-priority vulnerabilities",
            "detail": (f"{critical_vulns} vulnerabilities combine high "
                       "severity with critical business context. Schedule "
                       "emergency patching or compensating controls."),
        })
    top_cat = top_categories[0]["category"] if top_categories else None
    if top_cat in ("Phishing", "Social Engineering", "Credential Theft",
                   "Account Security"):
        priorities.append({
            "priority": "P2",
            "title": "Strengthen phishing defences and user awareness",
            "detail": (f"{top_cat} is the most common threat category in the "
                       "feed. Combine email security controls with the "
                       "Awareness Center phishing training."),
        })
    if unpatched:
        priorities.append({
            "priority": "P3",
            "title": "Track vulnerabilities without vendor patches",
            "detail": (f"{unpatched} vulnerabilities have no vendor patch "
                       "yet - apply compensating controls (segmentation, "
                       "WAF rules, feature disablement)."),
        })
    if awareness.get("weakest_categories"):
        weakest = awareness["weakest_categories"][0]
        priorities.append({
            "priority": "P4",
            "title": "Target awareness training at the weakest topic",
            "detail": (f"Quiz results show '{weakest['category']}' averaging "
                       f"{weakest['average_score']}%. Recommend the matching "
                       "Awareness Center module."),
        })
    priorities.append({
        "priority": "P5",
        "title": "Maintain monitoring and triage discipline",
        "detail": ("Keep the SOC queue healthy: triage NEW alerts promptly, "
                   "document findings, and close false positives to reduce "
                   "noise."),
    })
    return priorities
