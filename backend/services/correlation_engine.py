"""
Threat Correlation Engine
=========================

``correlate_threats()`` groups related observations into
RELATED THREAT CLUSTERS using, in priority order:

    1. Explicit campaign ID        (analyst/producer-assigned campaign)
    2. Shared indicator value      (same artifact observed repeatedly)
    3. Same category + overlapping observation window (30-day window)
       -> only suggested as a WEAK correlation requiring analyst review

CRITICAL INTELLIGENCE PRINCIPLE
    Correlation indicates a RELATIONSHIP or EVIDENCE LINK.
    It does NOT prove attribution, and it does NOT prove that the
    same adversary or campaign is responsible.

The engine is offline and deterministic: it works purely on the local
SQLite database. No external lookups are ever performed.
"""
from __future__ import annotations

import sqlite3
from typing import Dict, List, Optional

WINDOW_DAYS = 30          # observation window for weak (time/category) links
MIN_STRONG_CLUSTER = 2    # records needed to call a cluster "correlated"


def correlate_threats(db, threat_id: str = None,
                      include_weak: bool = True) -> Dict:
    """
    Build correlation clusters.

    With ``threat_id``: return the RELATED THREAT CLUSTER for that threat.
    Without: return a summary of all clusters (used by dashboards/tests).

    Response shape (single threat):
        {
          "threat_id": ...,
          "cluster": {
              "cluster_id": "SYN-CAMP-2026-001" | "indicator:<value>" | None,
              "correlation_basis": [...],     # why records were grouped
              "members": [ {threat summary}, ... ],
              "shared_indicators": [...],
              "distinct_sources": [...],
              "time_span": {"first": ..., "last": ...},
              "categories": [...],
              "observation_count_total": int
          },
          "weak_links": [ ... ],   # same category + time window, no direct link
          "attribution_note": "Correlation indicates relationship/evidence.
                               It does NOT prove attribution."
        }
    """
    if threat_id is not None:
        _ensure_row_factory(db)
        return _cluster_for_threat(db, threat_id, include_weak)
    _ensure_row_factory(db)
    return _all_clusters(db)


def _ensure_row_factory(db) -> None:
    """Guarantee dict-style row access regardless of caller connection."""
    if db is not None and getattr(db, "row_factory", None) is None:
        db.row_factory = sqlite3.Row


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _threat_row_to_summary(row) -> Dict:
    return {
        "threat_id": row["threat_id"],
        "threat_name": row["threat_name"],
        "category": row["threat_category"],
        "indicator_type": row["indicator_type"],
        "indicator_value": row["indicator_value"],
        "severity": row["severity"],
        "risk_score": row["risk_score"],
        "confidence_score": row["confidence_score"],
        "status": row["status"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "campaign_id": row["campaign_id"],
        "source_name": row["source_name"],
    }


def _cluster_for_threat(db, threat_id: str, include_weak: bool) -> Dict:
    row = db.execute(
        "SELECT * FROM threats WHERE threat_id = ?", (threat_id,)).fetchone()
    if row is None:
        return {"threat_id": threat_id, "cluster": None, "weak_links": [],
                "error": "Threat not found"}

    members = []
    basis = []

    # 1) explicit campaign correlation -------------------------------------
    if row["campaign_id"]:
        campaign_rows = db.execute(
            "SELECT * FROM threats WHERE campaign_id = ? "
            "ORDER BY first_seen", (row["campaign_id"],)).fetchall()
        members = list(campaign_rows)
        basis.append(f"Same campaign ID ({row['campaign_id']})")

    # 2) shared indicator value --------------------------------------------
    indicator_rows = db.execute(
        "SELECT * FROM threats WHERE indicator_value = ? AND threat_id != ? "
        "ORDER BY first_seen", (row["indicator_value"], threat_id)).fetchall()
    seen_ids = {m["threat_id"] for m in members}
    for candidate in indicator_rows:
        if candidate["threat_id"] not in seen_ids:
            members.append(candidate)
            basis.append("Same indicator value observed in multiple records")
            seen_ids.add(candidate["threat_id"])
    if indicator_rows:
        basis.append("Same indicator value observed in multiple records")

    # de-duplicate basis entries
    basis = list(dict.fromkeys(basis))
    cluster_id = row["campaign_id"] or (
        f"indicator:{row['indicator_value']}" if members else None)

    shared_indicators = sorted({m["indicator_value"] for m in members} |
                               {row["indicator_value"]})
    distinct_sources = sorted({m["source_name"] for m in members} |
                              {row["source_name"]})
    first = min([m["first_seen"] for m in members] + [row["first_seen"]])
    last = max([m["last_seen"] for m in members] + [row["last_seen"]])
    categories = sorted({m["threat_category"] for m in members} |
                        {row["threat_category"]})

    # 3) weak links: same category, overlapping window, no direct link -----
    weak_links = []
    if include_weak:
        weak_rows = db.execute(
            "SELECT * FROM threats WHERE threat_category = ? "
            "AND threat_id != ? AND campaign_id IS NOT ? "
            "AND indicator_value != ? "
            "AND last_seen >= date(?, ?) AND first_seen <= date(?, ?) "
            "LIMIT 5",
            (row["threat_category"], threat_id, row["campaign_id"],
             row["indicator_value"], row["first_seen"],
             f"-{WINDOW_DAYS} days", row["last_seen"], f"+{WINDOW_DAYS} days")
        ).fetchall()
        weak_links = [{
            "threat_id": w["threat_id"],
            "threat_name": w["threat_name"],
            "indicator_value": w["indicator_value"],
            "basis": (f"Same category ({w['threat_category']}) within a "
                      f"{WINDOW_DAYS}-day observation window"),
            "analyst_review_required": True,
        } for w in weak_rows]

    cluster = None
    if members:
        cluster = {
            "cluster_id": cluster_id,
            "correlation_basis": basis,
            "member_count": len(members) + 1,
            "members": [_threat_row_to_summary(m) for m in members],
            "shared_indicators": shared_indicators,
            "distinct_sources": distinct_sources,
            "time_span": {"first": first, "last": last},
            "categories": categories,
            "observation_count_total": sum(
                m["observation_count"] for m in members) + row["observation_count"],
            "attribution_note": (
                "Correlation indicates relationship/evidence. It does NOT "
                "prove attribution or confirm the same adversary."),
        }

    return {
        "threat_id": threat_id,
        "cluster": cluster,
        "weak_links": weak_links,
        "attribution_note": (
            "Correlation indicates relationship/evidence. It does NOT prove "
            "attribution. IOC matches are not automatic confirmation of "
            "compromise."),
    }


def _all_clusters(db) -> Dict:
    """Summarise every correlation cluster (campaign + indicator based)."""
    clusters = []

    campaign_rows = db.execute(
        "SELECT campaign_id, COUNT(*) AS n, "
        "       MIN(first_seen) AS first, MAX(last_seen) AS last, "
        "       COUNT(DISTINCT indicator_value) AS indicators, "
        "       COUNT(DISTINCT source_name) AS sources, "
        "       SUM(observation_count) AS obs "
        "FROM threats WHERE campaign_id IS NOT NULL AND campaign_id != '' "
        "GROUP BY campaign_id ORDER BY n DESC").fetchall()
    for c in campaign_rows:
        clusters.append({
            "cluster_id": c["campaign_id"],
            "basis": "Explicit campaign ID",
            "member_count": c["n"],
            "first_seen": c["first"],
            "last_seen": c["last"],
            "distinct_indicators": c["indicators"],
            "distinct_sources": c["sources"],
            "observation_count_total": c["obs"],
        })

    indicator_rows = db.execute(
        "SELECT indicator_value, COUNT(*) AS n, "
        "       MIN(first_seen) AS first, MAX(last_seen) AS last, "
        "       COUNT(DISTINCT source_name) AS sources "
        "FROM threats GROUP BY indicator_value HAVING n >= 2 "
        "ORDER BY n DESC LIMIT 50").fetchall()
    for r in indicator_rows:
        clusters.append({
            "cluster_id": f"indicator:{r['indicator_value']}",
            "basis": "Shared indicator value (corroboration)",
            "member_count": r["n"],
            "first_seen": r["first"],
            "last_seen": r["last"],
            "distinct_indicators": 1,
            "distinct_sources": r["sources"],
        })

    return {
        "cluster_count": len(clusters),
        "clusters": clusters[:200],
        "attribution_note": (
            "Correlation indicates relationship/evidence. It does NOT prove "
            "attribution."),
    }


def cluster_stats(db) -> Dict:
    """Small aggregate used by the dashboard."""
    campaigns = db.execute(
        "SELECT COUNT(DISTINCT campaign_id) FROM threats "
        "WHERE campaign_id IS NOT NULL AND campaign_id != ''").fetchone()[0]
    corroborated = db.execute(
        "SELECT COUNT(*) FROM (SELECT indicator_value FROM threats "
        "GROUP BY indicator_value HAVING COUNT(*) >= 2)").fetchone()[0]
    return {"campaign_clusters": campaigns,
            "corroborated_indicators": corroborated}
