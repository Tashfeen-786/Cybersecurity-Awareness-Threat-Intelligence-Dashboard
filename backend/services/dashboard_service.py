"""
Dashboard Analytics Service (Pandas-powered)
============================================

Builds every statistic and chart dataset for the SOC-style dashboard:

TOP CARDS: Total Threat Records, Critical Threats, High Threats,
           Active Indicators, Open Investigations, Average Confidence,
           Vulnerabilities Tracked.

CHARTS:   1. Threats Over Time        6. Risk Score Distribution
          2. Threats by Severity      7. Confidence Distribution
          3. Threats by Category      8. Vulnerabilities by Severity
          4. IOC Type Distribution    9. Top Threat Categories
          5. Top ATT&CK Tactics      10. Threat Status Distribution

Uses Pandas for aggregation (project requirement: Analytics = Pandas).
"""
from __future__ import annotations

from typing import Dict

import pandas as pd

RISK_BINS = [0, 20, 40, 60, 80, 100]
RISK_LABELS = ["0-20 (Informational)", "21-40 (Low)", "41-60 (Medium)",
               "61-80 (High)", "81-100 (Critical)"]
CONFIDENCE_BINS = [0, 20, 40, 60, 80, 100]
CONFIDENCE_LABELS = ["0-20 (Very low)", "21-40 (Low)", "41-60 (Moderate)",
                     "61-80 (Good)", "81-100 (High)"]

ACTIVE_STATUSES = ("NEW", "UNDER_REVIEW", "MONITORING")


def _load_frames(db) -> Dict[str, pd.DataFrame]:
    threats = pd.read_sql_query(
        "SELECT * FROM threats", db.connection
        if hasattr(db, "connection") else db)
    alerts = pd.read_sql_query("SELECT * FROM alerts", db.connection
                               if hasattr(db, "connection") else db)
    vulns = pd.read_sql_query("SELECT * FROM vulnerabilities",
                              db.connection if hasattr(db, "connection") else db)
    indicators = pd.read_sql_query("SELECT * FROM indicators",
                                   db.connection if hasattr(db, "connection")
                                   else db)
    attack = pd.read_sql_query(
        "SELECT tactic, technique_id FROM attack_mappings "
        "WHERE technique_id IS NOT NULL", db.connection
        if hasattr(db, "connection") else db)
    return {"threats": threats, "alerts": alerts, "vulns": vulns,
            "indicators": indicators, "attack": attack}


def dashboard_stats(db) -> Dict:
    frames = _load_frames(db)
    threats: pd.DataFrame = frames["threats"]
    vulns: pd.DataFrame = frames["vulns"]
    indicators: pd.DataFrame = frames["indicators"]
    attack: pd.DataFrame = frames["attack"]

    if threats.empty:
        return _empty_stats()

    active = threats[threats["status"].isin(ACTIVE_STATUSES)]

    # --- TOP CARDS ----------------------------------------------------------
    cards = {
        "total_threat_records": int(len(threats)),
        "critical_threats": int((active["severity"] == "CRITICAL").sum()),
        "high_threats": int((active["severity"] == "HIGH").sum()),
        "active_indicators": int(
            indicators["indicator_value"].nunique()) if not indicators.empty else 0,
        "open_investigations": int(threats["status"].isin(
            ["NEW", "UNDER_REVIEW"]).sum()),
        "average_confidence": round(float(active["confidence_score"].mean()), 1)
        if not active.empty else round(float(threats["confidence_score"].mean()), 1),
        "vulnerabilities_tracked": int(len(vulns)),
    }

    # --- CHART DATA ----------------------------------------------------------
    severity_order = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_counts = threats["severity"].value_counts().to_dict()
    threats_by_severity = [
        {"label": s, "count": int(severity_counts.get(s, 0))}
        for s in severity_order]

    category_counts = threats["threat_category"].value_counts()
    threats_by_category = [{"label": k, "count": int(v)}
                           for k, v in category_counts.items()]

    ioc_counts = threats["indicator_type"].value_counts()
    ioc_type_distribution = [{"label": k, "count": int(v)}
                             for k, v in ioc_counts.items()]

    status_order = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED",
                    "FALSE_POSITIVE"]
    status_counts = threats["status"].value_counts().to_dict()
    threat_status_distribution = [
        {"label": s, "count": int(status_counts.get(s, 0))}
        for s in status_order]

    if not attack.empty:
        tactic_counts = attack["tactic"].value_counts()
        top_tactics = [{"label": k, "count": int(v)}
                       for k, v in tactic_counts.head(10).items()]
    else:
        top_tactics = []

    if not vulns.empty:
        vuln_sev = vulns["severity"].value_counts().to_dict()
        vulnerabilities_by_severity = [
            {"label": s, "count": int(vuln_sev.get(s, 0))}
            for s in severity_order if vuln_sev.get(s, 0) > 0]
        top_vulnerability_categories = [
            {"label": k, "count": int(v)}
            for k, v in vulns["product_category"].value_counts().head(8).items()]
    else:
        vulnerabilities_by_severity = []
        top_vulnerability_categories = []

    return {
        "cards": cards,
        "charts": {
            "threats_by_severity": threats_by_severity,
            "threats_by_category": threats_by_category,
            "ioc_type_distribution": ioc_type_distribution,
            "threat_status_distribution": threat_status_distribution,
            "top_attack_tactics": top_tactics,
            "vulnerabilities_by_severity": vulnerabilities_by_severity,
            "top_threat_categories": threats_by_category[:8],
            "top_vulnerability_categories": top_vulnerability_categories,
        },
        "correlation": _correlation_snapshot(db),
        "data_notice": "All data is SYNTHETIC / DEMO ONLY (defensive "
                       "cybersecurity education).",
    }


def dashboard_trends(db) -> Dict:
    """Time-series charts: threats over time + score distributions."""
    frames = _load_frames(db)
    threats: pd.DataFrame = frames["threats"]

    if threats.empty:
        return {"threats_over_time": [], "risk_distribution": [],
                "confidence_distribution": [], "alerts_over_time": []}

    df = threats.copy()
    df["last_seen_dt"] = pd.to_datetime(df["last_seen"], errors="coerce",
                                        utc=True)
    df = df.dropna(subset=["last_seen_dt"])
    df["month"] = df["last_seen_dt"].dt.strftime("%Y-%m")
    monthly = df.groupby("month").size()

    threats_over_time = [{"period": k, "count": int(v)}
                         for k, v in monthly.items()]

    risk_cut = pd.cut(df["risk_score"], bins=RISK_BINS, labels=RISK_LABELS,
                      include_lowest=True)
    risk_distribution = [{"label": str(k), "count": int(v)}
                         for k, v in risk_cut.value_counts().reindex(
                             RISK_LABELS).items()]

    conf_cut = pd.cut(df["confidence_score"], bins=CONFIDENCE_BINS,
                      labels=CONFIDENCE_LABELS, include_lowest=True)
    confidence_distribution = [{"label": str(k), "count": int(v)}
                               for k, v in conf_cut.value_counts().reindex(
                                   CONFIDENCE_LABELS).items()]

    alerts: pd.DataFrame = frames["alerts"]
    if not alerts.empty:
        a = alerts.copy()
        a["month"] = pd.to_datetime(a["created_at"], errors="coerce",
                                    utc=True).dt.strftime("%Y-%m")
        alerts_over_time = [{"period": k, "count": int(v)}
                            for k, v in a.groupby("month").size().items()]
    else:
        alerts_over_time = []

    return {
        "threats_over_time": threats_over_time,
        "risk_distribution": risk_distribution,
        "confidence_distribution": confidence_distribution,
        "alerts_over_time": alerts_over_time,
    }


def _correlation_snapshot(db) -> Dict:
    try:
        row = db.execute(
            "SELECT COUNT(DISTINCT campaign_id) FROM threats WHERE "
            "campaign_id IS NOT NULL AND campaign_id != ''").fetchone()
        campaigns = row[0] if row else 0
        corroborated = db.execute(
            "SELECT COUNT(*) FROM (SELECT indicator_value FROM threats "
            "GROUP BY indicator_value HAVING COUNT(*) >= 2)").fetchone()[0]
        return {"campaign_clusters": campaigns,
                "corroborated_indicators": corroborated,
                "note": ("Correlation is evidence of relationship - it does "
                         "not prove attribution.")}
    except Exception:
        return {"campaign_clusters": 0, "corroborated_indicators": 0}


def _empty_stats() -> Dict:
    return {
        "cards": {"total_threat_records": 0, "critical_threats": 0,
                  "high_threats": 0, "active_indicators": 0,
                  "open_investigations": 0, "average_confidence": 0,
                  "vulnerabilities_tracked": 0},
        "charts": {key: [] for key in
                   ["threats_by_severity", "threats_by_category",
                    "ioc_type_distribution", "threat_status_distribution",
                    "top_attack_tactics", "vulnerabilities_by_severity",
                    "top_threat_categories", "top_vulnerability_categories"]},
        "correlation": {"campaign_clusters": 0,
                        "corroborated_indicators": 0},
        "data_notice": "Dataset is empty.",
    }
