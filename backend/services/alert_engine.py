"""
Alert Engine + Alert Correlation
================================

``generate_threat_alert()``  - create ONE alert for a threat when any rule
                              fires (risk threshold, confidence threshold,
                              high-priority vulnerability, repeated
                              observations, correlated indicators).
``correlate_alerts()``       - prevent ALERT FATIGUE by merging repeated
                              observations of the same indicator into a
                              single correlated alert with an observation
                              count.

ALERT FATIGUE (why correlation matters)
---------------------------------------
If the same indicator is observed 100 times in 5 minutes, creating 100
separate alerts buries the SOC queue and analysts start ignoring alerts.
Instead we create ONE correlated alert with:

    Observation Count = 100

so the analyst sees the full picture in a single triage item.

Alert statuses: NEW -> INVESTIGATING -> MONITORING -> RESOLVED | FALSE_POSITIVE
"""
from __future__ import annotations

from typing import Dict, List, Optional

import config
from utils.helpers import iso, utc_now

# Rules (thresholds come from config so they can be tuned via environment)
ALERT_RULES = [
    {
        "alert_type": "HIGH_RISK",
        "description": ("Risk score {risk} is at or above the risk threshold "
                        "({threshold}). Analyst triage recommended."),
        "check": lambda t, ctx: t["risk_score"] >= config.ALERT_RISK_THRESHOLD,
    },
    {
        "alert_type": "RISK_WITH_HIGH_CONFIDENCE",
        "description": ("Risk {risk} with high confidence ({confidence}) - "
                        "well-supported intelligence deserves prompt review."),
        "check": lambda t, ctx: (
            t["risk_score"] >= config.ALERT_CONFIDENCE_RISK_THRESHOLD
            and t["confidence_score"] >= config.ALERT_CONFIDENCE_THRESHOLD),
    },
    {
        "alert_type": "REPEATED_OBSERVATION",
        "description": ("Indicator observed {obs} times - repeated "
                        "observations increase analytical weight (not proof "
                        "of maliciousness by themselves)."),
        "check": lambda t, ctx: (
            t["observation_count"] >= config.ALERT_REPEATED_OBSERVATION_COUNT),
    },
    {
        "alert_type": "CORRELATED_INDICATORS",
        "description": ("Indicator belongs to a correlated cluster of "
                        "{cluster_size} records - related evidence found "
                        "(correlation is evidence, not attribution)."),
        "check": lambda t, ctx: (ctx.get("cluster_size", 0)
                                 >= config.ALERT_CORRELATION_CLUSTER_SIZE),
    },
    {
        "alert_type": "HIGH_PRIORITY_VULNERABILITY",
        "description": ("Associated vulnerability {cve} has contextual "
                        "priority {priority} - review patch/compensating "
                        "control plan."),
        "check": lambda t, ctx: (ctx.get("vuln_priority", 0)
                                 >= config.VULN_PRIORITY_ALERT_THRESHOLD),
    },
]


def alert_severity(risk: int, confidence: int = None) -> str:
    """Map risk score to alert severity (documented, deterministic)."""
    if risk >= 85:
        return "CRITICAL"
    if risk >= 70:
        return "HIGH"
    if risk >= 55:
        return "MEDIUM"
    if risk >= 40:
        return "LOW"
    return "INFORMATIONAL"


def generate_threat_alert(threat_row, context: Optional[Dict] = None,
                          observation_count: int = 1,
                          now=None) -> Optional[Dict]:
    """
    Evaluate alert rules for ONE threat row (sqlite Row or dict).

    Returns an alert dict, or None when no rule fires.
    Multiple firing rules produce one alert per rule type; the caller
    (database init / API) then merges duplicates via correlate_alerts().
    """
    context = context or {}
    t = threat_row
    alerts = []
    for rule in ALERT_RULES:
        if rule["check"](t, context):
            severity = alert_severity(t["risk_score"], t["confidence_score"])
            # A CRITICAL severity threat always escalates the alert.
            if t["severity"] == "CRITICAL" and severity in ("LOW", "MEDIUM"):
                severity = "HIGH"
            alerts.append({
                "alert_id": None,               # assigned on insert
                "threat_id": t["threat_id"],
                "timestamp": iso(now or utc_now()),
                "alert_type": rule["alert_type"],
                "severity": severity,
                "risk_score": t["risk_score"],
                "confidence_score": t["confidence_score"],
                "description": rule["description"].format(
                    risk=t["risk_score"], confidence=t["confidence_score"],
                    obs=t["observation_count"],
                    threshold=config.ALERT_RISK_THRESHOLD,
                    cluster_size=context.get("cluster_size", 0),
                    cve=context.get("cve_id", ""),
                    priority=context.get("vuln_priority", 0)),
                "status": "NEW",
                "observation_count": observation_count,
                "indicator_value": t["indicator_value"],
            })
    if not alerts:
        return None
    # Prefer the strongest alert as the primary alert: severity first, then
    # rule priority (HIGH_RISK is the primary triage signal).
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                     "INFORMATIONAL": 4}
    rule_priority = {"HIGH_RISK": 0, "HIGH_PRIORITY_VULNERABILITY": 1,
                     "RISK_WITH_HIGH_CONFIDENCE": 2, "CORRELATED_INDICATORS": 3,
                     "REPEATED_OBSERVATION": 4}
    alerts.sort(key=lambda a: (severity_rank.get(a["severity"], 9),
                               rule_priority.get(a["alert_type"], 9)))
    return alerts[0]


def correlate_alerts(alerts: List[Dict],
                     window_minutes: int = 60 * 24) -> Dict:
    """
    Merge repeated alerts about the SAME indicator into one correlated
    alert (the anti-alert-fatigue rule).

    Example from the project brief:
        same indicator observed 100 times in 5 minutes
        -> NOT 100 separate alerts
        -> ONE correlated alert with observation_count = 100

    Returns {"alerts": [...], "merged_count": n, "explanation": str}.
    """
    buckets: Dict[str, Dict] = {}
    merged = 0
    for alert in sorted(alerts, key=lambda a: a.get("timestamp") or ""):
        key = f"{alert.get('indicator_value')}|{alert['alert_type']}"
        if key in buckets:
            existing = buckets[key]
            existing["observation_count"] += alert.get("observation_count", 1)
            merged += 1
            # keep the most severe severity
            order = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if order.index(alert["severity"]) > order.index(existing["severity"]):
                existing["severity"] = alert["severity"]
            # keep the latest timestamp & highest scores
            existing["timestamp"] = max(existing["timestamp"],
                                        alert.get("timestamp") or "")
            existing["risk_score"] = max(existing["risk_score"],
                                         alert["risk_score"])
            existing["confidence_score"] = max(
                existing["confidence_score"], alert["confidence_score"])
        else:
            import copy
            buckets[key] = copy.deepcopy(alert)
            buckets[key].setdefault("observation_count", 1)

    return {
        "alerts": list(buckets.values()),
        "merged_count": merged,
        "explanation": (
            f"{merged} duplicate observation alert(s) merged into correlated "
            "alerts to prevent alert fatigue. Repeated observations of the "
            "same indicator raise the observation count instead of creating "
            "a new SOC queue item."),
    }


def status_is_valid(status: str) -> bool:
    return status in ("NEW", "INVESTIGATING", "MONITORING", "RESOLVED",
                      "FALSE_POSITIVE")
