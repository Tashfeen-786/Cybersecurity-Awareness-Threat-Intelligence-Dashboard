"""
Threat Service
==============

Data-access and business logic for threat records:
    * list with filters (severity, category, indicator type, risk,
      confidence, status, date range, text search)
    * sorting (newest, highest risk, highest confidence, most observed)
    * pagination
    * creation with IOC validation + duplicate-observation handling
    * update (status changes - audited at the route layer)
    * per-threat investigation timeline
    * recommended DEFENSIVE actions per category

All SQL is parameterized (no string interpolation of user input).
"""
from __future__ import annotations

from typing import Dict, List, Optional

import config
from services import ioc_validator
from utils.helpers import iso, parse_iso, sanitize_text, utc_now

SORT_OPTIONS = {
    "newest": "last_seen DESC",
    "oldest": "first_seen ASC",
    "risk": "risk_score DESC",
    "confidence": "confidence_score DESC",
    "observed": "observation_count DESC",
}

SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Recommended DEFENSIVE actions per category. The Phishing list is pinned
# to the project brief's demonstration scenario.
DEFENSIVE_ACTIONS = {
    "Phishing": [
        "Review related internal logs for the indicator",
        "Check for authorized sightings of the indicator (partner/vendor use)",
        "Review email-security telemetry for messages referencing it",
        "Increase phishing awareness for users (see Awareness Center)",
        "Monitor related indicators for further observations",
    ],
    "Malware": [
        "Search endpoint telemetry for the hash (defensive lookup only)",
        "Verify endpoint protection is enabled and up to date",
        "Review host isolation options with the asset owner if confirmed",
        "Check for related indicators in the correlation cluster",
        "Document findings in the threat record notes",
    ],
    "Ransomware": [
        "Verify backup integrity and offline backup availability",
        "Confirm patch levels on exposed services",
        "Review least-privilege and network segmentation controls",
        "Prepare incident-response checklist and escalation path",
        "Increase user awareness of ransomware lures",
    ],
    "Credential Theft": [
        "Review authentication logs for suspicious sign-ins",
        "Enforce/verify MFA on affected accounts",
        "Check for password resets initiated from unusual locations",
        "Advise affected users to rotate credentials via official channels",
        "Monitor for follow-up account-takeover indicators",
    ],
    "Web Threats": [
        "Review WAF/web-server logs for exploitation attempts",
        "Verify the affected application is patched",
        "Check for unauthorized administrative changes",
        "Validate input-validation controls on affected endpoints",
    ],
    "Network Threats": [
        "Review firewall/flow logs for connections to the indicator",
        "Verify egress filtering and proxy policies",
        "Check whether other internal hosts communicated with the indicator",
        "Consider defensive blocklist additions where policy allows",
    ],
    "Vulnerability Exposure": [
        "Review the vulnerability's contextual priority (not CVSS alone)",
        "Confirm the affected asset exists in the inventory",
        "Apply the vendor patch or compensating controls",
        "Track remediation in the ticketing system",
    ],
    "Social Engineering": [
        "Warn users about the reported impersonation theme",
        "Verify the request through an official out-of-band channel",
        "Review the Incident Reporting module with staff",
        "Monitor for related reports from other users",
    ],
    "Data Exposure": [
        "Review DLP/egress logs for the transfer volume involved",
        "Confirm whether the data was classified and authorized",
        "Engage data owners to assess business impact",
        "Review access controls on the affected data store",
    ],
    "Account Security": [
        "Review account activity for the affected identity",
        "Force a secure credential reset through the helpdesk",
        "Verify MFA enrolment and recent MFA changes",
        "Check for newly created accounts or mail-forwarding rules",
    ],
}


def recommended_actions(category: str) -> List[str]:
    return DEFENSIVE_ACTIONS.get(category, [
        "Review the indicator details and related observations",
        "Validate the intelligence before acting on it",
        "Document your investigation in analyst notes",
    ])


# ---------------------------------------------------------------------------
# Listing / filtering / sorting
# ---------------------------------------------------------------------------

def list_threats(db, filters: Optional[Dict] = None, sort: str = "newest",
                 page: int = 1, page_size: int = None) -> Dict:
    filters = filters or {}
    page = max(1, int(page or 1))
    page_size = max(1, min(int(page_size or config.DEFAULT_PAGE_SIZE),
                           config.MAX_PAGE_SIZE))
    order_by = SORT_OPTIONS.get(sort, SORT_OPTIONS["newest"])

    where = []
    params: List = []

    if filters.get("severity"):
        where.append("severity = ?")
        params.append(filters["severity"].upper())
    if filters.get("category"):
        where.append("threat_category = ?")
        params.append(filters["category"])
    if filters.get("indicator_type"):
        where.append("indicator_type = ?")
        params.append(filters["indicator_type"])
    if filters.get("status"):
        where.append("status = ?")
        params.append(filters["status"].upper())
    if filters.get("min_risk") is not None:
        where.append("risk_score >= ?")
        params.append(int(filters["min_risk"]))
    if filters.get("max_risk") is not None:
        where.append("risk_score <= ?")
        params.append(int(filters["max_risk"]))
    if filters.get("min_confidence") is not None:
        where.append("confidence_score >= ?")
        params.append(int(filters["min_confidence"]))
    if filters.get("date_from"):
        where.append("last_seen >= ?")
        params.append(filters["date_from"])
    if filters.get("date_to"):
        where.append("first_seen <= ?")
        params.append(filters["date_to"] + ("T23:59:59" if len(filters["date_to"]) == 10 else ""))
    if filters.get("campaign_id"):
        where.append("campaign_id = ?")
        params.append(filters["campaign_id"])
    if filters.get("q"):
        # Text search across safe, indexed columns (parameterized).
        where.append("(threat_name LIKE ? OR threat_id LIKE ? "
                     "OR indicator_value LIKE ?)")
        like = f"%{filters['q']}%"
        params.extend([like, like, like])

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total = db.execute(
        f"SELECT COUNT(*) FROM threats {where_sql}", params).fetchone()[0]

    rows = db.execute(
        f"SELECT * FROM threats {where_sql} ORDER BY {order_by} "
        "LIMIT ? OFFSET ?", (*params, page_size, (page - 1) * page_size)
    ).fetchall()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, -(-total // page_size)),
        "items": [row_to_dict(r) for r in rows],
    }


def get_threat(db, threat_id: str) -> Optional[Dict]:
    row = db.execute("SELECT * FROM threats WHERE threat_id = ?",
                     (threat_id,)).fetchone()
    return row_to_dict(row) if row else None


def row_to_dict(row) -> Dict:
    return {
        "threat_id": row["threat_id"],
        "timestamp": row["timestamp"],
        "threat_name": row["threat_name"],
        "threat_category": row["threat_category"],
        "indicator_type": row["indicator_type"],
        "indicator_value": row["indicator_value"],
        "source_name": row["source_name"],
        "source_id": row["source_id"],
        "confidence_score": row["confidence_score"],
        "severity": row["severity"],
        "risk_score": row["risk_score"],
        "status": row["status"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "country_or_region": row["country_or_region"],
        "description": row["description"],
        "campaign_id": row["campaign_id"],
        "observation_count": row["observation_count"],
        "cve_id": row["cve_id"],
        "synthetic": True,
        "synthetic_label": config.SYNTHETIC_LABEL,
    }


# ---------------------------------------------------------------------------
# Creation / update (analyst functions - routes enforce auth)
# ---------------------------------------------------------------------------

REQUIRED_CREATE_FIELDS = {"threat_name", "threat_category", "indicator_type",
                          "indicator_value", "severity"}


def validate_threat_payload(payload: Dict) -> Dict:
    """Validate + sanitize a threat-creation payload. Raises ValueError."""
    missing = REQUIRED_CREATE_FIELDS - set(payload or {})
    if missing:
        raise ValueError(f"Missing required fields: {sorted(missing)}")

    if payload["threat_category"] not in DEFENSIVE_ACTIONS:
        raise ValueError(f"Unknown threat_category "
                         f"'{payload['threat_category']}'")

    validation = ioc_validator.validate_indicator(payload["indicator_value"])
    if not validation["valid"]:
        raise ValueError("Indicator failed IOC validation: "
                         + "; ".join(validation["validation_notes"]))

    severity = str(payload["severity"]).upper()
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"Invalid severity '{severity}'. "
                         f"Allowed: {SEVERITY_ORDER}")

    confidence = payload.get("confidence_score", 50)
    try:
        confidence = int(confidence)
    except (TypeError, ValueError):
        raise ValueError("confidence_score must be an integer 0-100")
    if not 0 <= confidence <= 100:
        raise ValueError("confidence_score must be 0-100")

    return {
        "threat_name": sanitize_text(payload["threat_name"], 200),
        "threat_category": payload["threat_category"],
        "indicator_type": payload["indicator_type"],
        "indicator_value": validation["normalized_value"],
        "severity": severity,
        "confidence_score": confidence,
        "description": sanitize_text(payload.get("description", ""), 2000),
        "source_name": sanitize_text(payload.get("source_name",
                                                 "Internal SOC"), 100),
        "status": "NEW",
    }


def find_duplicate_observation(db, indicator_value: str, category: str,
                               window_hours: int = 24):
    """
    Duplicate-observation handling: if the SAME indicator in the SAME
    category was recorded recently, the new sighting is treated as an
    additional OBSERVATION of the existing record (observation_count + 1,
    last_seen refreshed) instead of a brand-new threat record.
    """
    row = db.execute(
        "SELECT * FROM threats WHERE indicator_value = ? "
        "AND threat_category = ? AND last_seen >= datetime('now', ?) "
        "ORDER BY last_seen DESC LIMIT 1",
        (indicator_value, category, f'-{window_hours} hours')).fetchone()
    return row


def create_threat(db, payload: Dict, author: str = "analyst") -> Dict:
    """
    Insert a new threat record. Returns
    {created: bool, duplicate_observation: bool, threat: {...}}.
    """
    data = validate_threat_payload(payload)
    dup = find_duplicate_observation(db, data["indicator_value"],
                                     data["threat_category"])
    if dup is not None:
        db.execute(
            "UPDATE threats SET observation_count = observation_count + 1, "
            "last_seen = ? WHERE threat_id = ?",
            (iso(utc_now()), dup["threat_id"]))
        db.execute(
            "INSERT INTO timeline_events (threat_id, event_type, description,"
            " occurred_at) VALUES (?, 'OBSERVATION', ?, ?)",
            (dup["threat_id"],
             "Duplicate observation received - merged into this record "
             "(observation count increased, no duplicate threat created).",
             iso(utc_now())))
        return {"created": False, "duplicate_observation": True,
                "threat": get_threat(db, dup["threat_id"])}

    now = iso(utc_now())
    threat_id = _next_threat_id(db)
    source = db.execute("SELECT source_id FROM sources WHERE source_name = ?",
                        (data["source_name"],)).fetchone()
    source_id = source["source_id"] if source else _ensure_source(
        db, data["source_name"])

    db.execute(
        "INSERT INTO threats (threat_id, timestamp, threat_name, "
        "threat_category, indicator_type, indicator_value, source_id, "
        "source_name, confidence_score, severity, risk_score, status, "
        "first_seen, last_seen, country_or_region, description, campaign_id, "
        "observation_count, cve_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?"
        ",?,?,?)",
        (threat_id, now, data["threat_name"], data["threat_category"],
         data["indicator_type"], data["indicator_value"], source_id,
         data["source_name"], data["confidence_score"], data["severity"],
         data.get("risk_score", 0), "NEW", now, now, "",
         data["description"], None, 1, None))
    db.execute(
        "INSERT INTO indicators (threat_id, indicator_type, indicator_value, "
        "first_seen, last_seen) VALUES (?,?,?,?,?)",
        (threat_id, data["indicator_type"], data["indicator_value"], now, now))
    db.execute(
        "INSERT INTO timeline_events (threat_id, event_type, description, "
        "occurred_at) VALUES (?, 'FIRST_SEEN', ?, ?)",
        (threat_id, "Threat record created and indicator validated.", now))
    return {"created": True, "duplicate_observation": False,
            "threat": get_threat(db, threat_id)}


def _next_threat_id(db) -> str:
    year = utc_now().year
    row = db.execute(
        "SELECT COUNT(*) FROM threats WHERE threat_id LIKE ?",
        (f"THR-{year}-%",)).fetchone()
    return f"THR-{year}-{row[0] + 1:04d}"


def _ensure_source(db, source_name: str) -> int:
    cur = db.execute("INSERT INTO sources (source_name, reliability) "
                     "VALUES (?, 'D')", (source_name,))
    return cur.lastrowid


def update_threat(db, threat_id: str, updates: Dict) -> Optional[Dict]:
    """Update mutable fields of a threat (status, notes handled elsewhere)."""
    allowed = {"status", "severity", "description", "threat_name",
               "country_or_region"}
    clean = {k: v for k, v in (updates or {}).items() if k in allowed}
    if not clean:
        return get_threat(db, threat_id)

    if "status" in clean:
        status = str(clean["status"]).upper()
        valid = {"NEW", "UNDER_REVIEW", "MONITORING", "CLOSED",
                 "FALSE_POSITIVE"}
        if status not in valid:
            raise ValueError(f"Invalid status '{status}'. Allowed: {sorted(valid)}")
        clean["status"] = status
    if "severity" in clean:
        if clean["severity"].upper() not in SEVERITY_ORDER:
            raise ValueError("Invalid severity")
        clean["severity"] = clean["severity"].upper()
    if "description" in clean:
        clean["description"] = sanitize_text(clean["description"], 2000)
    if "threat_name" in clean:
        clean["threat_name"] = sanitize_text(clean["threat_name"], 200)
    if "country_or_region" in clean:
        clean["country_or_region"] = sanitize_text(clean["country_or_region"], 80)

    sets = ", ".join(f"{key} = ?" for key in clean)
    db.execute(f"UPDATE threats SET {sets} WHERE threat_id = ?",
               (*clean.values(), threat_id))

    if "status" in clean:
        db.execute(
            "INSERT INTO timeline_events (threat_id, event_type, description,"
            " occurred_at) VALUES (?, 'STATUS_CHANGE', ?, ?)",
            (threat_id, f"Status changed to {clean['status']} by analyst.",
             iso(utc_now())))
    return get_threat(db, threat_id)


# ---------------------------------------------------------------------------
# Timeline (First Seen -> Observations -> Risk change -> Investigation ->
#           Monitoring -> Closed)
# ---------------------------------------------------------------------------

TIMELINE_ORDER = {"FIRST_SEEN": 0, "OBSERVATION": 1, "RISK_INCREASE": 2,
                  "RISK_DECREASE": 2, "INVESTIGATION": 3, "STATUS_CHANGE": 3,
                  "MONITORING": 4, "CLOSED": 5, "FALSE_POSITIVE": 5}


def get_timeline(db, threat_id: str) -> List[Dict]:
    rows = db.execute(
        "SELECT * FROM timeline_events WHERE threat_id = ? "
        "ORDER BY occurred_at ASC", (threat_id,)).fetchall()
    return [{
        "event_type": r["event_type"],
        "description": r["description"],
        "occurred_at": r["occurred_at"],
    } for r in rows]
