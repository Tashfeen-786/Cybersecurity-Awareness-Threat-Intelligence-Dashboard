"""
Database Layer (SQLite)
=======================

Implements the database design required by the project brief:

    THREATS, INDICATORS, SOURCES, ATTACK_MAPPINGS, VULNERABILITIES,
    ALERTS, ANALYST_NOTES, AWARENESS_MODULES, QUIZ_RESULTS

plus two documented extensions needed by the required features:

    TIMELINE_EVENTS  - per-threat investigation timeline (First Seen ->
                       Observations -> Risk change -> Investigation ->
                       Monitoring -> Closed)
    AUDIT_LOG        - audit trail for administrative/analyst actions
                       (security requirement: "administrative changes are
                       auditable")

Design notes:
    * Primary keys, foreign keys (PRAGMA foreign_keys=ON) and indexes.
    * All access goes through parameterized SQL (injection-safe).
    * ANALYST_NOTES contain investigation data -> protected at the API
      layer (masked for unauthenticated requests) because threat-intel
      data reveals an organisation's defensive posture.

``init_database()`` is idempotent: it rebuilds the database from the
synthetic CSVs, generates alerts via the alert engine, builds timelines
and seeds synthetic quiz results for the awareness trend.
"""
from __future__ import annotations

import csv
import json
import random
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

import config
from services import ioc_validator
from services.alert_engine import (alert_severity, correlate_alerts,
                                   generate_threat_alert)
from utils.helpers import iso, utc_now

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
    source_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name  TEXT NOT NULL UNIQUE,
    reliability  TEXT NOT NULL DEFAULT 'D'
);

CREATE TABLE IF NOT EXISTS threats (
    threat_id          TEXT PRIMARY KEY,
    timestamp          TEXT,
    threat_name        TEXT NOT NULL,
    threat_category    TEXT NOT NULL,
    description        TEXT DEFAULT '',
    severity           TEXT NOT NULL,
    risk_score         INTEGER NOT NULL DEFAULT 0,
    confidence_score   INTEGER NOT NULL DEFAULT 0,
    status             TEXT NOT NULL DEFAULT 'NEW',
    first_seen         TEXT,
    last_seen          TEXT,
    source_id          INTEGER REFERENCES sources(source_id),
    source_name        TEXT DEFAULT '',
    indicator_type     TEXT,
    indicator_value    TEXT,
    country_or_region  TEXT DEFAULT '',
    campaign_id        TEXT DEFAULT '',
    observation_count  INTEGER DEFAULT 1,
    cve_id             TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_threats_severity   ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_category   ON threats(threat_category);
CREATE INDEX IF NOT EXISTS idx_threats_status     ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_risk       ON threats(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_threats_confidence ON threats(confidence_score DESC);
CREATE INDEX IF NOT EXISTS idx_threats_indicator  ON threats(indicator_value);
CREATE INDEX IF NOT EXISTS idx_threats_campaign   ON threats(campaign_id);
CREATE INDEX IF NOT EXISTS idx_threats_last_seen  ON threats(last_seen DESC);

CREATE TABLE IF NOT EXISTS indicators (
    indicator_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id       TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    indicator_type  TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    first_seen      TEXT,
    last_seen       TEXT
);

CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_indicators_threat ON indicators(threat_id);

CREATE TABLE IF NOT EXISTS attack_mappings (
    mapping_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id     TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    tactic        TEXT,
    technique     TEXT,
    technique_id  TEXT,
    justification TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_attack_threat  ON attack_mappings(threat_id);
CREATE INDEX IF NOT EXISTS idx_attack_tactic  ON attack_mappings(tactic);
CREATE INDEX IF NOT EXISTS idx_attack_tech    ON attack_mappings(technique_id);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                    TEXT NOT NULL UNIQUE,
    product_category          TEXT,
    product_name              TEXT DEFAULT '',
    severity                  TEXT,
    cvss_score                REAL,
    published_date            TEXT,
    patch_available           INTEGER DEFAULT 1,
    exploitation_status_demo  TEXT,
    asset_criticality         INTEGER DEFAULT 3,
    exposure                  TEXT,
    business_context          TEXT,
    priority_score            INTEGER DEFAULT 0,
    priority_band             TEXT,
    description               TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_priority ON vulnerabilities(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_cve      ON vulnerabilities(cve_id);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id         TEXT REFERENCES threats(threat_id) ON DELETE CASCADE,
    timestamp         TEXT,
    alert_type        TEXT,
    severity          TEXT,
    risk_score        INTEGER DEFAULT 0,
    confidence_score  INTEGER DEFAULT 0,
    description       TEXT DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'NEW',
    observation_count INTEGER DEFAULT 1,
    indicator_value   TEXT DEFAULT '',
    created_at        TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_threat ON alerts(threat_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id   TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    note        TEXT NOT NULL,
    author_role TEXT DEFAULT 'analyst',
    created_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_notes_threat ON analyst_notes(threat_id);

CREATE TABLE IF NOT EXISTS awareness_modules (
    module_id       TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    category        TEXT,
    summary         TEXT DEFAULT '',
    reading_minutes INTEGER DEFAULT 3,
    content_json    TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS quiz_results (
    result_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    anonymous_user_id  TEXT,
    overall_score      REAL,
    correct_count      INTEGER,
    question_count     INTEGER,
    category_scores    TEXT DEFAULT '{}',
    source             TEXT DEFAULT 'demo_attempt',
    created_at         TEXT
);

CREATE TABLE IF NOT EXISTS timeline_events (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id    TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    event_type   TEXT,
    description  TEXT DEFAULT '',
    occurred_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_timeline_threat ON timeline_events(threat_id);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT,
    actor      TEXT,
    action     TEXT,
    target     TEXT DEFAULT '',
    details    TEXT DEFAULT '',
    client_ip  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# Synthetic sources with their reliability grades (A-D)
DEFAULT_SOURCES = [
    ("Internal SOC", "A"),
    ("Security Vendor", "B"),
    ("Public Threat Feed", "C"),
    ("Research Report", "B"),
    ("Community Submission", "C"),
    ("Unknown Source", "D"),
]

# Seeded analyst notes (clearly synthetic; the first is pinned to the
# demonstration scenario required by the project brief).
SEED_NOTES = [
    ("THR-2026-001",
     "Indicator appears in multiple synthetic phishing observations.",
     "analyst"),
    ("THR-2026-002",
     "Related infrastructure for the synthetic credential-phishing "
     "campaign; corroborated by three demo sources. Monitoring continues.",
     "analyst"),
    ("THR-2026-003",
     "Attachment hash under review. No execution performed - hash analysis "
     "is data-only by policy.", "analyst"),
    ("THR-2026-007",
     "Lure URL mirrors the campaign domain pattern. Added to the demo "
     "blocklist watch view.", "analyst"),
]


# ---------------------------------------------------------------------------
# Connection handling
# ---------------------------------------------------------------------------

@contextmanager
def get_connection(db_path=None):
    """Open a configured SQLite connection (foreign keys ON, WAL)."""
    path = str(db_path or config.DATABASE_PATH)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def create_schema(conn) -> None:
    conn.executescript(SCHEMA)


# ---------------------------------------------------------------------------
# Initialisation / ingestion
# ---------------------------------------------------------------------------

def init_database(db_path=None, threat_csv=None, vulnerabilities_csv=None,
                  modules_json=None, seed_quiz=True, seed_notes=True) -> Dict:
    """
    (Re)build the database from the synthetic datasets.

    Steps:
      1. create schema
      2. ingest sources, threats, indicators
      3. ingest ATT&CK mappings (only those present in the dataset)
      4. ingest vulnerabilities (contextual priority already computed)
      5. generate alerts via the alert engine + correlate duplicates
      6. build per-threat investigation timelines
      7. seed synthetic analyst notes (demo scenario)
      8. load awareness modules
      9. seed synthetic quiz results (awareness trend)
     10. store generation metadata

    Returns a summary dict with row counts.
    """
    db_path = str(db_path or config.DATABASE_PATH)
    threat_csv = Path(threat_csv or config.THREAT_DATASET_CSV)
    vulnerabilities_csv = Path(vulnerabilities_csv or config.VULNERABILITIES_CSV)
    modules_json = Path(modules_json or config.AWARENESS_MODULES_JSON)

    if Path(db_path).exists():
        Path(db_path).unlink()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(db_path + suffix)
        if sidecar.exists():
            sidecar.unlink()

    summary: Dict = {}
    with get_connection(db_path) as conn:
        create_schema(conn)

        # --- 1) sources ---------------------------------------------------
        conn.executemany(
            "INSERT INTO sources (source_name, reliability) VALUES (?,?)",
            DEFAULT_SOURCES)
        source_ids = {name: sid for sid, name in
                      [(r["source_id"], r["source_name"])
                       for r in conn.execute("SELECT source_id, source_name "
                                             "FROM sources")]}

        # --- 2) threats + indicators --------------------------------------
        threat_rows = _read_csv(threat_csv)
        summary["threats"] = len(threat_rows)
        for row in threat_rows:
            conn.execute(
                "INSERT INTO threats (threat_id, timestamp, threat_name, "
                "threat_category, description, severity, risk_score, "
                "confidence_score, status, first_seen, last_seen, source_id, "
                "source_name, indicator_type, indicator_value, "
                "country_or_region, campaign_id, observation_count, cve_id) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (row.get("threat_id"), row.get("timestamp"),
                 row.get("threat_name"), row.get("threat_category"),
                 row.get("description", ""),
                 row.get("severity", "LOW"),
                 int(row.get("risk_score") or 0),
                 int(row.get("confidence_score") or 0),
                 row.get("status", "NEW"),
                 row.get("first_seen"), row.get("last_seen"),
                 source_ids.get(row.get("source_name")),
                 row.get("source_name", ""),
                 row.get("indicator_type", ""),
                 row.get("indicator_value", ""),
                 row.get("country_or_region_optional", ""),
                 row.get("campaign_id", "") or "",
                 int(row.get("observation_count") or 1),
                 row.get("cve_id_optional", "") or ""))

            validation = ioc_validator.validate_indicator(
                row.get("indicator_value", ""))
            fine_type = validation["indicator_type"] if validation["valid"] \
                else row.get("indicator_type", "unknown")
            conn.execute(
                "INSERT INTO indicators (threat_id, indicator_type, "
                "indicator_value, first_seen, last_seen) VALUES (?,?,?,?,?)",
                (row.get("threat_id"), fine_type,
                 validation["normalized_value"] or row.get("indicator_value"),
                 row.get("first_seen"), row.get("last_seen")))

        # --- 3) ATT&CK mappings (already justified by the generator) ------
        mapped = 0
        for row in threat_rows:
            technique_field = (row.get("mitre_technique_optional") or "").strip()
            tactic = (row.get("mitre_tactic_optional") or "").strip()
            if not technique_field or not tactic:
                continue
            technique_id, technique_name = _split_technique(technique_field)
            conn.execute(
                "INSERT INTO attack_mappings (threat_id, tactic, technique, "
                "technique_id, justification) VALUES (?,?,?,?,?)",
                (row["threat_id"], tactic, technique_name or technique_field,
                 technique_id,
                 "Mapping justified by behavioural context in the synthetic "
                 "observation (see threat description)."))
            mapped += 1
        summary["attack_mappings"] = mapped

        # --- 4) vulnerabilities --------------------------------------------
        vuln_rows = _read_csv(vulnerabilities_csv)
        summary["vulnerabilities"] = len(vuln_rows)
        for row in vuln_rows:
            conn.execute(
                "INSERT INTO vulnerabilities (cve_id, product_category, "
                "product_name, severity, cvss_score, published_date, "
                "patch_available, exploitation_status_demo, "
                "asset_criticality, exposure, business_context, "
                "priority_score, priority_band, description) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (row["cve_id"], row["product_category"],
                 row.get("product_name", ""), row["severity"],
                 float(row["cvss_score"]), row["published_date"],
                 1 if str(row["patch_available"]).lower() == "true" else 0,
                 row["exploitation_status_demo"],
                 int(row.get("asset_criticality") or 3),
                 row.get("exposure", ""), row.get("business_context", ""),
                 int(row.get("priority_score") or 0),
                 row.get("priority_band", ""),
                 row.get("description", "")))

        # --- 5) alert engine + correlation ---------------------------------
        summary["alerts"] = _generate_alerts(conn)

        # --- 6) timelines ---------------------------------------------------
        summary["timeline_events"] = _build_timelines(conn)

        # --- 7) seeded analyst notes ----------------------------------------
        if seed_notes:
            now = iso(utc_now())
            for threat_id, note, role in SEED_NOTES:
                exists = conn.execute(
                    "SELECT 1 FROM threats WHERE threat_id = ?",
                    (threat_id,)).fetchone()
                if exists:
                    conn.execute(
                        "INSERT INTO analyst_notes (threat_id, note, "
                        "author_role, created_at) VALUES (?,?,?,?)",
                        (threat_id, note, role, now))
            summary["seed_notes"] = len(SEED_NOTES)

        # --- 8) awareness modules --------------------------------------------
        with open(modules_json, "r", encoding="utf-8") as fh:
            modules = json.load(fh)
        for module in modules:
            conn.execute(
                "INSERT INTO awareness_modules (module_id, title, category, "
                "summary, reading_minutes, content_json) VALUES (?,?,?,?,?,?)",
                (module["module_id"], module["title"], module["category"],
                 module.get("summary", ""),
                 int(module.get("reading_minutes", 3)),
                 json.dumps(module)))
        summary["awareness_modules"] = len(modules)

        # --- 9) synthetic quiz results (trend seed) ---------------------------
        if seed_quiz:
            summary["quiz_results"] = _seed_quiz_results(conn)

        # --- 10) metadata ------------------------------------------------------
        meta = {}
        meta_path = config.DATASET_META_JSON
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                meta = {}
        conn.executemany(
            "INSERT INTO meta (key, value) VALUES (?,?)",
            [("dataset_generated_at", meta.get("generated_at", "")),
             ("dataset_record_count", str(meta.get("record_count", ""))),
             ("database_initialized_at", iso(utc_now())),
             ("synthetic_notice", config.SYNTHETIC_LABEL)])

    return summary


def _read_csv(path: Path) -> List[Dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _split_technique(field: str):
    """'T1566.002 (Phishing: Spearphishing Link)' -> id, name"""
    if "(" in field and field.endswith(")"):
        tech_id, _, name = field.partition("(")
        return tech_id.strip(), name.rstrip(")").strip()
    return field.strip(), None


def _generate_alerts(conn) -> int:
    """
    Run the alert engine across all threats, then correlate duplicates
    (anti alert-fatigue) before inserting.
    """
    threats = conn.execute("SELECT * FROM threats").fetchall()

    # Cluster sizes for the correlation rule
    cluster_sizes: Dict[str, int] = {}
    for t in threats:
        if t["campaign_id"]:
            cluster_sizes[t["campaign_id"]] = (
                cluster_sizes.get(t["campaign_id"], 0) + 1)

    # Vulnerability priorities for the vulnerability rule
    vuln_priority: Dict[str, int] = {}
    for v in conn.execute("SELECT cve_id, priority_score FROM vulnerabilities"):
        vuln_priority[v["cve_id"]] = v["priority_score"]

    generated = []
    for t in threats:
        context = {
            "cluster_size": cluster_sizes.get(t["campaign_id"], 0)
            if t["campaign_id"] else 0,
            "vuln_priority": vuln_priority.get(t["cve_id"], 0)
            if t["cve_id"] else 0,
            "cve_id": t["cve_id"] or "",
        }
        alert = generate_threat_alert(t, context=context,
                                      observation_count=t["observation_count"],
                                      now=_parse_or_none(t["last_seen"]))
        if alert:
            alert["timestamp"] = t["last_seen"] or iso(utc_now())
            alert["indicator_value"] = t["indicator_value"]
            # Closed/false-positive threats get terminal alert statuses so
            # the SOC queue demonstrates the full lifecycle.
            status_map = {"NEW": "NEW", "UNDER_REVIEW": "INVESTIGATING",
                          "MONITORING": "MONITORING", "CLOSED": "RESOLVED",
                          "FALSE_POSITIVE": "FALSE_POSITIVE"}
            alert["status"] = status_map.get(t["status"], "NEW")
            generated.append(alert)

    merged = correlate_alerts(generated)["alerts"]
    for alert in merged:
        conn.execute(
            "INSERT INTO alerts (threat_id, timestamp, alert_type, severity, "
            "risk_score, confidence_score, description, status, "
            "observation_count, indicator_value, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (alert["threat_id"], alert["timestamp"], alert["alert_type"],
             alert["severity"], alert["risk_score"],
             alert["confidence_score"], alert["description"], alert["status"],
             alert["observation_count"], alert.get("indicator_value", ""),
             alert["timestamp"]))
    return len(merged)


def _parse_or_none(value):
    if not value:
        return None
    from utils.helpers import parse_iso
    return parse_iso(value)


def _build_timelines(conn) -> int:
    """
    Build the per-threat investigation timeline:
        FIRST_SEEN -> OBSERVATION -> RISK change -> INVESTIGATION ->
        MONITORING -> CLOSED / FALSE_POSITIVE
    """
    count = 0
    for t in conn.execute("SELECT * FROM threats").fetchall():
        events = [
            ("FIRST_SEEN",
             f"Indicator first observed ({t['indicator_value']}). "
             f"Type: {t['indicator_type']}.", t["first_seen"]),
            ("OBSERVATION",
             f"{t['observation_count']} observation(s) recorded from source "
             f"'{t['source_name']}'.", t["last_seen"]),
        ]
        if t["risk_score"] >= 70:
            events.append(("RISK_INCREASE",
                           f"Risk score {t['risk_score']}/100 is above the "
                           f"alert threshold - escalated for triage.",
                           t["last_seen"]))
        elif t["risk_score"] <= 40:
            events.append(("RISK_DECREASE",
                           f"Risk score {t['risk_score']}/100 remains in the "
                           "low band - routine monitoring.",
                           t["last_seen"]))
        if t["status"] in ("UNDER_REVIEW", "MONITORING", "CLOSED",
                           "FALSE_POSITIVE"):
            events.append(("INVESTIGATION",
                           "Analyst triage: indicator validated, enrichment "
                           "reviewed, related observations checked.",
                           t["last_seen"]))
        if t["status"] in ("MONITORING", "CLOSED", "FALSE_POSITIVE"):
            events.append(("MONITORING",
                           "Threat placed under monitoring after initial "
                           "investigation.", t["last_seen"]))
        if t["status"] == "CLOSED":
            events.append(("CLOSED",
                           "Investigation closed - no further action "
                           "required.", t["last_seen"]))
        if t["status"] == "FALSE_POSITIVE":
            events.append(("FALSE_POSITIVE",
                           "Marked FALSE POSITIVE - indicator judged benign "
                           "or irrelevant after investigation. (Example of "
                           "why IOC matches are not automatic compromise.)",
                           t["last_seen"]))

        for event_type, description, occurred_at in events:
            conn.execute(
                "INSERT INTO timeline_events (threat_id, event_type, "
                "description, occurred_at) VALUES (?,?,?,?)",
                (t["threat_id"], event_type, description,
                 occurred_at or iso(utc_now())))
            count += 1
    return count


def _seed_quiz_results(conn, attempts: int = 48) -> int:
    """
    Seed SYNTHETIC quiz results so the executive awareness trend and
    weakest-area analytics have history to visualise. Results are marked
    source='synthetic_seed' and use anonymous placeholder IDs.
    """
    rng = random.Random(4242)
    categories = ["Phishing", "Passwords", "MFA", "Social Engineering",
                  "Safe Browsing", "Ransomware", "Privacy", "Wi-Fi",
                  "Mobile Security", "Incident Reporting"]
    now = datetime.now(timezone.utc)
    inserted = 0
    for i in range(attempts):
        days_ago = int(180 * (i / attempts))
        created = (now - timedelta(days=days_ago)).replace(
            microsecond=0).isoformat()
        # Simulated improvement over time + weak phishing/social scores.
        base = 48 + (days_ago < 90) * 12 + rng.randint(-8, 10)
        cat_scores = {}
        for cat in categories:
            weak_penalty = 14 if cat in ("Phishing", "Social Engineering") else 0
            cat_scores[cat] = max(10, min(100, base - weak_penalty
                                          + rng.randint(-6, 6)))
        overall = round(sum(cat_scores.values()) / len(cat_scores), 1)
        correct = int(round(overall * 0.36 / 100))
        conn.execute(
            "INSERT INTO quiz_results (anonymous_user_id, overall_score, "
            "correct_count, question_count, category_scores, source, "
            "created_at) VALUES (?,?,?,?,?,?,?)",
            (f"synthetic-seed-{i + 1:03d}", overall, correct, 36,
             json.dumps(cat_scores), "synthetic_seed", created))
        inserted += 1
    return inserted
