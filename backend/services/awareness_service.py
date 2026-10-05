"""
Cybersecurity Awareness Center Service
======================================

Loads the 15 awareness learning modules (awareness/modules.json) and serves
them through the database (AWARENESS_MODULES table) and API.

Every module contains the five required sections:
    * what_is_it          - What is it?
    * why_it_matters      - Why does it matter?
    * warning_signs       - Warning signs
    * safe_practices      - Safe practices
    * if_it_happens       - What to do if something happens

Purely educational, defensive content.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

import config


def load_modules_json() -> List[Dict]:
    with open(config.AWARENESS_MODULES_JSON, "r", encoding="utf-8") as fh:
        return json.load(fh)


def get_modules(db) -> List[Dict]:
    rows = db.execute(
        "SELECT module_id, title, category, summary, reading_minutes "
        "FROM awareness_modules ORDER BY module_id").fetchall()
    return [{
        "module_id": r["module_id"],
        "title": r["title"],
        "category": r["category"],
        "summary": r["summary"],
        "reading_minutes": r["reading_minutes"],
    } for r in rows]


def get_module_detail(db, module_id: str) -> Optional[Dict]:
    row = db.execute(
        "SELECT * FROM awareness_modules WHERE module_id = ?",
        (module_id,)).fetchone()
    if row is None:
        return None
    return {
        "module_id": row["module_id"],
        "title": row["title"],
        "category": row["category"],
        "summary": row["summary"],
        "reading_minutes": row["reading_minutes"],
        "content": json.loads(row["content_json"]),
    }


def count_modules(db) -> int:
    return db.execute("SELECT COUNT(*) FROM awareness_modules").fetchone()[0]
