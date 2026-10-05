"""
Admin routes - audit trail and health (ADMIN role only).

    GET  /api/admin/audit-log     admin   view audit trail
    GET  /api/admin/health        public  service health/info
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from database import get_connection
import config
from services import security

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _db():
    with get_connection() as conn:
        yield conn


@router.get("/whoami", summary="Validate an API key and return its role")
def whoami(auth=Depends(security.authenticate)):
    """Used by the frontend 'sign in' dialog. Never returns the key itself."""
    return {"authenticated": True, "role": auth.role,
            "permissions": sorted(config.ROLE_PERMISSIONS[auth.role])}


@router.get("/audit-log", summary="View audit trail (admin role required)")
def audit_log(limit: int = Query(100, ge=1, le=1000), db=Depends(_db),
              auth=Depends(security.require_admin)):
    rows = db.execute(
        "SELECT * FROM audit_log ORDER BY audit_id DESC LIMIT ?",
        (limit,)).fetchall()
    return {"total": len(rows),
            "entries": [dict(r) for r in rows],
            "note": ("Every analyst/admin write action is recorded. Raw API "
                     "keys are never stored - only the acting role.")}


@router.get("/health", summary="Service health + build info (public)")
def health(db=Depends(_db)):
    threats = db.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    alerts = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    vulns = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    modules = db.execute("SELECT COUNT(*) FROM awareness_modules").fetchone()[0]
    return {
        "status": "ok",
        "app": config.APP_NAME,
        "version": config.APP_VERSION,
        "records": {"threats": threats, "alerts": alerts,
                    "vulnerabilities": vulns, "awareness_modules": modules},
        "offline": True,
        "notice": ("Runs fully offline with SYNTHETIC / DEMO ONLY data. "
                   "No external threat feeds, API keys or outbound "
                   "connections are used."),
    }
