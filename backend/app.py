"""
Cybersecurity Awareness & Threat Intelligence Dashboard - FastAPI backend
=========================================================================

Run (Windows):
    cd backend
    ..\\venv\\Scripts\\python -m uvicorn app:app --host 127.0.0.1 --port 8000

The backend serves:
    * the REST API under /api/*  (see docs/api_documentation.md)
    * the interactive Swagger docs at /docs
    * the static frontend at /   (so one server runs the whole project)

DEFENSIVE-SECURITY DESIGN
-------------------------
* Fully OFFLINE: no external feeds, no third-party API keys, no outbound
  connections to indicators, ever.
* All data is SYNTHETIC / DEMO ONLY.
* Analyst/admin functions require API-key authentication + RBAC.
* APIs are rate-limited; write actions are audited; inputs are validated
  and sanitized (XSS defence-in-depth).
* HTTPS for production is documented in docs/security_privacy.md.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import config
from database import get_connection, init_database
from routes import (alerts, attack, awareness, dashboard, executive,
                    indicators, quiz, threats, vulnerabilities, admin as admin_routes)

app = FastAPI(
    title=config.APP_NAME,
    version=config.APP_VERSION,
    description=(
        "Defensive cybersecurity education platform: threat intelligence "
        "analytics, IOC validation/search, risk & confidence scoring, "
        "MITRE ATT&CK mapping, vulnerability awareness, SOC alerting and a "
        "cybersecurity awareness center. **All data is SYNTHETIC / DEMO "
        "ONLY** - the application runs fully offline and never contacts "
        "any indicator."),
)

# CORS: permissive for the LOCAL educational demo only (frontend may be
# served from a separate local static server). Production must restrict.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in config.CORS_ALLOW_ORIGINS.split(",")],
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["X-API-Key", "Content-Type"],
)


# ---------------------------------------------------------------------------
# Rate limiting middleware (requirement: rate-limited APIs)
# ---------------------------------------------------------------------------
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        from services.security import client_key, rate_limiter
        key = client_key(request, request.headers.get("x-api-key"))
        check = rate_limiter.check(key)
        if not check["allowed"]:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(check["retry_after"])},
                content={"detail": (
                    f"Rate limit exceeded: max {config.RATE_LIMIT_REQUESTS} "
                    f"requests per {config.RATE_LIMIT_WINDOW_SECONDS}s. "
                    f"Retry after {check['retry_after']}s.")})
        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(check["remaining"])
        return response
    return await call_next(request)


# ---------------------------------------------------------------------------
# Global exception handling: never leak internals; log consistently
# ---------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": "Request validation failed.",
                 "errors": [
                     {"field": ".".join(str(p) for p in e.get("loc", [])),
                      "message": e.get("msg", "")}
                     for e in exc.errors()]},
    )


@app.exception_handler(sqlite3.Error)
async def database_handler(request: Request, exc: sqlite3.Error):
    return JSONResponse(
        status_code=500,
        content={"detail": "A database error occurred. The incident was "
                           "logged server-side."})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
app.include_router(threats.router)
app.include_router(indicators.router)
app.include_router(dashboard.router)
app.include_router(alerts.router)
app.include_router(vulnerabilities.router)
app.include_router(awareness.router)
app.include_router(quiz.router)
app.include_router(attack.router)
app.include_router(executive.router)
app.include_router(admin_routes.router)


@app.get("/api", tags=["meta"])
def api_index():
    """API index - lists endpoint groups."""
    return {
        "name": config.APP_NAME,
        "version": config.APP_VERSION,
        "docs": "/docs",
        "endpoints": [
            "GET /api/threats", "GET /api/threats/{id}",
            "POST /api/threats", "PUT /api/threats/{id}",
            "GET /api/indicators/validate", "GET /api/indicators/search",
            "GET /api/dashboard/stats", "GET /api/dashboard/trends",
            "GET /api/alerts", "GET /api/alerts/{id}",
            "PUT /api/alerts/{id}/status", "POST /api/threats/{id}/notes",
            "GET /api/vulnerabilities", "GET /api/vulnerabilities/{cve_id}",
            "GET /api/awareness/modules",
            "GET /api/awareness/modules/{id}",
            "GET /api/quiz", "POST /api/quiz/submit",
            "GET /api/attack/summary", "GET /api/attack/tactics/{tactic}",
            "GET /api/attack/techniques/{technique_id}",
            "GET /api/executive/summary",
            "GET /api/admin/health", "GET /api/admin/audit-log",
        ],
        "notice": "SYNTHETIC / DEMO ONLY - defensive cybersecurity education.",
    }


# ---------------------------------------------------------------------------
# Static frontend (mounted last so /api/* and /docs take precedence)
# ---------------------------------------------------------------------------
if config.FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(config.FRONTEND_DIR), html=True),
              name="frontend")


# ---------------------------------------------------------------------------
# Convenience: initialise the database on first run (idempotent)
# ---------------------------------------------------------------------------
def _ensure_database() -> None:
    """Create + initialize the SQLite database if it does not exist yet."""
    if not Path(config.DATABASE_PATH).exists():
        if not config.THREAT_DATASET_CSV.exists():
            raise RuntimeError(
                "Synthetic dataset missing. Run: python data/generate_threat_data.py")
        init_database()


_ensure_database()


if __name__ == "__main__":  # pragma: no cover
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
