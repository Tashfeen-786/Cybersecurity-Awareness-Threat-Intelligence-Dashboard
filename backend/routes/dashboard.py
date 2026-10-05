"""Dashboard routes: GET /api/dashboard/stats and GET /api/dashboard/trends."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from database import get_connection
from services import dashboard_service

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _db():
    with get_connection() as conn:
        yield conn


@router.get("/stats", summary="Top cards + categorical chart data")
def stats(db=Depends(_db)):
    return dashboard_service.dashboard_stats(db)


@router.get("/trends", summary="Time-series + score distribution data")
def trends(db=Depends(_db)):
    return dashboard_service.dashboard_trends(db)
