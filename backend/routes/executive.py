"""Executive route: management-friendly cybersecurity summary."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from database import get_connection
from services import executive_service

router = APIRouter(prefix="/api/executive", tags=["executive"])


def _db():
    with get_connection() as conn:
        yield conn


@router.get("/summary", summary="Executive cybersecurity summary (non-technical)")
def executive_summary(db=Depends(_db)):
    return executive_service.build_executive_summary(db)
