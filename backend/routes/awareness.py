"""
Awareness routes - Cybersecurity Awareness Center.

    GET /api/awareness/modules          public  module list
    GET /api/awareness/modules/{id}     public  full module content
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from database import get_connection
from services import awareness_service

router = APIRouter(prefix="/api/awareness", tags=["awareness"])


def _db():
    with get_connection() as conn:
        yield conn


@router.get("/modules", summary="List awareness learning modules")
def list_modules(db=Depends(_db)):
    modules = awareness_service.get_modules(db)
    return {"total": len(modules), "modules": modules}


@router.get("/modules/{module_id}", summary="Full awareness module content")
def get_module(module_id: str, db=Depends(_db)):
    module = awareness_service.get_module_detail(db, module_id)
    if module is None:
        raise HTTPException(404, detail=f"Module '{module_id}' not found")
    return module
