"""
Quiz routes - security awareness quiz + awareness scoring.

    GET  /api/quiz          public   questions (WITHOUT correct answers)
    POST /api/quiz/submit   public   server-side scoring + recommendations
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from database import get_connection
from models.schemas import QuizSubmit
from services import quiz_service

router = APIRouter(prefix="/api/quiz", tags=["quiz"])


def _db():
    with get_connection() as conn:
        yield conn


@router.get("", summary="Quiz questions (correct answers are not exposed)")
def get_quiz(db=Depends(_db)):
    questions = quiz_service.public_questions()
    return {
        "total_questions": len(questions),
        "categories": sorted({q["category"] for q in questions}),
        "scoring_bands": [
            {"range": "0-40", "label": "Needs Improvement"},
            {"range": "41-60", "label": "Basic Awareness"},
            {"range": "61-80", "label": "Good Awareness"},
            {"range": "81-100", "label": "Strong Awareness"},
        ],
        "educational_note": ("This quiz produces an EDUCATIONAL awareness "
                             "score. It is not an employee fitness or "
                             "competency judgment."),
        "questions": questions,
    }


@router.post("/submit", summary="Submit answers - scores calculated server-side")
def submit_quiz(payload: QuizSubmit, db=Depends(_db)):
    try:
        result = quiz_service.grade_submission(
            db, [a.model_dump() for a in payload.answers],
            payload.anonymous_user_id)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc))
    return result
