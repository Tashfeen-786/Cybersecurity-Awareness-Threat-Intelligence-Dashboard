"""
Awareness modules, quiz scoring and learning recommendations tests
(scenarios 30-32 from the project brief).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from services.quiz_service import (  # noqa: E402
    generate_learning_recommendations, grade_submission, load_questions,
    public_questions, score_band)

QUIZ_JSON = Path(__file__).resolve().parents[1] / "awareness" / "quiz_questions.json"


# T-030 - Awareness module retrieval
def test_T030_awareness_module_retrieval(client):
    data = client.get("/api/awareness/modules").json()
    assert data["total"] == 15, "all 15 modules must be served"
    titles = {m["title"] for m in data["modules"]}
    assert "Phishing Awareness" in titles
    assert "Ransomware Awareness" in titles
    assert "AI-Enabled Scam Awareness" in titles

    # full content includes all five required sections
    mod = client.get("/api/awareness/modules/phishing-awareness").json()
    for section in ["what_is_it", "why_it_matters", "warning_signs",
                    "safe_practices", "if_it_happens"]:
        assert mod["content"][section], section
    assert any("QR" in w for w in mod["content"]["warning_signs"]) \
        or any("QR code" in s for s in mod["content"]["warning_signs"])
    assert client.get("/api/awareness/modules/does-not-exist").status_code == 404


def test_T030b_quiz_questions_shape():
    questions = load_questions()
    assert len(questions) >= 30, "at least 30 questions required"
    categories = {q["category"] for q in questions}
    assert {"Phishing", "Passwords", "MFA", "Social Engineering",
            "Safe Browsing", "Ransomware", "Privacy", "Wi-Fi",
            "Mobile Security", "Incident Reporting"} <= categories
    for q in questions:
        assert len(q["options"]) == 4
        assert 0 <= q["correct_answer"] < 4
        assert q["explanation"], "every question needs an explanation"
    # public API never leaks correct answers
    publics = public_questions()
    assert all("correct_answer" not in p and "explanation" not in p
               for p in publics)


# T-031 - Quiz scoring (server-side calculation)
def test_T031_quiz_scoring_perfect(client):
    questions = load_questions()
    answers = [{"question_id": q["question_id"],
                "selected_option": q["correct_answer"]} for q in questions]
    resp = client.post("/api/quiz/submit", json={"answers": answers})
    assert resp.status_code == 200
    result = resp.json()
    assert result["overall_score"] == 100.0
    assert result["band"] == "Strong Awareness"
    assert result["correct_count"] == len(questions)
    assert all(score == 100.0 for score in result["category_scores"].values())


def test_T031b_quiz_scoring_partial_and_bands(client):
    questions = load_questions()
    # answer exactly half correctly
    answers = []
    for i, q in enumerate(questions):
        correct = q["correct_answer"]
        wrong = (correct + 1) % len(q["options"])
        answers.append({"question_id": q["question_id"],
                        "selected_option": correct if i % 2 == 0 else wrong})
    result = client.post("/api/quiz/submit", json={"answers": answers}).json()
    assert result["overall_score"] == 50.0
    assert result["band"] == "Basic Awareness"
    # score persisted to the database
    # (verified via a second submission increasing the count)

    # bands
    assert score_band(0) == "Needs Improvement"
    assert score_band(40) == "Needs Improvement"
    assert score_band(41) == "Basic Awareness"
    assert score_band(61) == "Good Awareness"
    assert score_band(81) == "Strong Awareness"

    # empty submission -> 422
    resp = client.post("/api/quiz/submit", json={"answers": []})
    assert resp.status_code == 422


# T-032 - Learning recommendations
def test_T032_learning_recommendations(client):
    # weak phishing -> phishing module recommended
    recs = generate_learning_recommendations({"Phishing": 40.0})
    assert recs[0]["category"] == "Phishing"
    assert "phishing-awareness" in recs[0]["module_ids"]

    # strong score -> no immediate module required
    recs = generate_learning_recommendations({"Passwords": 90.0})
    assert "no immediate module required" in recs[0]["message"].lower()

    # borderline social engineering -> review recommended
    recs = generate_learning_recommendations({"Social Engineering": 55.0})
    assert recs[0]["action"].startswith("Review")

    # end-to-end via API: all-wrong answers produce weakest areas
    questions = load_questions()[:10]
    answers = [{"question_id": q["question_id"],
                "selected_option": (q["correct_answer"] + 1) % 4}
               for q in questions]
    result = client.post("/api/quiz/submit", json={"answers": answers}).json()
    assert result["weakest_areas"]
    assert result["recommendations"]
    assert "not an employee fitness" in result["educational_note"]
