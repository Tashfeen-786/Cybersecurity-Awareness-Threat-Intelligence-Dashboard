"""
Security Awareness Quiz + Scoring + Personalized Recommendations
================================================================

* GET  questions WITHOUT correct answers (answers never leak to the client).
* POST /api/quiz/submit -> actually calculates the score server-side.

Awareness score bands (educational, NOT a competency/fitness judgment):
    0-40   Needs Improvement
    41-60  Basic Awareness
    61-80  Good Awareness
    81-100 Strong Awareness

``generate_learning_recommendations()`` maps weak categories to the
matching awareness modules.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

import config
from utils.helpers import sanitize_text, iso, utc_now

SCORE_BANDS = [
    (0, 40, "Needs Improvement"),
    (41, 60, "Basic Awareness"),
    (61, 80, "Good Awareness"),
    (81, 100, "Strong Awareness"),
]

# quiz category -> recommended awareness module id(s)
CATEGORY_TO_MODULES = {
    "Phishing": ["phishing-awareness", "ai-scam-awareness"],
    "Passwords": ["password-security"],
    "MFA": ["multi-factor-authentication", "password-security"],
    "Social Engineering": ["social-engineering", "ai-scam-awareness"],
    "Safe Browsing": ["safe-browsing"],
    "Ransomware": ["ransomware-awareness", "usb-media-safety"],
    "Privacy": ["data-privacy", "mobile-security"],
    "Wi-Fi": ["secure-wifi", "remote-work-security"],
    "Mobile Security": ["mobile-security", "remote-work-security"],
    "Incident Reporting": ["incident-reporting"],
    "AI-Enabled Scams": ["ai-scam-awareness", "phishing-awareness"],
}


def score_band(score: float) -> str:
    for low, high, label in SCORE_BANDS:
        if low <= round(score) <= high:
            return label
    return "Strong Awareness"


def load_questions() -> List[Dict]:
    with open(config.QUIZ_QUESTIONS_JSON, "r", encoding="utf-8") as fh:
        return json.load(fh)


def public_questions() -> List[Dict]:
    """Questions for the client - correct answers and explanations removed."""
    out = []
    for q in load_questions():
        out.append({
            "question_id": q["question_id"],
            "category": q["category"],
            "question": q["question"],
            "options": q["options"],
        })
    return out


def grade_submission(db, answers: List[Dict],
                     anonymous_user_id: Optional[str] = None) -> Dict:
    """
    Grade a quiz submission SERVER-SIDE and store the result.

    answers: [{"question_id": ..., "selected_option": 0-3}, ...]

    Returns overall + per-category scores, weakest areas and
    personalized learning recommendations.
    """
    questions = {q["question_id"]: q for q in load_questions()}
    if not answers:
        raise ValueError("No answers submitted.")

    per_category: Dict[str, Dict] = {}
    correct_total = 0
    graded = 0

    for ans in answers:
        qid = ans.get("question_id")
        selected = ans.get("selected_option")
        question = questions.get(qid)
        if question is None:
            continue  # unknown question ids are ignored safely
        if not isinstance(selected, int) or not (0 <= selected < len(question["options"])):
            selected = None

        cat = question["category"]
        bucket = per_category.setdefault(cat, {"correct": 0, "total": 0})
        bucket["total"] += 1
        graded += 1
        if selected is not None and selected == question["correct_answer"]:
            bucket["correct"] += 1
            correct_total += 1

    if graded == 0:
        raise ValueError("No valid answers submitted.")

    overall = round(100.0 * correct_total / graded, 1)

    category_scores = {}
    explanations = []
    for cat, bucket in per_category.items():
        pct = round(100.0 * bucket["correct"] / bucket["total"], 1)
        category_scores[cat] = pct
        weakest_qs = [q for q in load_questions()
                      if q["category"] == cat]
        explanations.append({
            "category": cat,
            "score": pct,
            "correct": bucket["correct"],
            "total": bucket["total"],
        })

    weakest = sorted(category_scores.items(), key=lambda kv: kv[1])[:3]

    result = {
        "overall_score": overall,
        "band": score_band(overall),
        "correct_count": correct_total,
        "question_count": graded,
        "category_scores": category_scores,
        "category_breakdown": explanations,
        "weakest_areas": [{"category": c, "score": s} for c, s in weakest
                          if s < 100],
        "recommendations": generate_learning_recommendations(category_scores),
        "educational_note": (
            "This is an EDUCATIONAL awareness score. It is not an employee "
            "fitness or competency judgment - it only suggests which "
            "learning modules to review."),
    }

    # Persist (anonymous by design; no personal data is collected).
    user_id = None
    if anonymous_user_id:
        user_id = sanitize_text(anonymous_user_id, 60)
    db.execute(
        "INSERT INTO quiz_results (anonymous_user_id, overall_score, "
        "correct_count, question_count, category_scores, source, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (user_id, overall, correct_total, graded,
         json.dumps(category_scores), "demo_attempt", iso(utc_now())))
    return result


def generate_learning_recommendations(category_scores: Dict[str, float]) -> List[Dict]:
    """
    Personalized recommendations, e.g.:
        Phishing 40%        -> "Complete the Phishing Awareness module."
        Passwords 90%       -> no immediate module required
        Social Eng. 55%     -> "Review Social Engineering Awareness."
    Threshold: score < 70 triggers a recommendation.
    """
    recommendations = []
    for category, score in sorted(category_scores.items(),
                                  key=lambda kv: kv[1]):
        if score >= 70:
            continue
        module_ids = CATEGORY_TO_MODULES.get(category, [])
        if score < 50:
            action = "Complete the full module"
        else:
            action = "Review the module"
        recommendations.append({
            "category": category,
            "score": score,
            "action": action,
            "module_ids": module_ids,
            "message": (f"{category} score is {score}%. {action}"
                        + (f" ({', '.join(module_ids)})"
                           if module_ids else "") + "."),
        })
    if not recommendations:
        recommendations.append({
            "category": None, "score": None, "action": None,
            "module_ids": [],
            "message": ("All category scores are 70% or higher - no "
                        "immediate module required. Keep learning to stay "
                        "sharp."),
        })
    return recommendations


def awareness_stats(db) -> Dict:
    """Aggregates for the executive dashboard."""
    rows = db.execute(
        "SELECT overall_score, category_scores, created_at FROM quiz_results "
        "ORDER BY created_at").fetchall()
    if not rows:
        return {"attempts": 0, "average_score": None, "trend": [],
                "weakest_categories": []}

    import collections
    cat_scores = collections.defaultdict(list)
    for r in rows:
        try:
            cats = json.loads(r["category_scores"] or "{}")
        except json.JSONDecodeError:
            cats = {}
        for cat, score in cats.items():
            cat_scores[cat].append(score)

    # monthly trend
    trend = collections.OrderedDict()
    for r in rows:
        month = (r["created_at"] or "")[:7]
        trend.setdefault(month, []).append(r["overall_score"])
    trend_out = [{"month": month, "average_score": round(sum(v) / len(v), 1),
                  "attempts": len(v)} for month, v in trend.items()]

    weakest = sorted(((cat, round(sum(v) / len(v), 1))
                      for cat, v in cat_scores.items()),
                     key=lambda kv: kv[1])[:5]
    return {
        "attempts": len(rows),
        "average_score": round(sum(r["overall_score"] for r in rows)
                               / len(rows), 1),
        "trend": trend_out,
        "weakest_categories": [{"category": c, "average_score": s}
                               for c, s in weakest],
    }
