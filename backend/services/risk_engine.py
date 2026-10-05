"""
Threat Risk & Confidence Scoring Engine
=======================================

RISK SCORE  - "How concerning the indicator/event MAY be."
CONFIDENCE  - "How confident the system is in the available intelligence."

These are DIFFERENT concepts and must never be blended:

    Risk 90 / Confidence 25 -> potentially serious, but the evidence is weak.
    Risk 70 / Confidence 95 -> high-confidence intelligence, meaningful risk.

HIGH RISK DOES NOT AUTOMATICALLY MEAN CONFIRMED COMPROMISE.

Risk formula (0-100, deterministic, explainable):

    risk = 0.30 * severity          (weight 30%)
         + 0.25 * confidence        (weight 25%)
         + 0.15 * recency           (weight 15%)
         + 0.10 * observation_freq  (weight 10%)
         + 0.10 * source_reliability(weight 10%)
         + 0.10 * context/correlation (weight 10%)

Classification:
    0-20   INFORMATIONAL
    21-40  LOW
    41-60  MEDIUM
    61-80  HIGH
    81-100 CRITICAL

Every score returns a full factor-by-factor breakdown so analysts can see
exactly WHY a number is what it is (explainable scoring).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from utils.helpers import parse_iso

# ---------------------------------------------------------------------------
# Severity -> points (used by the severity factor)
# ---------------------------------------------------------------------------
SEVERITY_POINTS = {
    "INFORMATIONAL": 10,
    "LOW": 30,
    "MEDIUM": 50,
    "HIGH": 70,
    "CRITICAL": 92,
}

# ---------------------------------------------------------------------------
# Source reliability (Admiralty-style letter grades, synthetic sources)
# ---------------------------------------------------------------------------
SOURCE_RELIABILITY = {
    "A": {"label": "A – Highly Reliable", "points": 100},
    "B": {"label": "B – Usually Reliable", "points": 80},
    "C": {"label": "C – Fairly Reliable", "points": 60},
    "D": {"label": "D – Reliability Unknown", "points": 40},
}

WEIGHTS = {
    "severity": 0.30,
    "confidence": 0.25,
    "recency": 0.15,
    "observation_frequency": 0.10,
    "source_reliability": 0.10,
    "context_correlation": 0.10,
}

RISK_BANDS = [
    (0, 20, "INFORMATIONAL"),
    (21, 40, "LOW"),
    (41, 60, "MEDIUM"),
    (61, 80, "HIGH"),
    (81, 100, "CRITICAL"),
]


def classify_risk(score: float) -> str:
    """Map a 0-100 risk score to its severity band."""
    for low, high, label in RISK_BANDS:
        if low <= round(score) <= high:
            return label
    return "CRITICAL" if score > 100 else "INFORMATIONAL"


# ---------------------------------------------------------------------------
# Factor sub-scores (each 0-100, deterministic)
# ---------------------------------------------------------------------------

def severity_factor(severity: str) -> int:
    return SEVERITY_POINTS.get((severity or "").upper(), 20)


def recency_factor(last_seen, reference_now: Optional[datetime] = None) -> int:
    """
    Recency of the LAST observation:
        seen in last 7 days        -> 100
        8-30 days                  -> 85
        31-90 days                 -> 70
        91-180 days                -> 50
        181-365 days               -> 30
        older                      -> 10
        never seen / unparsable    -> 0
    """
    if isinstance(last_seen, str):
        last_seen = parse_iso(last_seen)
    if last_seen is None:
        return 0
    if reference_now is None:
        reference_now = datetime.now(timezone.utc)
    if isinstance(reference_now, str):
        reference_now = parse_iso(reference_now)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    days = (reference_now - last_seen).days
    if days < 0:
        days = 0
    if days <= 7:
        return 100
    if days <= 30:
        return 85
    if days <= 90:
        return 70
    if days <= 180:
        return 50
    if days <= 365:
        return 30
    return 10


def observation_frequency_factor(observation_count: int) -> int:
    """
    Observation frequency: how often this indicator was observed.
        1 observation -> 20, each extra adds 15, capped at 100.
    Repeated observations increase analytical weight but never prove
    maliciousness on their own.
    """
    try:
        count = max(1, int(observation_count))
    except (TypeError, ValueError):
        count = 1
    return min(100, 15 * count + 5)


def source_reliability_factor(reliability_grade: str) -> int:
    grade = (reliability_grade or "").strip().upper()[:1]
    return SOURCE_RELIABILITY.get(grade, SOURCE_RELIABILITY["D"])["points"]


def context_correlation_factor(context_flags: Optional[Dict] = None) -> int:
    """
    Context / correlation:
        base                              -> 20
        + belongs to a correlated cluster  -> +40
        + related indicators observed      -> +40
    Capped at 100. Correlation raises analytical context but NEVER proves
    attribution or compromise by itself.
    """
    flags = context_flags or {}
    score = 20
    if flags.get("correlated_cluster"):
        score += 40
    if flags.get("related_indicator"):
        score += 40
    return min(100, score)


# ---------------------------------------------------------------------------
# Main risk calculation
# ---------------------------------------------------------------------------

def calculate_threat_risk(
    severity: str,
    confidence: int,
    last_seen,
    observation_count: int,
    source_reliability: str,
    context_flags: Optional[Dict] = None,
    reference_now=None,
) -> Dict:
    """
    Calculate a deterministic, explainable 0-100 risk score.

    Returns dict with:
        risk_score           int
        classification       str (INFORMATIONAL..CRITICAL)
        breakdown            list of {factor, weight, component_score,
                                     contribution, explanation}
        interpretation_note  str
    """
    confidence = max(0, min(100, int(confidence or 0)))

    sev_p = severity_factor(severity)
    rec_p = recency_factor(last_seen, reference_now)
    freq_p = observation_frequency_factor(observation_count)
    src_p = source_reliability_factor(source_reliability)
    ctx_p = context_correlation_factor(context_flags)

    breakdown: List[Dict] = [
        {
            "factor": "Severity",
            "weight": WEIGHTS["severity"],
            "component_score": sev_p,
            "contribution": round(WEIGHTS["severity"] * sev_p, 2),
            "explanation": f"Reported severity {str(severity).upper()} maps to "
                           f"{sev_p}/100 severity points.",
        },
        {
            "factor": "Confidence",
            "weight": WEIGHTS["confidence"],
            "component_score": confidence,
            "contribution": round(WEIGHTS["confidence"] * confidence, 2),
            "explanation": "Intelligence confidence in this specific item "
                           f"is {confidence}/100.",
        },
        {
            "factor": "Recency",
            "weight": WEIGHTS["recency"],
            "component_score": rec_p,
            "contribution": round(WEIGHTS["recency"] * rec_p, 2),
            "explanation": "Recency of the most recent observation "
                           f"({rec_p}/100). Stale indicators lose weight.",
        },
        {
            "factor": "Observation Frequency",
            "weight": WEIGHTS["observation_frequency"],
            "component_score": freq_p,
            "contribution": round(WEIGHTS["observation_frequency"] * freq_p, 2),
            "explanation": f"Indicator observed {observation_count} time(s) "
                           f"({freq_p}/100).",
        },
        {
            "factor": "Source Reliability",
            "weight": WEIGHTS["source_reliability"],
            "component_score": src_p,
            "contribution": round(WEIGHTS["source_reliability"] * src_p, 2),
            "explanation": "Reliability grade "
                           f"{(source_reliability or 'D').upper()} "
                           f"({src_p}/100). Reliability of the SOURCE is "
                           "distinct from confidence in the ITEM.",
        },
        {
            "factor": "Context / Correlation",
            "weight": WEIGHTS["context_correlation"],
            "component_score": ctx_p,
            "contribution": round(WEIGHTS["context_correlation"] * ctx_p, 2),
            "explanation": "Analytical context: correlated cluster membership "
                           "and related indicators (correlation is evidence of "
                           "relationship, not proof of attribution).",
        },
    ]

    risk = sum(item["contribution"] for item in breakdown)
    risk_score = int(round(risk))

    return {
        "risk_score": risk_score,
        "classification": classify_risk(risk_score),
        "breakdown": breakdown,
        "interpretation_note": (
            "Risk expresses how concerning this indicator may be. "
            "A high risk score does NOT automatically mean confirmed "
            "compromise - it means the indicator deserves analyst attention."
        ),
    }


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

CONFIDENCE_BASE_BY_RELIABILITY = {"A": 85, "B": 70, "C": 55, "D": 30}


def calculate_confidence(
    source_reliability: str,
    corroborating_sources: int = 1,
    observation_count: int = 1,
    last_seen=None,
    reference_now=None,
) -> Dict:
    """
    Calculate a 0-100 CONFIDENCE score for a piece of intelligence.

    Model (deterministic, explainable):
        base            = 85/70/55/30 for source reliability A/B/C/D
        corroboration   = +5 per additional independent observing source
                          (max +15)
        frequency       = +5 when observed 3+ times
        staleness       = -10 when last seen > 180 days ago,
                          -20 when > 365 days ago
        clamped to 0-100

    Confidence describes EVIDENCE QUALITY, not how dangerous the
    indicator is. A high-risk item with weak evidence should stay at
    low confidence until corroborated.
    """
    grade = (source_reliability or "D").strip().upper()[:1]
    base = CONFIDENCE_BASE_BY_RELIABILITY.get(grade, 30)
    notes = [f"Base score {base}/100 for source reliability grade {grade}."]

    corroboration = max(0, int(corroborating_sources) - 1)
    corroboration_bonus = min(15, corroboration * 5)
    if corroboration_bonus:
        notes.append(f"+{corroboration_bonus} corroboration "
                     f"({corroborating_sources} independent sources).")

    frequency_bonus = 5 if int(observation_count or 1) >= 3 else 0
    if frequency_bonus:
        notes.append(f"+{frequency_bonus} repeated observations "
                     f"({observation_count} sightings).")

    staleness_penalty = 0
    rec = recency_factor(last_seen, reference_now)
    if rec <= 30 and rec > 0:
        staleness_penalty = 10 if rec == 30 else 20
        notes.append(f"-{staleness_penalty} staleness (last seen more than "
                     "180 days ago weakens the evidence).")
    elif rec == 0:
        staleness_penalty = 20
        notes.append("-20 unknown observation time (no last-seen evidence).")

    score = max(0, min(100, base + corroboration_bonus + frequency_bonus
                       - staleness_penalty))

    return {
        "confidence_score": score,
        "grade": grade,
        "components": {
            "base": base,
            "corroboration_bonus": corroboration_bonus,
            "frequency_bonus": frequency_bonus,
            "staleness_penalty": staleness_penalty,
        },
        "explanation": notes,
        "interpretation_note": (
            "Confidence expresses evidence quality. Low confidence means the "
            "assessment needs corroboration, regardless of how risky the "
            "indicator appears."
        ),
    }
