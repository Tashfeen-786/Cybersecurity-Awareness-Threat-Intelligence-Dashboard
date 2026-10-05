"""Small shared helpers used across the backend."""
from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Date / time helpers (timezone-aware, deprecation-safe)
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """Current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """Format a datetime as an ISO-8601 string."""
    if dt is None:
        return None
    return dt.replace(microsecond=0).isoformat()


def parse_iso(value: str):
    """Parse an ISO-8601 string into an aware datetime (None on failure)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Sanitization (defence-in-depth against XSS / control-character abuse)
# ---------------------------------------------------------------------------

# Characters that carry no legitimate meaning in free-text security notes and
# could be used for log-forging or XSS when rendered in an HTML dashboard.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

MAX_TEXT_LENGTH = 4000


def sanitize_text(value, max_length: int = MAX_TEXT_LENGTH) -> str:
    """
    Sanitize free-text user input (notes, descriptions, names).

    1. Strips control characters (log forging / protocol abuse).
    2. HTML-escapes angle brackets so stored text can never form HTML/script
       tags when rendered by the dashboard (defence-in-depth: the frontend
       also escapes everything it renders).
    3. Truncates to a sane maximum length.

    This is intentional defence-in-depth: the frontend never uses innerHTML
    with user data, and the backend never stores raw angle brackets.
    """
    if value is None:
        return ""
    text = str(value)
    text = unicodedata.normalize("NFKC", text)
    text = _CONTROL_CHARS.sub("", text)
    # Escape the two characters that could start or close an HTML tag.
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("javascript:", "")  # neutralize inline URI schemes
    text = text.strip()
    if len(text) > max_length:
        text = text[:max_length]
    return text


def clamp(value, low: int, high: int) -> int:
    """Clamp an integer into [low, high]."""
    try:
        value = int(round(float(value)))
    except (TypeError, ValueError):
        value = low
    return max(low, min(high, value))


def is_safe_demo_label(text: str) -> bool:
    """True when a string only contains characters safe for demo labels."""
    return bool(re.fullmatch(r"[A-Za-z0-9 .,:;()\-_/]+", text or ""))
