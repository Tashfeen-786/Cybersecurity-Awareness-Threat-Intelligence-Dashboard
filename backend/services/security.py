"""
Security Services: Authentication, RBAC, Rate Limiting, Audit
=============================================================

Implements the project's security & privacy requirements:

    * API-key authentication for analyst/admin functions
    * Role-based access control (viewer / analyst / admin)
    * Per-client API rate limiting (sliding window, in-memory)
    * Audit logging of administrative/analyst actions
    * Protection of analyst notes (masked for unauthenticated requests)
    * Secrets only via environment variables (see config.py / .env.example)

Threat-intelligence data itself needs access control because IOC lists,
investigation notes and alert queues reveal an organisation's DEFENSIVE
posture - which systems are watched, what has been detected, and what is
not yet patched. Leaking that data would help an adversary tailor attacks.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Dict, Optional

from fastapi import Header, HTTPException, Request

import config
from utils.helpers import iso, sanitize_text, utc_now

# ---------------------------------------------------------------------------
# Authentication + RBAC
# ---------------------------------------------------------------------------

class AuthContext:
    def __init__(self, api_key: str, role: str):
        self.api_key = api_key
        self.role = role

    @property
    def actor(self) -> str:
        """Label written to the audit log. The raw key is NEVER logged."""
        return f"role:{self.role}"

    def has_permission(self, permission: str) -> bool:
        return config.role_has_permission(self.role, permission)


def authenticate(request: Request,
                 x_api_key: Optional[str] = Header(default=None)) -> AuthContext:
    """
    FastAPI dependency: require a valid API key.
    Returns 401 when missing/unknown. (Authorization is a separate check.)
    """
    if not x_api_key or config.get_role_for_api_key(x_api_key) is None:
        raise HTTPException(
            status_code=401,
            detail=("Authentication required: provide a valid API key in "
                    "the 'X-API-Key' header. Demo keys are listed in "
                    ".env.example for local use."))
    return AuthContext(x_api_key, config.get_role_for_api_key(x_api_key))


def require_permission(permission: str):
    """FastAPI dependency factory: require an authenticated role with a
    permission (RBAC). 401 for bad key, 403 for insufficient role."""
    def dependency(request: Request,
                   x_api_key: Optional[str] = Header(default=None)) -> AuthContext:
        ctx = authenticate(request, x_api_key)
        if not ctx.has_permission(permission):
            raise HTTPException(
                status_code=403,
                detail=(f"Forbidden: role '{ctx.role}' lacks the "
                        f"'{permission}' permission."))
        return ctx
    return dependency

require_viewer = require_permission("read")
require_analyst = require_permission("write_notes")
require_admin = require_permission("admin")


# ---------------------------------------------------------------------------
# Rate limiting (sliding window, per client, in-memory, dependency-free)
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    Simple sliding-window rate limiter.

    Keyed by API key when present (per client identity) otherwise by client
    IP. Returns (allowed, retry_after_seconds, remaining).
    """
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> Dict:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                retry_after = int(self.window_seconds -
                                  (now - bucket[0])) + 1
                return {"allowed": False, "retry_after": retry_after,
                        "remaining": 0}
            bucket.append(now)
            return {"allowed": True, "retry_after": 0,
                    "remaining": self.max_requests - len(bucket)}

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


# One global limiter for the app (configurable via environment).
rate_limiter = RateLimiter(config.RATE_LIMIT_REQUESTS,
                           config.RATE_LIMIT_WINDOW_SECONDS)


def client_key(request: Request, api_key: Optional[str]) -> str:
    if api_key:
        return f"key:{api_key}"
    forwarded = request.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() if forwarded else (
        request.client.host if request.client else "unknown")
    return f"ip:{ip}"


# ---------------------------------------------------------------------------
# Audit logging (administrative changes are auditable)
# ---------------------------------------------------------------------------

def audit(db, actor: str, action: str, target: str = "",
          details: str = "", request: Request = None) -> None:
    """Append an audit record for an administrative/analyst action."""
    ip = ""
    if request is not None:
        forwarded = request.headers.get("x-forwarded-for", "")
        ip = forwarded.split(",")[0].strip() if forwarded else (
            request.client.host if request.client else "")
    db.execute(
        "INSERT INTO audit_log (timestamp, actor, action, target, details, "
        "client_ip) VALUES (?,?,?,?,?,?)",
        (iso(utc_now()), sanitize_text(actor, 80), sanitize_text(action, 80),
         sanitize_text(target, 120), sanitize_text(details, 1000),
         sanitize_text(ip, 64)))
