"""
backend/security.py — OBLVN Comprehensive Security Module

Covers:
  1. Security Headers Middleware (CSP, HSTS, X-Frame-Options, etc.)
  2. Request Size Limit Middleware
  3. Traffic / Abuse Monitor Middleware (per-IP rate + error rate blocking)
  4. UUID & Email input validation
  5. Password strength enforcement
  6. IDOR ownership assertion helpers (job, org, anomaly)
  7. Enum allowlist validation
  8. Safe error response helpers
  9. Phishing / suspicious-host detection
"""

import re
import time
import uuid
from collections import defaultdict
from typing import Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


# ─────────────────────────────────────────────────────────────────────────────
# 1. Security Headers Middleware
# ─────────────────────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Inject hardened HTTP security headers into every response.

    Headers applied
    ───────────────
    X-Frame-Options            — prevent clickjacking
    X-Content-Type-Options     — prevent MIME sniffing
    X-XSS-Protection           — legacy XSS filter
    Referrer-Policy            — no full-URL leakage cross-origin
    Permissions-Policy         — disable unneeded browser features
    Content-Security-Policy    — restrict resource loading
    Strict-Transport-Security  — force HTTPS (production only)

    Removed
    ───────
    Server                     — hide framework/version fingerprint
    X-Powered-By               — hide stack fingerprint
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), bluetooth=(), interest-cohort=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "worker-src 'self' blob:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none';"
        )

        # HSTS — only enforce in production to avoid dev-loop headaches
        try:
            from backend.config import config
            if config.ENV == "production":
                response.headers["Strict-Transport-Security"] = (
                    "max-age=31536000; includeSubDomains; preload"
                )
        except Exception:
            pass

        # Strip server fingerprinting headers
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)

        return response


# ─────────────────────────────────────────────────────────────────────────────
# 2. Request Size Limit Middleware
# ─────────────────────────────────────────────────────────────────────────────

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Reject request bodies larger than max_bytes.
    Default: 10 MiB — prevents memory exhaustion / DoS via giant payloads.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = 10 * 1024 * 1024):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > self.max_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body too large"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header"},
                )
        return await call_next(request)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Traffic / Abuse Monitor Middleware
# ─────────────────────────────────────────────────────────────────────────────

class _TrafficMonitor:
    """
    Per-IP in-memory tracker.

    Thresholds (configurable via class attributes):
      MAX_RPM      — requests per minute before temp-block
      MAX_ERR_RPM  — 4xx errors per minute before temp-block
      BLOCK_SECS   — duration of a temporary block in seconds

    Note: this is an in-process store.  For multi-worker deployments replace
    with a Redis-backed store.  For a single-process desktop app this is fine.
    """

    MAX_RPM: int = 300          # sustained flood threshold
    MAX_ERR_RPM: int = 60       # error scanning threshold
    BLOCK_SECS: int = 300       # 5-minute block
    WINDOW_SECS: int = 60       # sliding window

    def __init__(self):
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._errors:   dict[str, list[float]] = defaultdict(list)
        self._blocked:  dict[str, float]        = {}

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _prune(lst: list[float], window: int) -> list[float]:
        cutoff = time.monotonic() - window
        return [t for t in lst if t > cutoff]

    def is_blocked(self, ip: str) -> bool:
        until = self._blocked.get(ip)
        if until and time.monotonic() < until:
            return True
        self._blocked.pop(ip, None)
        return False

    def _block(self, ip: str) -> None:
        self._blocked[ip] = time.monotonic() + self.BLOCK_SECS
        # Log the block event without causing circular imports
        try:
            from backend.audit import log_event
            log_event(
                "ip_blocked",
                {"ip": ip, "reason": "abuse_threshold_exceeded"},
                user_id=None,
            )
        except Exception:
            pass

    # ── public API ───────────────────────────────────────────────────────────

    def record_request(self, ip: str) -> bool:
        """Return True if the IP should be blocked (request denied)."""
        if self.is_blocked(ip):
            return True
        now = time.monotonic()
        self._requests[ip] = self._prune(self._requests[ip], self.WINDOW_SECS)
        self._requests[ip].append(now)
        if len(self._requests[ip]) > self.MAX_RPM:
            self._block(ip)
            return True
        return False

    def record_error(self, ip: str, status_code: int) -> None:
        """Track 4xx responses; block if error rate is too high."""
        if status_code < 400 or status_code >= 500:
            return
        now = time.monotonic()
        self._errors[ip] = self._prune(self._errors[ip], self.WINDOW_SECS)
        self._errors[ip].append(now)
        if len(self._errors[ip]) > self.MAX_ERR_RPM:
            self._block(ip)


_traffic_monitor = _TrafficMonitor()


class TrafficMonitorMiddleware(BaseHTTPMiddleware):
    """
    Middleware that uses _TrafficMonitor to block abusive IPs.
    Excluded paths: /verify/* (public cert verification), static assets.
    """

    # Paths that are intentionally public and high-traffic — skip blocking
    _EXEMPT_PREFIXES = ("/app/assets/", "/verify/")

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip monitoring for static asset serving and public cert verify
        for prefix in self._EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)

        ip = (request.client.host if request.client else "unknown")

        if _traffic_monitor.record_request(ip):
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests — your IP has been temporarily blocked"
                },
                headers={"Retry-After": "300"},
            )

        response = await call_next(request)
        _traffic_monitor.record_error(ip, response.status_code)
        return response


# ─────────────────────────────────────────────────────────────────────────────
# 4. UUID & Email Validation
# ─────────────────────────────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+$"
)


def validate_uuid(value: str, field_name: str = "id") -> str:
    """
    Raise HTTP 400 if *value* is not a valid UUID v4 string.
    Returns the value unchanged on success.

    This prevents IDOR probing via non-UUID path params (e.g. SQL injection
    attempts, path traversal strings).
    """
    if not value or not _UUID_RE.match(str(value)):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field_name}: must be a valid UUID",
        )
    return str(value)


def validate_email(email: str) -> str:
    """
    Raise HTTP 400 if *email* fails basic format validation.
    Returns the lower-cased, stripped email on success.
    """
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    email = email.strip().lower()
    if len(email) > 254:
        raise HTTPException(status_code=400, detail="Email address too long")
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid email address format")
    return email


# ─────────────────────────────────────────────────────────────────────────────
# 5. Password Strength Enforcement
# ─────────────────────────────────────────────────────────────────────────────

def validate_password_strength(password: str) -> None:
    """
    Enforce minimum password complexity.

    Requirements
    ────────────
    • ≥ 8 characters
    • ≥ 1 uppercase letter
    • ≥ 1 lowercase letter
    • ≥ 1 digit
    • ≥ 1 special character

    Raise HTTP 400 listing all failing requirements.
    """
    if not password:
        raise HTTPException(status_code=400, detail="Password is required")

    failures = []
    if len(password) < 8:
        failures.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        failures.append("at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        failures.append("at least one lowercase letter")
    if not re.search(r"\d", password):
        failures.append("at least one digit (0-9)")
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?/\\|`~]', password):
        failures.append("at least one special character")

    if failures:
        raise HTTPException(
            status_code=400,
            detail="Password must contain: " + ", ".join(failures),
        )


# ─────────────────────────────────────────────────────────────────────────────
# 6. IDOR Ownership Assertion Helpers
# ─────────────────────────────────────────────────────────────────────────────

def assert_job_access(job: dict, user_id: str, svc) -> None:
    """
    Raise HTTP 403 if *user_id* has no access to *job*.

    Access is granted when:
      (a) user_id == job["user_id"]  (owner), OR
      (b) user_id is a member of job["org_id"]  (org member).

    This prevents IDOR: user A cannot view/modify user B's job by guessing
    the job UUID.
    """
    if job.get("user_id") == user_id:
        return

    org_id = job.get("org_id")
    if org_id:
        r = (
            svc.table("org_memberships")
            .select("role")
            .eq("org_id", org_id)
            .eq("user_id", user_id)
            .maybe_single()
            .execute()
        )
        if r.data:
            return

    raise HTTPException(status_code=403, detail="Forbidden")


def assert_org_membership(
    org_id: str,
    user_id: str,
    svc,
    min_role: str = "operator",
) -> str:
    """
    Verify *user_id* belongs to *org_id* with at least *min_role*.

    Returns the user's actual role string.
    Raises HTTP 403 if not a member or role is insufficient.
    """
    from backend.auth import ROLES

    r = (
        svc.table("org_memberships")
        .select("role")
        .eq("org_id", org_id)
        .eq("user_id", user_id)
        .maybe_single()
        .execute()
    )
    if not r.data:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: not a member of this organisation",
        )

    role = r.data["role"]
    if ROLES.get(role, 0) < ROLES.get(min_role, 0):
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: requires {min_role} or higher",
        )
    return role


def assert_anomaly_access(anomaly_id: str, user_id: str, svc) -> dict:
    """
    Fetch anomaly by ID and verify *user_id* can access it.

    Access rules:
      • anomaly.org_id set → user must be an org member
      • anomaly.org_id null → anomaly.user_id must match

    Returns the anomaly row dict.
    Raises HTTP 404 (not found) or HTTP 403 (forbidden).
    """
    r = (
        svc.table("anomalies")
        .select("*")
        .eq("id", anomaly_id)
        .maybe_single()
        .execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Anomaly not found")

    anomaly = r.data

    if anomaly.get("org_id"):
        member = (
            svc.table("org_memberships")
            .select("role")
            .eq("org_id", anomaly["org_id"])
            .eq("user_id", user_id)
            .maybe_single()
            .execute()
        )
        if member.data:
            return anomaly

    if anomaly.get("user_id") == user_id:
        return anomaly

    raise HTTPException(status_code=403, detail="Forbidden")


def assert_certificate_access(job_id: str, user_id: str, svc) -> dict:
    """
    Fetch a completed wipe job (certificate) and assert user access.

    Raises HTTP 404 if not found / not completed.
    Raises HTTP 403 if user has no access.
    Returns the job row dict.
    """
    r = (
        svc.table("wipe_jobs")
        .select("*")
        .eq("id", job_id)
        .eq("status", "completed")
        .maybe_single()
        .execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Certificate not found")

    job = r.data
    assert_job_access(job, user_id, svc)
    return job


# ─────────────────────────────────────────────────────────────────────────────
# 7. Enum Allowlists
# ─────────────────────────────────────────────────────────────────────────────

ALLOWED_WIPE_METHODS  = {"binary_overwrite", "crypto_erase", "full_sanitization"}
ALLOWED_STANDARDS     = {"nist_800_88", "dod_5220_22m", "gutmann"}
ALLOWED_ROLES         = {"operator", "team_lead", "org_admin"}
ALLOWED_SENSITIVITIES = {"low", "medium", "high"}
ALLOWED_AUDIT_FORMATS = {"json", "csv", "pdf"}


def validate_enum(value: str, allowed: set, field_name: str) -> str:
    """
    Raise HTTP 400 if *value* is not in the *allowed* set.
    Returns *value* unchanged on success.
    """
    if value not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field_name}: must be one of {sorted(allowed)}",
        )
    return value


# ─────────────────────────────────────────────────────────────────────────────
# 8. Safe Error Helpers
# ─────────────────────────────────────────────────────────────────────────────

def safe_error_detail(exc: Exception, generic: str = "An internal error occurred") -> str:
    """
    Return a user-safe error string.

    In development (DEBUG=True) the raw exception string is returned to aid
    debugging.  In production only the *generic* placeholder is returned,
    preventing internal paths / stack traces from leaking to clients.
    """
    try:
        from backend.config import config
        if config.DEBUG:
            return str(exc)
    except Exception:
        pass
    return generic


# ─────────────────────────────────────────────────────────────────────────────
# 9. Phishing / Suspicious Host Detection
# ─────────────────────────────────────────────────────────────────────────────

_ALLOWED_HOSTS: Optional[set] = None


def _get_allowed_hosts() -> set:
    """Lazy-load allowed hosts from config."""
    global _ALLOWED_HOSTS
    if _ALLOWED_HOSTS is None:
        try:
            import os
            raw = os.environ.get("OBLVN_ALLOWED_HOSTS", "localhost,127.0.0.1")
            _ALLOWED_HOSTS = {h.strip() for h in raw.split(",") if h.strip()}
        except Exception:
            _ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
    return _ALLOWED_HOSTS


class HostValidationMiddleware(BaseHTTPMiddleware):
    """
    Reject requests with a Host header that is not in the OBLVN_ALLOWED_HOSTS
    allow-list.  Prevents DNS rebinding and phishing via forged Host headers
    in production deployments.

    Only enforced when FLASK_ENV=production to avoid breaking local dev.
    """

    async def dispatch(self, request: Request, call_next):
        try:
            from backend.config import config
            if config.ENV != "production":
                return await call_next(request)
        except Exception:
            return await call_next(request)

        host = request.headers.get("host", "").split(":")[0].lower()
        if host not in _get_allowed_hosts():
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid host header"},
            )
        return await call_next(request)