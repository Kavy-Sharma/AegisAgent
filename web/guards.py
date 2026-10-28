"""
web/guards.py - AegisAgent Web Security Guards

Non-negotiable security controls:
1. DNS-Rebinding defense: Enforce Host header in [127.0.0.1, localhost] (with optional port).
2. Session cookie protection: HttpOnly, SameSite=Strict, 15-minute server-side idle timeout.
3. Cryptographic CSRF protection on all mutating requests (X-CSRF-Token or form field).
4. Strict CSP & security headers on every response.
5. Role-based access control read strictly from server session, with audit logging on 403.
"""

from functools import wraps
import hmac
import os
from pathlib import Path
import re
import secrets
import time
from flask import abort, jsonify, redirect, request, session, url_for

import security.logger
from security.logger import _file_lock

_SECRET_ENV_KEY = "AEGIS_WEB_SECRET"
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"
SESSION_IDLE_TIMEOUT_SECONDS = 900  # 15 minutes


def get_web_secret() -> str:
    """
    Retrieves or generates AEGIS_WEB_SECRET from .env with atomic file locking.
    Never exposes or logs the secret.
    """
    val = os.environ.get(_SECRET_ENV_KEY)
    if val and val.strip():
        return val.strip()

    with _file_lock(_ENV_FILE):
        val = os.environ.get(_SECRET_ENV_KEY)
        if val and val.strip():
            return val.strip()

        if _ENV_FILE.exists():
            try:
                with open(_ENV_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            if k.strip() == _SECRET_ENV_KEY:
                                secret = v.strip().strip("'\"")
                                if secret:
                                    os.environ[_SECRET_ENV_KEY] = secret
                                    return secret
            except Exception:
                pass

        new_secret = secrets.token_hex(32)
        os.environ[_SECRET_ENV_KEY] = new_secret
        try:
            if _ENV_FILE.exists():
                existing = _ENV_FILE.read_text(encoding="utf-8")
                if not existing.endswith("\n"):
                    existing += "\n"
                existing += f"{_SECRET_ENV_KEY}={new_secret}\n"
                _ENV_FILE.write_text(existing, encoding="utf-8")
            else:
                _ENV_FILE.write_text(f"{_SECRET_ENV_KEY}={new_secret}\n", encoding="utf-8")
        except Exception:
            pass

        return new_secret


HOST_REGEX = re.compile(r"^(127\.0\.0\.1|localhost)(:\d+)?$", re.IGNORECASE)


def verify_host_header():
    """DNS-rebinding defense: reject requests with unrecognized Host header."""
    host = request.host
    if not host or not HOST_REGEX.match(host):
        return jsonify({"error": "Bad Request: Invalid Host header"}), 400


def enforce_session_timeout():
    """Enforces 15-minute server-side idle timeout."""
    # Ensure CSRF token exists for the session
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    username = session.get("username")
    if not username:
        return

    now = time.time()
    last_act = session.get("last_activity")

    if last_act is not None and (now - float(last_act)) > SESSION_IDLE_TIMEOUT_SECONDS:
        session.clear()
        session["csrf_token"] = secrets.token_hex(32)
        if request.path.startswith("/api/"):
            return jsonify({"error": "Session expired", "status": "expired"}), 401
        return redirect(url_for("login", expired=1))

    # Update last_activity only for non-GET requests and non-/api/ page loads.
    # Background polling GET /api/* must not extend the 15-minute idle session timeout.
    if request.method != "GET" or not request.path.startswith("/api/"):
        session["last_activity"] = now


def verify_csrf():
    """
    Verifies CSRF token on all state-changing HTTP methods (POST, PUT, DELETE, PATCH).
    Token is read from X-CSRF-Token header or form data, verified via constant-time compare.
    """
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        expected = session.get("csrf_token")
        if not expected or not isinstance(expected, str):
            return jsonify({"error": "CSRF verification failed: missing session token"}), 403

        provided = request.headers.get("X-CSRF-Token")
        if not provided and request.form:
            provided = request.form.get("csrf_token")

        if not provided or not isinstance(provided, str):
            return jsonify({"error": "CSRF verification failed: invalid token"}), 403

        # Non-ASCII CSRF defense: guard compare_digest against encoding errors
        try:
            if not hmac.compare_digest(provided.strip(), expected.strip()):
                return jsonify({"error": "CSRF verification failed: invalid token"}), 403
        except Exception:
            return jsonify({"error": "CSRF verification failed: invalid token"}), 403


def apply_security_headers(response):
    """
    Applies strict Content-Security-Policy and response headers.
    No inline script or style execution is permitted.
    """
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'self';"
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"

    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    return response


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("username"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required", "status": "unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def role_required(min_role="guest"):
    """
    Enforces role hierarchy (guest < admin).
    Role is read strictly from server session, never request JSON.
    Violations write an audit event and return 403 JSON or abort 403.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            username = session.get("username")
            if not username:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("login"))

            user_role = session.get("role", "guest")
            role_levels = {"guest": 1, "operator": 2, "admin": 3}

            required_level = role_levels.get(min_role, 1)
            actual_level = role_levels.get(user_role, 0)

            if actual_level < required_level:
                security.logger.log_event(
                    "unauthorized_access",
                    {
                        "path": request.path,
                        "required_role": min_role,
                        "role": user_role,
                        "username": username,
                    },
                )
                if request.path.startswith("/api/"):
                    return jsonify({"error": f"Forbidden: {min_role} role required"}), 403
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator
