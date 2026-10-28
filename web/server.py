"""
web/server.py - AegisAgent Web Application Server

Hand-built Flask web server bound strictly to 127.0.0.1:8501.
Replaces the Streamlit frontend with a high-performance, air-gapped web interface.
"""

from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
import secrets
import time
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import security.auth
import security.health
import security.logger
from web.api import api_bp
from web.guards import (
    apply_security_headers,
    enforce_session_timeout,
    get_web_secret,
    login_required,
    role_required,
    verify_csrf,
    verify_host_header,
)
import threading

ROOT_DIR = Path(__file__).resolve().parent.parent

_setup_lock = threading.Lock()


def has_registered_users() -> bool:
    """Checks if any user account has been registered in data/users.json."""
    data = security.auth._load_data()
    return bool(data.get("users"))


def create_app() -> Flask:
    """Flask application factory."""
    app = Flask(
        __name__,
        template_folder=str(ROOT_DIR / "web" / "templates"),
        static_folder=str(ROOT_DIR / "web" / "static"),
    )

    # Cryptographic Session Configuration
    app.secret_key = get_web_secret()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,  # False for local HTTP 127.0.0.1 execution
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    )

    # Security Request Lifecycle Hooks
    @app.before_request
    def check_host():
        return verify_host_header()

    @app.before_request
    def check_timeout_and_csrf():
        timeout_res = enforce_session_timeout()
        if timeout_res:
            return timeout_res
        return verify_csrf()

    @app.after_request
    def add_security_headers(response):
        return apply_security_headers(response)

    # Register API Blueprint
    app.register_blueprint(api_bp)

    # Page Routes
    @app.route("/", methods=["GET"])
    def index():
        if session.get("username"):
            return redirect(url_for("overview"))
        if not has_registered_users():
            return redirect(url_for("setup"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        # First-run setup redirect if no users exist
        if not has_registered_users():
            return redirect(url_for("setup"))

        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            success, res = security.auth.verify_login(username, password)
            if success:
                session.clear()
                session.permanent = True
                session["username"] = username
                session["role"] = res
                session["real_role"] = res
                session["last_activity"] = time.time()
                session["csrf_token"] = secrets.token_hex(32)
                session["console_session_id"] = "sess_" + secrets.token_hex(8)
                return redirect(url_for("overview"))
            else:
                return render_template("login.html", error=res, expired=False), 401

        # GET request
        if session.get("username"):
            return redirect(url_for("overview"))

        expired = request.args.get("expired") == "1"
        return render_template("login.html", error=None, expired=expired)

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        # Once any user exists, setup is permanently disabled
        if has_registered_users():
            return redirect(url_for("login"))

        if request.method == "POST":
            with _setup_lock:
                if has_registered_users():
                    return redirect(url_for("login"))

                username = (request.form.get("username") or "").strip()
                password = request.form.get("password") or ""
                confirm = request.form.get("confirm_password") or ""

                if not username or not password:
                    return render_template("setup.html", error="Username and password are required."), 400

                if password != confirm:
                    return render_template("setup.html", error="Passwords do not match."), 400

                try:
                    security.auth.create_user(username, password, role="admin")
                    session.clear()
                    session.permanent = True
                    session["username"] = username
                    session["role"] = "admin"
                    session["real_role"] = "admin"
                    session["last_activity"] = time.time()
                    session["csrf_token"] = secrets.token_hex(32)
                    session["console_session_id"] = "sess_" + secrets.token_hex(8)
                    return redirect(url_for("overview"))
                except Exception as e:
                    return render_template("setup.html", error=f"Setup failed: {e}"), 400

        return render_template("setup.html", error=None)

    @app.route("/logout", methods=["POST"])
    def logout():
        username = session.get("username")
        if username:
            security.auth.logout(username)
        session.clear()
        session["csrf_token"] = secrets.token_hex(32)
        return redirect(url_for("login"))

    @app.route("/overview", methods=["GET"])
    @login_required
    def overview():
        return render_template("overview.html", active_page="overview")

    @app.route("/console", methods=["GET"])
    @login_required
    def console():
        health = security.health.get_system_health()
        worker_alive = bool(health.get("worker", {}).get("alive"))
        return render_template("console.html", active_page="console", worker_alive=worker_alive)

    @app.route("/approvals", methods=["GET"])
    @login_required
    @role_required("admin")
    def approvals():
        return render_template("approvals.html", active_page="approvals")

    # Error Handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Bad Request", "detail": str(e)}), 400
        return f"<h3>400 Bad Request</h3><p>{e}</p>", 400

    @app.errorhandler(403)
    def handle_forbidden(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Forbidden", "detail": "Access denied"}), 403
        return "<h3>403 Access Denied</h3><p>Administrative privileges are required to access this resource.</p>", 403

    @app.errorhandler(404)
    def handle_not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Endpoint Not Found"}), 404
        return "<h3>404 Page Not Found</h3><p>The requested page does not exist.</p>", 404

    @app.errorhandler(500)
    def handle_internal_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal Server Error"}), 500
        return "<h3>500 Internal Server Error</h3><p>An unexpected error occurred.</p>", 500

    return app


if __name__ == "__main__":
    app = create_app()
    print("=" * 60)
    print(" AegisAgent Web Security Gateway ".center(60, "="))
    print(" Local address: http://127.0.0.1:8501")
    print(" Host protection: Enforcing 127.0.0.1 / localhost")
    print(" Session idle timeout: 15 minutes (server-side)")
    print(" 100% offline, zero CDN dependencies")
    print("=" * 60)
    app.run(host="127.0.0.1", port=8501, debug=False)
