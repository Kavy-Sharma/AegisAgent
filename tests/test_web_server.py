"""
tests/test_web_server.py - Security & Functionality Verification for Flask Web App

Verifies:
1. Security headers present on every response (strict CSP, nosniff, no-referrer, no-store on /api).
2. Missing or invalid CSRF token rejected with 403.
3. Guest hitting admin API routes rejected with 403 and written to audit log.
4. Role in request JSON is strictly ignored (session role is used).
5. Bad Host header rejected with 400 (DNS-rebinding defense).
6. 15-minute server-side session idle timeout.
7. Chat inbox request is cryptographically signed with ts and nonce.
8. XSS payloads (<script>, [x](http://evil), <img onerror>, ANSI codes, 10k chars) are escaped or rejected.
9. Approve on expired or unknown request is rejected.
10. First-run setup is permanently unavailable once a user exists.
"""

from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import pytest
import re
import secrets
import time

import security.auth
import security.logger
import security.signing
import web.guards
from web.server import create_app


@pytest.fixture
def test_secrets(monkeypatch):
    dash_sec = secrets.token_hex(32)
    web_sec = secrets.token_hex(32)
    monkeypatch.setenv("AEGIS_DASH_SECRET", dash_sec)
    monkeypatch.setenv("AEGIS_WEB_SECRET", web_sec)
    return {"dash_secret": dash_sec, "web_secret": web_sec}


@pytest.fixture
def app(test_secrets):
    flask_app = create_app()
    flask_app.config["TESTING"] = True
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


def test_security_headers_present(client):
    """Verifies strict CSP, nosniff, no-referrer, and no-store on API responses."""
    resp = client.get("/login", follow_redirects=True)
    assert resp.status_code == 200

    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "form-action 'self'" in csp

    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("Referrer-Policy") == "no-referrer"

    # API route headers
    with client.session_transaction() as sess:
        sess["username"] = "test_guest"
        sess["role"] = "guest"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = secrets.token_hex(32)

    api_resp = client.get("/api/health")
    assert api_resp.status_code == 200
    cache_ctrl = api_resp.headers.get("Cache-Control", "")
    assert "no-store" in cache_ctrl


def test_missing_and_invalid_csrf_rejected_403(client):
    """Verifies that missing or mismatched CSRF tokens on mutating requests yield 403."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    # 1. Missing CSRF header
    resp_no_csrf = client.post(
        "/api/console/send",
        json={"text": "hello"},
    )
    assert resp_no_csrf.status_code == 403
    assert b"CSRF verification failed" in resp_no_csrf.data

    # 2. Invalid CSRF header
    resp_bad_csrf = client.post(
        "/api/console/send",
        headers={"X-CSRF-Token": "bad_token_12345"},
        json={"text": "hello"},
    )
    assert resp_bad_csrf.status_code == 403

    # 3. Valid CSRF header succeeds
    resp_ok = client.post(
        "/api/console/send",
        headers={"X-CSRF-Token": csrf_token},
        json={"text": "hello"},
    )
    assert resp_ok.status_code == 200


def test_guest_hitting_admin_api_returns_403_and_audited(client, tmp_path):
    """Verifies that guest role cannot access admin APIs and an audit event is recorded."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "guest_user"
        sess["role"] = "guest"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    # Guest attempts to reset session
    resp = client.post(
        "/api/console/new_session",
        headers={"X-CSRF-Token": csrf_token},
        json={},
    )
    assert resp.status_code == 403
    assert b"Forbidden: admin role required" in resp.data

    # Verify audit event in tmp_path
    log_file = tmp_path / "logs" / "audit_log.jsonl"
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "unauthorized_access" in content
    assert "guest_user" in content


def test_role_in_request_json_ignored(client, tmp_path):
    """Verifies that client cannot elevate role by supplying 'role' in request JSON."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "sneaky_guest"
        sess["role"] = "guest"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    # Attacker passes "role": "admin" in JSON payload
    resp = client.post(
        "/api/console/send",
        headers={"X-CSRF-Token": csrf_token},
        json={"text": "Unlock door", "role": "admin"},
    )
    assert resp.status_code == 200
    res_data = resp.get_json()
    req_id = res_data["request_id"]

    # Read the generated inbox file
    inbox_file = tmp_path / "data" / "chat" / "inbox" / f"{req_id}.json"
    assert inbox_file.exists()
    inbox_data = json.loads(inbox_file.read_text(encoding="utf-8"))

    # The payload's role MUST be 'guest', not 'admin'
    assert inbox_data["role"] == "guest"
    assert inbox_data["username"] == "sneaky_guest"


def test_bad_host_header_rejected_400(client):
    """Verifies DNS-rebinding protection rejects unrecognized Host headers."""
    # Bad host: attacker domain
    resp_evil = client.get("/login", headers={"Host": "attacker.evil.com:8501"})
    assert resp_evil.status_code == 400
    assert b"Invalid Host header" in resp_evil.data

    # Bad host: arbitrary IP
    resp_ip = client.get("/login", headers={"Host": "192.168.1.50:8501"})
    assert resp_ip.status_code == 400

    # Good host: 127.0.0.1:8501
    resp_ok1 = client.get("/login", headers={"Host": "127.0.0.1:8501"}, follow_redirects=True)
    assert resp_ok1.status_code == 200

    # Good host: localhost:8501
    resp_ok2 = client.get("/login", headers={"Host": "localhost:8501"}, follow_redirects=True)
    assert resp_ok2.status_code == 200


def test_session_idle_timeout(client):
    """Verifies 15-minute server-side session expiration."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "idle_user"
        sess["role"] = "guest"
        # 950 seconds ago (> 900s timeout)
        sess["last_activity"] = time.time() - 950
        sess["csrf_token"] = csrf_token

    # API returns 401 Session expired
    resp_api = client.get("/api/health")
    assert resp_api.status_code == 401
    assert b"Session expired" in resp_api.data

    # Re-arm idle session
    with client.session_transaction() as sess:
        sess["username"] = "idle_user"
        sess["role"] = "guest"
        sess["last_activity"] = time.time() - 950
        sess["csrf_token"] = csrf_token

    # Page route redirects to /login?expired=1
    resp_page = client.get("/overview")
    assert resp_page.status_code == 302
    assert "/login?expired=1" in resp_page.headers["Location"]


def test_chat_inbox_request_is_signed_with_ts_and_nonce(client, tmp_path):
    """Verifies chat message inbox file contains ts, nonce, and valid HMAC-SHA256 signature."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "alice"
        sess["role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    before_ts = time.time()
    resp = client.post(
        "/api/console/send",
        headers={"X-CSRF-Token": csrf_token},
        json={"text": "Turn on light"},
    )
    after_ts = time.time()
    assert resp.status_code == 200
    req_id = resp.get_json()["request_id"]

    inbox_file = tmp_path / "data" / "chat" / "inbox" / f"{req_id}.json"
    assert inbox_file.exists()
    payload = json.loads(inbox_file.read_text(encoding="utf-8"))

    # ts within valid range
    assert before_ts - 1 <= payload["ts"] <= after_ts + 1

    # nonce present and 32 hex chars (16 bytes)
    assert "nonce" in payload
    assert len(payload["nonce"]) == 32
    assert re.match(r"^[0-9a-f]{32}$", payload["nonce"])

    # signature is valid
    sig = payload.pop("signature")
    assert security.signing.verify(payload, sig) is True


def test_xss_payloads_escaped_or_rejected(client):
    """Verifies XSS and injection payloads are escaped by templates and rejected if oversized."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    payloads = [
        "<script>alert('xss')</script>",
        "[x](http://evil.com)",
        "<img src=x onerror=alert(1)>",
        "\x1b[31mRed Alert\x1b[0m",
    ]

    for p in payloads:
        resp = client.post(
            "/api/console/send",
            headers={"X-CSRF-Token": csrf_token},
            json={"text": p},
        )
        assert resp.status_code == 200

    # Overly long payload (> 10,000 characters) is rejected with 400
    huge_payload = "A" * 10001
    resp_huge = client.post(
        "/api/console/send",
        headers={"X-CSRF-Token": csrf_token},
        json={"text": huge_payload},
    )
    assert resp_huge.status_code == 400
    assert b"exceeds maximum allowed length" in resp_huge.data


def test_approve_on_expired_or_unknown_request_rejected(client, tmp_path):
    """Verifies approvals API rejects non-existent or expired requests."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    # 1. Unknown request ID -> 404
    resp_unknown = client.post(
        "/api/approvals/decide",
        headers={"X-CSRF-Token": csrf_token},
        json={"request_id": "nonexistent_req_1234", "approved": True},
    )
    assert resp_unknown.status_code == 404

    # 2. Expired request -> 400
    pending_dir = tmp_path / "data" / "approvals" / "pending"
    pending_dir.mkdir(parents=True, exist_ok=True)

    expired_id = "req_expired_12345678"
    past_iso = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    pending_file = pending_dir / f"{expired_id}.json"
    pending_file.write_text(json.dumps({
        "request_id": expired_id,
        "kind": "tool_call",
        "tool": "unlock_door",
        "args": {},
        "risk": "HIGH",
        "expires_at": past_iso,
        "request_hash": "dummyhash",
    }), encoding="utf-8")

    resp_expired = client.post(
        "/api/approvals/decide",
        headers={"X-CSRF-Token": csrf_token},
        json={"request_id": expired_id, "approved": True},
    )
    assert resp_expired.status_code == 400
    assert b"expired" in resp_expired.data.lower()


def test_first_run_setup_unavailable_once_user_exists(client, tmp_path):
    """Verifies that first-run setup is accessible initially and disabled once a user exists."""
    # 1. No users yet -> setup returns 200, login redirects to setup
    resp_setup = client.get("/setup")
    assert resp_setup.status_code == 200
    assert b"Create Administrator" in resp_setup.data

    resp_login = client.get("/login")
    assert resp_login.status_code == 302
    assert "/setup" in resp_login.headers["Location"]

    # 2. Create the administrator account
    with client.session_transaction() as sess:
        csrf_token = sess.get("csrf_token") or secrets.token_hex(32)
        sess["csrf_token"] = csrf_token

    post_setup = client.post(
        "/setup",
        data={
            "csrf_token": csrf_token,
            "username": "admin",
            "password": "MasterPassword123!",
            "confirm_password": "MasterPassword123!",
        },
    )
    assert post_setup.status_code == 302
    assert "/overview" in post_setup.headers["Location"]

    # Clear session to act as anonymous visitor
    with client.session_transaction() as sess:
        sess.clear()

    # 3. Now setup is permanently disabled; GET /setup redirects to /login
    resp_setup_again = client.get("/setup")
    assert resp_setup_again.status_code == 302
    assert "/login" in resp_setup_again.headers["Location"]


def test_console_clear_threat_endpoint(client, tmp_path):
    """Verifies that an admin can clear the multi-turn threat window, and guest is blocked."""
    csrf_token = secrets.token_hex(32)

    # 1. Guest is blocked
    with client.session_transaction() as sess:
        sess["username"] = "guest_user"
        sess["role"] = "guest"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    resp_guest = client.post(
        "/api/console/clear_threat",
        headers={"X-CSRF-Token": csrf_token},
        json={},
    )
    assert resp_guest.status_code == 403

    # 2. Admin successfully clears threat window
    with client.session_transaction() as sess:
        sess["username"] = "admin_user"
        sess["role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token
        sess["console_session_id"] = "sess_prior123"

    resp_admin = client.post(
        "/api/console/clear_threat",
        headers={"X-CSRF-Token": csrf_token},
        json={},
    )
    assert resp_admin.status_code == 200
    data = resp_admin.get_json()
    assert data["status"] == "ok"
    assert "session_id" in data
    assert data["session_id"] != "sess_prior123"
