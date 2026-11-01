"""
Phase 8B -- Ported Security Test Suite (Zero-Streamlit Dependency)

Ported from legacy test_phase8b.py:
1. Role gating enforcement on approvals endpoints (guest blocked with 403).
2. Login lockout enforcement after 5 failed attempts (security.auth).
3. Signed decision writer HMAC-SHA256 generation & tamper rejection (security.signing).
4. IST timezone conversion (+5:30 offset).
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pytest

import security.auth
import security.signing
from web.api import _format_ist
from web.server import create_app


# ============================================================================
# 1. ROLE GATING TESTS (ADMIN-ONLY APPROVALS)
# ============================================================================

def test_role_gating_blocks_guest_on_approvals_api():
    """Verifies that a guest role is strictly denied access to the Approvals API."""
    app = create_app()
    client = app.test_client()

    # Simulate an authenticated guest session
    with client.session_transaction() as sess:
        sess["username"] = "guest_operator"
        sess["role"] = "guest"
        sess["_login_time"] = datetime.now(timezone.utc).isoformat()
        sess["_last_activity"] = datetime.now(timezone.utc).isoformat()

    # Guest accessing admin-only approvals pending
    resp_pending = client.get("/api/approvals/pending")
    assert resp_pending.status_code == 403
    data = resp_pending.get_json()
    assert "admin role required" in data.get("error", "").lower()

    # Guest attempting to decide an approval
    resp_decide = client.post("/api/approvals/decide", json={"request_id": "req-1", "approved": True})
    assert resp_decide.status_code == 403


# ============================================================================
# 2. LOGIN LOCKOUT PATH TESTS
# ============================================================================

def test_login_lockout_after_5_failed_attempts():
    """Verifies that an account is locked out after 5 consecutive failed logins."""
    security.auth.create_user("test_lockout_user_clean", "ValidPass123!", "guest")

    for attempt in range(1, 5):
        ok, msg = security.auth.verify_login("test_lockout_user_clean", "WrongPassword!")
        assert ok is False
        assert msg == "Invalid username or password"

    # 5th attempt triggers lockout
    ok, msg = security.auth.verify_login("test_lockout_user_clean", "WrongPassword!")
    assert ok is False
    assert msg == "Invalid username or password"

    # 6th attempt with correct password fails closed due to active lockout
    ok, msg = security.auth.verify_login("test_lockout_user_clean", "ValidPass123!")
    assert ok is False
    assert msg == "Invalid username or password"


# ============================================================================
# 3. SIGNED DECISION WRITER TESTS
# ============================================================================

def test_signed_decision_writer(tmp_path, monkeypatch):
    """Verifies HMAC-SHA256 signature generation and tamper rejection on decision payloads."""
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))

    decisions_dir = tmp_path / "approvals" / "decisions"
    decisions_dir.mkdir(parents=True, exist_ok=True)

    req_id = "test-req-id-1234"
    req_hash = "f" * 64
    decided_at = datetime.now(timezone.utc).isoformat()

    sig_payload = {
        "approved": True,
        "decided_at": decided_at,
        "request_hash": req_hash,
        "request_id": req_id,
    }
    sig = security.signing.sign(sig_payload)

    data = {
        "approved": True,
        "decided_at": decided_at,
        "decided_by": "admin_alice",
        "reason": "Approved by administrator (admin_alice)",
        "request_hash": req_hash,
        "request_id": req_id,
        "signature": sig,
    }

    decision_file = decisions_dir / f"{req_id}.json"
    decision_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    assert decision_file.exists()
    loaded = json.loads(decision_file.read_text(encoding="utf-8"))
    assert loaded["approved"] is True
    assert loaded["request_id"] == req_id
    assert loaded["request_hash"] == req_hash
    assert loaded["decided_by"] == "admin_alice"

    # Verify signature
    assert security.signing.verify(sig_payload, sig) is True

    # Tampered payload fails verification
    tampered_payload = dict(sig_payload)
    tampered_payload["approved"] = False
    assert security.signing.verify(tampered_payload, sig) is False


# ============================================================================
# 4. TIMEZONE CONVERSION TESTS
# ============================================================================

def test_format_ist_correct_offset():
    """Verifies that UTC timestamps are correctly formatted to IST (+5:30)."""
    # 2026-10-27 00:00:00 UTC should be 05:30:00 IST (+5:30)
    utc_dt = datetime(2026, 10, 27, 0, 0, 0, tzinfo=timezone.utc)
    ist_str = _format_ist(utc_dt)
    assert "05:30:00 IST" in ist_str
    assert "IST" in ist_str


# ============================================================================
# 5. CONSOLE SANITIZATION & CLIENT-SIDE TEXTCONTENT SAFETY TESTS
# ============================================================================

def test_sanitize_for_console_strips_ansi_and_control_codes():
    """Verifies that terminal injection vectors (ANSI escapes, control codes) are stripped."""
    from security.approval import sanitize_for_console

    # ANSI color and cursor jump sequence
    ansi_input = "\x1b[31;1mCRITICAL ALERT\x1b[0m\x1b[2J"
    clean = sanitize_for_console(ansi_input)
    assert "\x1b" not in clean
    assert "CRITICAL ALERT" in clean

    # Dangerous control characters (null byte, bell, backspace)
    ctrl_input = "Admin\x00_Operation\x07\x08_Confirmed"
    clean_ctrl = sanitize_for_console(ctrl_input)
    assert "\x00" not in clean_ctrl
    assert "\x07" not in clean_ctrl
    assert "\x08" not in clean_ctrl
    assert clean_ctrl == "Admin_Operation_Confirmed"

    # Truncation cap to prevent console buffer flooding
    huge_input = "X" * 1000
    truncated = sanitize_for_console(huge_input, max_len=150)
    assert "... [truncated]" in truncated
    assert len(truncated) <= 150 + len("... [truncated]")


def test_audit_js_uses_textcontent_without_innerhtml():
    """Verifies that audit.js strictly uses textContent and safe DOM construction with 0 innerHTML calls."""
    audit_js_path = Path(__file__).resolve().parent.parent / "web" / "static" / "js" / "audit.js"
    assert audit_js_path.exists()
    content = audit_js_path.read_text(encoding="utf-8")

    # Audit page must never call innerHTML
    lines_with_innerhtml = [
        f"L{i+1}: {line.strip()}"
        for i, line in enumerate(content.splitlines())
        if ".innerHTML" in line and not line.strip().startswith("//") and not line.strip().startswith("*")
    ]
    assert len(lines_with_innerhtml) == 0, f"Unexpected innerHTML calls in audit.js: {lines_with_innerhtml}"
    assert "textContent" in content

