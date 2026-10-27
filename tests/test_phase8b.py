"""
Phase 8B — Test Suite: Dashboard Components, Sanitization, Role Gating & Signed Decisions
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from dashboard.components import sanitize_text, status_pill, pulse_dot, pipeline_stepper
from dashboard.pages.approvals import _write_signed_decision, render_approvals
from dashboard.theme import format_ist
import security.auth
import security.signing


# ============================================================================
# 1. COMPONENT SANITIZATION TESTS
# ============================================================================

def test_sanitize_text_escapes_script_tags():
    malicious = "<script>alert('pwned')</script>"
    clean = sanitize_text(malicious)
    assert "<script>" not in clean
    assert "&lt;script&gt;" in clean


def test_sanitize_text_escapes_markdown_links():
    link_injection = "[Click here for free bitcoin](http://evil.com)"
    clean = sanitize_text(link_injection)
    assert clean == "[Click here for free bitcoin](http://evil.com)"
    # When passed to html.escape, brackets and parens remain safe literal text, not HTML


def test_sanitize_text_strips_ansi_codes():
    ansi_input = "\x1b[31;1mRed Critical Alert\x1b[0m\x1b[2J"
    clean = sanitize_text(ansi_input)
    assert "\x1b" not in clean
    assert "Red Critical Alert" in clean


def test_sanitize_text_truncates_10k_chars():
    huge_input = "A" * 10000
    clean = sanitize_text(huge_input, max_len=500)
    assert len(clean) < 600
    assert "... [truncated]" in clean


def test_sanitize_text_safely_handles_dicts_and_lists():
    data = {"rule": "<INJ-001>", "tags": ["admin", "<script>"]}
    clean = sanitize_text(data)
    assert "&lt;INJ-001&gt;" in clean
    assert "&lt;script&gt;" in clean


def test_status_pill_sanitization():
    # Known kinds
    pill_ok = status_pill("ok", "ALLOWED")
    assert 'class="aegis-pill aegis-pill-ok"' in pill_ok
    assert "ALLOWED" in pill_ok

    # Unknown kind falls back to neutral
    pill_unknown = status_pill("super_danger_custom", "WARN")
    assert 'class="aegis-pill aegis-pill-neutral"' in pill_unknown

    # Dangerous payload in text is escaped
    pill_xss = status_pill("danger", "<img src=x onerror=alert(1)>")
    assert "<img" not in pill_xss
    assert "&lt;img" in pill_xss


def test_pulse_dot_normalized_states():
    assert 'aegis-dot-live' in pulse_dot("live")
    assert 'aegis-dot-live' in pulse_dot("online")
    assert 'aegis-dot-offline' in pulse_dot("offline")
    assert 'aegis-dot-warn' in pulse_dot("warn")
    assert 'aegis-dot-unknown' in pulse_dot("random_unknown_state")


# ============================================================================
# 2. ROLE GATING TESTS
# ============================================================================

def test_role_gating_blocks_guest(monkeypatch):
    """Verifies that a guest role is strictly denied access to the Approvals page."""
    import streamlit as st

    # Mock guest session state
    monkeypatch.setattr(st, "session_state", {"authenticated": True, "role": "guest", "username": "guest_user"})

    error_called = False
    stop_called = False

    def mock_error(msg):
        nonlocal error_called
        error_called = True
        assert "Access Denied" in msg

    def mock_stop():
        nonlocal stop_called
        stop_called = True
        raise RuntimeError("streamlit_stop_triggered")

    monkeypatch.setattr(st, "error", mock_error)
    monkeypatch.setattr(st, "stop", mock_stop)

    with pytest.raises(RuntimeError) as exc:
        render_approvals()

    assert "streamlit_stop_triggered" in str(exc.value)
    assert error_called is True
    assert stop_called is True


# ============================================================================
# 3. LOGIN LOCKOUT PATH TESTS
# ============================================================================

def test_login_lockout_after_5_failed_attempts():
    security.auth.create_user("test_lockout_user", "ValidPass123!", "guest")

    for attempt in range(1, 5):
        ok, msg = security.auth.verify_login("test_lockout_user", "WrongPassword!")
        assert ok is False
        assert "attempts remaining" in msg

    # 5th attempt triggers lockout
    ok, msg = security.auth.verify_login("test_lockout_user", "WrongPassword!")
    assert ok is False
    assert "Account locked for 5 minutes" in msg

    # 6th attempt with correct password fails closed
    ok, msg = security.auth.verify_login("test_lockout_user", "ValidPass123!")
    assert ok is False
    assert "Account is locked" in msg


# ============================================================================
# 4. SIGNED DECISION WRITER TESTS
# ============================================================================

def test_signed_decision_writer(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))

    req_id = "test-req-id-1234"
    req_hash = "f" * 64
    _write_signed_decision(req_id, req_hash, approved=True, decided_by="admin_alice")

    dec_file = tmp_path / "approvals" / "decisions" / f"{req_id}.json"
    assert dec_file.exists()

    data = json.loads(dec_file.read_text(encoding="utf-8"))
    assert data["approved"] is True
    assert data["request_id"] == req_id
    assert data["request_hash"] == req_hash
    assert data["decided_by"] == "admin_alice"

    sig = data["signature"]
    assert sig and len(sig) == 64

    # Verify signature
    sig_payload = {
        "approved": data["approved"],
        "decided_at": data["decided_at"],
        "request_hash": data["request_hash"],
        "request_id": data["request_id"],
    }
    assert security.signing.verify(sig_payload, sig) is True

    # Tampered payload fails verification
    tampered_payload = dict(sig_payload)
    tampered_payload["approved"] = False
    assert security.signing.verify(tampered_payload, sig) is False


# ============================================================================
# 5. TIMEZONE CONVERSION TESTS
# ============================================================================

def test_format_ist_correct_offset():
    # 2026-10-27 00:00:00 UTC should be 05:30:00 IST (+5:30)
    utc_dt = datetime(2026, 10, 27, 0, 0, 0, tzinfo=timezone.utc)
    ist_str = format_ist(utc_dt)
    assert "2026-10-27 05:30:00 IST" in ist_str
    assert "IST" in ist_str
