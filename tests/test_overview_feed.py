"""
tests/test_overview_feed.py - Verification tests for v2 Overview feed safety, filtering, and mapping.
Requirements:
(a) unauthenticated -> 401/redirect
(b) guest response has no prompt/reason fields or rule details
(c) system events (login, logout, worker start, hardware command, role change, anchor) never appear in the feed
(d) a decision with no known value is never shown as Blocked (it is skipped)
(e) mapping: detection->Detection, param_guard->Parameters, rbac->Role, approval->Approval, output_scan->Output scan
"""

import json
import pytest
from web.server import create_app
import security.logger


@pytest.fixture
def app():
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


def test_overview_unauthenticated_rejected(app):
    """(a) Unauthenticated requests to /api/overview return 401, /overview redirects to login."""
    with app.test_client() as c:
        res_api = c.get("/api/overview")
        assert res_api.status_code == 401
        data = res_api.get_json()
        assert "error" in data

        res_page = c.get("/overview")
        assert res_page.status_code in (302, 401)
        if res_page.status_code == 302:
            assert "/login" in res_page.headers.get("Location", "")


def test_overview_guest_safety_no_leak(app):
    """(b) Guest responses must not leak prompt text, internal reason text, args, or specific rule IDs."""
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "guest_user"
            sess["role"] = "guest"
            sess["real_role"] = "guest"

        res = c.get("/api/overview")
        assert res.status_code == 200
        data = res.get_json()
        assert "v2_decisions" in data
        feed = data["v2_decisions"]

        for item in feed:
            # Sensitive fields must never be exposed
            assert "prompt" not in item, f"Leak: 'prompt' found in feed item {item.get('id')}"
            assert "reason" not in item, f"Leak: 'reason' found in feed item {item.get('id')}"
            assert "args" not in item, f"Leak: 'args' found in feed item {item.get('id')}"
            assert "rule_ids" not in item, f"Leak: 'rule_ids' found in feed item {item.get('id')}"

            # Rule identifier must be generic for guests
            assert item.get("rule") in ("policy", "none", ""), f"Specific rule leaked: {item.get('rule')}"

            # Text and why should not disclose raw rule IDs
            text = item.get("text", "")
            why = item.get("why", "")
            assert "INJ-" not in text, f"Rule ID leaked in text: {text}"
            assert "INJ-" not in why, f"Rule ID leaked in why: {why}"
            assert "Gate rule:" not in why, f"Internal gate rule leaked in why: {why}"


def test_overview_system_events_never_appear_in_feed(app, tmp_path, monkeypatch):
    """(c) System events (login, logout, worker start, hardware command, role change, anchor) never appear in the feed."""
    test_log = tmp_path / "test_audit_log.jsonl"
    monkeypatch.setattr(security.logger, "get_log_file", lambda: test_log)
    monkeypatch.setattr("web.api._get_log_file", lambda: test_log)

    # Log various system events
    security.logger.log_event("login_success", {"username": "alice", "event": "login_success"})
    security.logger.log_event("login_failure", {"username": "mallory", "event": "login_failure"})
    security.logger.log_event("logout", {"username": "alice", "event": "logout"})
    security.logger.log_event("worker_started_by_admin", {"admin": "bob", "pid": 1234, "event": "worker_started_by_admin"})
    security.logger.log_event("hardware_command", {"command": "SET_LIGHT_ON", "ok": True, "event": "hardware_command"})
    security.logger.log_event("role_change", {"old_role": "guest", "new_role": "admin", "event": "role_change"})
    security.logger.log_event("anchor", {"hash": "abc", "event": "anchor"})
    security.logger.log_event("intent_scope", {"scope": ["turn_light_on"], "event": "intent_scope"})

    # Log one real turn_summary decision
    security.logger.log_turn_summary(
        request_id="req_turn_valid_01",
        session_id="sess_valid",
        decision="ALLOW",
        tool="turn_light_on",
        rule_ids=[],
        latency_ms=45.0,
        scope=["turn_light_on"],
        tainted=False,
        role="admin"
    )

    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"

        res = c.get("/api/overview")
        assert res.status_code == 200
        feed = res.get_json().get("v2_decisions", [])

        # Feed must only contain the 1 turn_summary decision, not any of the 8 system events
        assert len(feed) == 1
        assert feed[0]["raw_decision"] == "ALLOW"
        assert feed[0]["tool"] == "turn_light_on"


def test_overview_unknown_decision_skipped_not_blocked(app, tmp_path, monkeypatch):
    """(d) A decision with no known value or UNKNOWN is never shown as Blocked (it is skipped)."""
    test_log = tmp_path / "test_audit_log.jsonl"
    monkeypatch.setattr(security.logger, "get_log_file", lambda: test_log)
    monkeypatch.setattr("web.api._get_log_file", lambda: test_log)

    # Log turn summaries with unknown / empty decisions
    security.logger.log_event("turn_summary", {"event": "turn_summary", "decision": "UNKNOWN", "request_id": "r1"})
    security.logger.log_event("turn_summary", {"event": "turn_summary", "decision": "", "request_id": "r2"})
    security.logger.log_event("turn_summary", {"event": "turn_summary", "decision": "INFO", "request_id": "r3"})
    security.logger.log_event("turn_summary", {"event": "turn_summary", "decision": None, "request_id": "r4"})

    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"

        res = c.get("/api/overview")
        assert res.status_code == 200
        feed = res.get_json().get("v2_decisions", [])
        assert len(feed) == 0, f"Expected unknown decisions to be skipped, got {feed}"


def test_overview_gate_mappings(app, tmp_path, monkeypatch):
    """(e) Mapping: detection->Detection, param_guard->Parameters, rbac->Role, approval->Approval, output_scan->Output scan."""
    test_log = tmp_path / "test_audit_log.jsonl"
    monkeypatch.setattr(security.logger, "get_log_file", lambda: test_log)
    monkeypatch.setattr("web.api._get_log_file", lambda: test_log)

    mappings_to_test = [
        ("detection", "Detection", 0),
        ("param_guard", "Parameters", 4),
        ("rbac", "Role", 3),
        ("approval", "Approval", 6),
        ("output_scan", "Output scan", 8),
    ]

    for stage_key, expected_label, expected_idx in mappings_to_test:
        security.logger.log_event("turn_summary", {
            "event": "turn_summary",
            "decision": "BLOCK",
            "stopped_at": stage_key,
            "request_id": f"req_{stage_key}",
            "tool": "test_tool",
            "role": "admin",
            "timestamp": "2026-11-07T12:00:00Z"
        })

    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"

        res = c.get("/api/overview")
        assert res.status_code == 200
        feed = res.get_json().get("v2_decisions", [])
        assert len(feed) == len(mappings_to_test)

        # Feed is reversed (most recent first)
        stage_items = {item.get("raw_layer"): item for item in feed}
        for stage_key, expected_label, expected_idx in mappings_to_test:
            assert stage_key in stage_items, f"Missing stage {stage_key} in feed: {list(stage_items.keys())}"
            item = stage_items[stage_key]
            assert item["stage_name"] == expected_label, f"Mismatch for {stage_key}: expected {expected_label}, got {item['stage_name']}"
            assert item["stop"] == expected_idx, f"Mismatch index for {stage_key}: expected {expected_idx}, got {item['stop']}"


def test_console_poll_carries_stopped_stage(app, tmp_path, monkeypatch):
    """The console poll response JSON must carry the stopped_stage where the real pipeline stopped."""
    data_dir = tmp_path / "data"
    outbox_dir = data_dir / "chat" / "outbox"
    outbox_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("web.api._get_data_dir", lambda: data_dir)

    req_id = "req_test_stop_stage_01"
    outbox_file = outbox_dir / f"{req_id}.jsonl"

    # Simulate worker writing outbox steps stopping at detection
    with open(outbox_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"owner": "admin", "request_id": req_id}) + "\n")
        f.write(json.dumps({"stage": "detection", "status": "block", "detail": {"reason": "Instruction override"}}) + "\n")
        f.write(json.dumps({"final": True, "reply": "I can't do that.", "decision": "BLOCK", "stopped_at": "detection"}) + "\n")

    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"

        res = c.get(f"/api/console/poll/{req_id}")
        assert res.status_code == 200
        data = res.get_json()
        assert data.get("stopped_stage") == "detection"

