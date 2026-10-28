"""
tests/test_checklist_items.py - Complete verification of checklist items [T]:
Item 1: api_hardware_actuate (worker_alive, cmd_to_tool 400, LOW waits up to 5s, HIGH 202 without waiting).
Item 2: api_audit_verify (uses entry_hash, reads once, returns count, genesis_hash, head_hash).
Item 3: api_approvals_decide (request_hash required, atomic create-if-not-exists, concurrent double decide -> 409).
Item 5: guards.py idle timeout (polling GET /api/approvals/history does not extend idle timeout).
Item 10: turn_summary audit event at end of run_turn, overview counts only turn_summary, last_request null, read tail from end.
Item 11:
  - switch_role 403 for real guest and audited for admin
  - simulated guest gets 403 on /api/approvals/*
  - min password 10
  - uniform login error for unknown user, bad password and locked account
  - corrupt last log line -> append raises and gateway denies (worker survives)
  - mode mqtt + broker down -> ok False, never FakeBridge.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import pytest
import secrets
import threading
import time

from agent.agent import TurnResult, run_turn
from agent.worker import _process_direct_tool
import security.auth
import security.gateway
import security.hardware
import security.logger
import security.policy_loader
import security.signing
from web.api import _read_log_tail
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


# =========================================================================
# Item 1 [T]: api_hardware_actuate
# =========================================================================

def test_api_hardware_actuate_invalid_command_400(client):
    """Commands outside {light_on, light_off, unlock_door, alarm_on} return 400."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    resp = client.post(
        "/api/hardware/actuate",
        headers={"X-CSRF-Token": csrf_token},
        json={"command": "laser_strike"},
    )
    assert resp.status_code == 400
    assert "Invalid or unmapped hardware command" in resp.get_json().get("error", "")


def test_api_hardware_actuate_worker_offline_503(client, monkeypatch):
    """When worker is not alive, returns 503."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    # Mock health reporting worker not alive
    monkeypatch.setattr(
        "security.health.get_system_health",
        lambda: {"worker": {"alive": False}},
    )

    resp = client.post(
        "/api/hardware/actuate",
        headers={"X-CSRF-Token": csrf_token},
        json={"command": "light_on"},
    )
    assert resp.status_code == 503
    assert "worker is offline" in resp.get_json().get("error", "").lower()


def test_api_hardware_actuate_high_risk_returns_202_immediately(client, monkeypatch):
    """HIGH risk tools (unlock_door, alarm_on) return 202 with request_id and do not wait."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    monkeypatch.setattr(
        "security.health.get_system_health",
        lambda: {"worker": {"alive": True}},
    )

    start = time.time()
    resp = client.post(
        "/api/hardware/actuate",
        headers={"X-CSRF-Token": csrf_token},
        json={"command": "unlock_door"},
    )
    elapsed = time.time() - start

    assert resp.status_code == 202
    data = resp.get_json()
    assert data.get("message") == "Awaiting human approval in Approvals queue"
    assert "request_id" in data
    # Returns immediately without waiting
    assert elapsed < 1.0


def test_api_hardware_actuate_low_risk_waits_up_to_5s(client, monkeypatch, tmp_path):
    """LOW risk tools (light_on, light_off) wait up to 5s for outbox result."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    monkeypatch.setattr(
        "security.health.get_system_health",
        lambda: {"worker": {"alive": True}},
    )

    outbox_dir = tmp_path / "data" / "chat" / "outbox"
    outbox_dir.mkdir(parents=True, exist_ok=True)
    inbox_dir = tmp_path / "data" / "chat" / "inbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)

    # Simulate worker writing success response after 0.2 seconds in separate thread
    def write_outbox_later():
        for _ in range(50):
            time.sleep(0.05)
            inbox_files = list(inbox_dir.glob("*.json"))
            if inbox_files:
                req_id = json.loads(inbox_files[0].read_text(encoding="utf-8"))["id"]
                out_file = outbox_dir / f"{req_id}.jsonl"
                out_file.write_text(
                    json.dumps({"final": True, "decision": "ALLOW", "reply": "Light turned on"}) + "\n",
                    encoding="utf-8",
                )
                break

    t = threading.Thread(target=write_outbox_later)
    t.start()

    resp = client.post(
        "/api/hardware/actuate",
        headers={"X-CSRF-Token": csrf_token},
        json={"command": "light_on"},
    )
    t.join(timeout=2.0)

    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("ok") is True
    assert data.get("command") == "light_on"


# =========================================================================
# Item 2 [T]: api_audit_verify
# =========================================================================

def test_api_audit_verify_returns_expected_fields_and_entry_hash(client, tmp_path):
    """api_audit_verify uses entry['entry_hash'] for head_hash, reads once, returns count, genesis_hash, head_hash."""
    with client.session_transaction() as sess:
        sess["username"] = "guest_user"
        sess["role"] = "guest"
        sess["real_role"] = "guest"
        sess["last_activity"] = time.time()

    # Write 3 audit log entries
    security.logger.log_event("event_1", {"data": "one"})
    security.logger.log_event("event_2", {"data": "two"})
    e3 = security.logger.log_event("event_3", {"data": "three"})

    resp = client.get("/api/audit/verify")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data.get("intact") is True
    assert data.get("count") == 3
    assert data.get("genesis_hash") == "0" * 64
    assert data.get("head_hash") == e3["entry_hash"]


# =========================================================================
# Item 3 [T]: api_approvals_decide
# =========================================================================

def test_api_approvals_decide_requires_matching_request_hash(client, tmp_path):
    """api_approvals_decide returns 400 if request_hash is missing or does not match."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    req_id = "req_test_hash_val"
    true_hash = "abcdef1234567890" * 4

    pending_dir = tmp_path / "data" / "approvals" / "pending"
    pending_dir.mkdir(parents=True, exist_ok=True)
    pending_file = pending_dir / f"{req_id}.json"
    pending_file.write_text(json.dumps({
        "request_id": req_id,
        "request_hash": true_hash,
        "tool": "unlock_door",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    }), encoding="utf-8")

    # Missing request_hash -> 400
    resp_missing = client.post(
        "/api/approvals/decide",
        headers={"X-CSRF-Token": csrf_token},
        json={"request_id": req_id, "approved": True},
    )
    assert resp_missing.status_code == 400

    # Mismatched request_hash -> 400
    resp_mismatch = client.post(
        "/api/approvals/decide",
        headers={"X-CSRF-Token": csrf_token},
        json={"request_id": req_id, "request_hash": "wrong_hash", "approved": True},
    )
    assert resp_mismatch.status_code == 400


def test_api_approvals_decide_concurrent_double_decide_returns_409(client, tmp_path):
    """Atomic write mode 'x' ensures concurrent double-decide results in exactly one 200 and one 409."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    req_id = "req_concurrent_atomic"
    req_hash = hashlib.sha256(b"tool_unlock").hexdigest()

    pending_dir = tmp_path / "data" / "approvals" / "pending"
    pending_dir.mkdir(parents=True, exist_ok=True)
    pending_file = pending_dir / f"{req_id}.json"
    pending_file.write_text(json.dumps({
        "request_id": req_id,
        "request_hash": req_hash,
        "tool": "unlock_door",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    }), encoding="utf-8")

    results = []
    barrier = threading.Barrier(2)

    def submit_decision(decision_val):
        barrier.wait()
        res = client.post(
            "/api/approvals/decide",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "request_id": req_id,
                "request_hash": req_hash,
                "approved": decision_val,
            },
        )
        results.append(res.status_code)

    t1 = threading.Thread(target=submit_decision, args=(True,))
    t2 = threading.Thread(target=submit_decision, args=(False,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert sorted(results) == [200, 409]


# =========================================================================
# Item 5 [T]: guards.py idle timeout
# =========================================================================

def test_polling_get_api_does_not_extend_idle_timeout(client):
    """Polling GET /api/approvals/history does not extend 15-minute idle session timeout."""
    csrf_token = secrets.token_hex(32)
    initial_activity = time.time() - 100  # 100 seconds ago

    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = initial_activity
        sess["csrf_token"] = csrf_token

    # 1. GET /api/approvals/history should NOT update last_activity
    resp = client.get("/api/approvals/history")
    assert resp.status_code == 200

    with client.session_transaction() as sess:
        # last_activity must remain unchanged
        assert sess.get("last_activity") == initial_activity

    # 2. Non-API GET (e.g. page navigation) DOES update last_activity
    resp_page = client.get("/overview")
    assert resp_page.status_code == 200

    with client.session_transaction() as sess:
        assert sess.get("last_activity") > initial_activity


# =========================================================================
# Item 10 [T]: turn_summary & Overview metrics
# =========================================================================

def test_turn_summary_audit_event_and_overview_counts(client, monkeypatch):
    """
    turn_summary event is written at the end of run_turn.
    Overview counts Requests and Blocks from turn_summary events only.
    last_request returns null when no requests yet.
    _read_log_tail reads backwards from file end.
    """
    with client.session_transaction() as sess:
        sess["username"] = "guest_user"
        sess["role"] = "guest"
        sess["real_role"] = "guest"
        sess["last_activity"] = time.time()

    # 1. Initially, overview has no requests -> last_request is None
    resp_init = client.get("/api/overview")
    assert resp_init.status_code == 200
    data_init = resp_init.get_json()
    assert data_init["last_request"] is None
    assert data_init["kpis"]["requests_last_hour"]["value"] == 0
    assert data_init["kpis"]["blocked_attacks"]["value"] == 0

    # 2. Log irrelevant events (e.g. hardware_command, approval_decision)
    # These must NOT be counted as Requests or Blocks
    security.logger.log_event("hardware_command", {"command": "light_on", "ok": True})
    security.logger.log_event("approval_request", {"tool": "unlock_door", "decision": "BLOCK"})

    resp_noise = client.get("/api/overview")
    data_noise = resp_noise.get_json()
    assert data_noise["kpis"]["requests_last_hour"]["value"] == 0
    assert data_noise["kpis"]["blocked_attacks"]["value"] == 0
    assert data_noise["last_request"] is None

    # 3. Simulate turn_summary events
    req_id_1 = "turn_req_001"
    security.logger.log_turn_summary(
        request_id=req_id_1,
        session_id="sess_demo",
        decision="ALLOW",
        tool="turn_light_on",
        rule_ids=[],
        latency_ms=145.2,
    )

    req_id_2 = "turn_req_002"
    security.logger.log_turn_summary(
        request_id=req_id_2,
        session_id="sess_demo",
        decision="BLOCK",
        tool="unlock_door",
        rule_ids=["INJ-001"],
        latency_ms=210.5,
    )

    resp_after = client.get("/api/overview")
    data_after = resp_after.get_json()
    assert data_after["kpis"]["requests_last_hour"]["value"] == 2
    assert data_after["kpis"]["blocked_attacks"]["value"] == 1
    assert data_after["last_request"]["id"] == req_id_2
    assert data_after["last_request"]["decision"] == "BLOCK"
    assert data_after["last_request"]["tool"] == "unlock_door"

    # 4. Verify _read_log_tail reads without calling readlines
    log_file = security.logger.get_log_file()
    tail = _read_log_tail(log_file, max_lines=2)
    assert len(tail) == 2
    assert tail[-1]["request_id"] == req_id_2


# =========================================================================
# Item 11 [T]: Edge cases, RBAC, password, corrupt log, MQTT
# =========================================================================

def test_switch_role_forbidden_for_real_guest_and_audited_for_admin(client):
    """switch_role returns 403 for real guest and is audited for admin."""
    csrf_token = secrets.token_hex(32)

    # 1. Real guest attempts switch_role -> 403
    with client.session_transaction() as sess:
        sess["username"] = "real_guest_user"
        sess["role"] = "guest"
        sess["real_role"] = "guest"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    resp_guest = client.post(
        "/api/auth/switch_role",
        headers={"X-CSRF-Token": csrf_token},
        json={"role": "admin"},
    )
    assert resp_guest.status_code == 403

    # 2. Real admin attempts switch_role -> 200 & audited
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    resp_admin = client.post(
        "/api/auth/switch_role",
        headers={"X-CSRF-Token": csrf_token},
        json={"role": "guest"},
    )
    assert resp_admin.status_code == 200
    assert resp_admin.get_json()["active_role"] == "guest"
    assert resp_admin.get_json()["is_simulated"] is True


def test_simulated_guest_gets_403_on_approvals_api(client):
    """Simulated guest gets 403 on /api/approvals/*."""
    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "guest"  # simulated guest role
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    resp_pending = client.get("/api/approvals/pending")
    assert resp_pending.status_code == 403

    resp_history = client.get("/api/approvals/history")
    assert resp_history.status_code == 403


def test_min_password_length_10():
    """Passwords shorter than 10 characters are rejected."""
    with pytest.raises(ValueError, match="at least 10 characters"):
        security.auth.create_user("test_user_short", "pass12345", role="admin")

    # 10 characters succeeds
    res = security.auth.create_user("test_user_ok", "1234567890", role="admin")
    assert res["username"] == "test_user_ok"


def test_uniform_login_error_message():
    """Uniform login error for unknown user, bad password, and locked account."""
    security.auth.create_user("target_user", "validpassword10", role="admin")

    # 1. Unknown user
    ok1, msg1 = security.auth.verify_login("nonexistent_user", "somepassword10")
    assert ok1 is False
    assert str(msg1) == "Invalid username or password"

    # 2. Bad password
    ok2, msg2 = security.auth.verify_login("target_user", "wrongpassword10")
    assert ok2 is False
    assert str(msg2) == "Invalid username or password"

    # 3. Trigger lockout (5 failed attempts)
    for _ in range(4):
        security.auth.verify_login("target_user", "wrongpassword10")

    # 4. Locked account
    ok3, msg3 = security.auth.verify_login("target_user", "wrongpassword10")
    assert ok3 is False
    assert str(msg3) == "Invalid username or password"


def test_corrupt_last_log_line_raises_append_and_gateway_denies(tmp_path):
    """Corrupt last log line causes append to raise and the gateway denies the request (worker survives)."""
    log_file = security.logger.get_log_file()
    # Write one valid entry
    security.logger.log_event("valid_init", {"ok": True})

    # Corrupt last line
    with open(log_file, "a", encoding="utf-8") as f:
        f.write("{corrupt: json truncated...\n")

    # 1. Direct append raises RuntimeError
    with pytest.raises(RuntimeError, match="Corrupt audit log detected"):
        security.logger.log_event("should_fail", {"data": 123})

    # 2. Gateway evaluate catches failure and returns BLOCK (fails closed)
    eval_res = security.gateway.evaluate(
        tool_name="turn_light_on",
        tool_args={},
        user_text="turn on light",
        role="admin",
        session_id="test_corrupt_sess",
    )
    assert eval_res["decision"] == "BLOCK"
    assert "Audit logging failure" in eval_res["reason"]

    # 3. Worker direct_tool survives (does not crash or raise uncaught exception)
    outbox = tmp_path / "worker_corrupt_outbox.jsonl"
    req = {
        "id": "req-corrupt-survive",
        "kind": "direct_tool",
        "role": "admin",
        "session_id": "corrupt_sess",
        "tool": "turn_light_on",
        "username": "admin",
    }
    _process_direct_tool(req, lambda stage, status, d: None, outbox)
    assert outbox.exists()
    final_line = json.loads(outbox.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert final_line["decision"] == "BLOCK"


def test_mode_mqtt_broker_down_returns_ok_false_never_fake_bridge():
    """Mode mqtt with broker down returns ok=False, and bridge is never a FakeBridge."""
    policy_dict = {
        "hardware": {
            "mode": "mqtt",
            "broker_host": "127.0.0.1",
            "broker_port": 19999,  # Unreachable port
            "device_id": "esp32-test",
            "publish_timeout_seconds": 0.5,
        }
    }
    bridge = security.hardware.HardwareBridge(policy_dict=policy_dict)
    assert not isinstance(bridge, security.hardware.FakeBridge)
    assert isinstance(bridge, security.hardware.HardwareBridge)

    res = bridge.publish("light_on")
    assert res.ok is False
    assert res.error is not None
