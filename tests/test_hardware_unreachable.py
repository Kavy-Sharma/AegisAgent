"""
Tests for Prompt 76 Part C (unreachable/timeout hardware fail-closed & UI chip/gate wording)
and Part A.2 (/api/console/poll live stage tracking).
"""

import json
import secrets
import threading
import time
from unittest.mock import patch

import pytest

import agent.agent as agent_mod
from agent.agent import run_turn
from agent.tools import (
    UNREACHABLE_DEVICE_MSG,
    activate_alarm,
    turn_light_off,
    turn_light_on,
    unlock_door,
)
from agent.worker import _process_direct_tool
from security.approval import ApprovalManager, ScriptedApprovalProvider
import security.gateway
import security.hardware
from security.hardware import HardwareCommandResult, set_bridge
from security.verify_log import verify_audit_log
from security.virtual_home import VirtualBridge
from web.server import create_app


class RaisingFakeBridge:
    """Custom fake hardware bridge whose publish/ack raises an exception (unreachable)."""

    transport = "mqtt"

    def __init__(self, exc: Exception | None = None):
        self.exc = exc or ConnectionError("ESP32 socket unreachable")
        self.publish_calls: list[str] = []

    def is_device_online(self) -> bool:
        return False

    def publish(self, command: str) -> HardwareCommandResult:
        self.publish_calls.append(command)
        raise self.exc


class TimeoutFakeBridge:
    """Custom fake hardware bridge simulating a hardware timeout on publish."""

    transport = "serial"
    port = "COM99"

    def __init__(self):
        self.publish_calls: list[str] = []

    def is_device_online(self) -> bool:
        return False

    def publish(self, command: str) -> HardwareCommandResult:
        self.publish_calls.append(command)
        raise TimeoutError("Timed out waiting for ESP32 ping ACK")


class ConnectedFakeBridge:
    """Custom fake hardware bridge representing reachable connected hardware."""

    transport = "serial"
    port = "COM7"

    def __init__(self):
        self.publish_calls: list[str] = []

    def is_device_online(self) -> bool:
        return True

    def publish(self, command: str) -> HardwareCommandResult:
        self.publish_calls.append(command)
        return HardwareCommandResult(ok=True, adapter="serial")


def _read_audit_events(log_path) -> list[dict]:
    events = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


@pytest.mark.parametrize("bridge_cls", [RaisingFakeBridge, TimeoutFakeBridge])
def test_unreachable_hardware_tools_fail_closed_and_log(bridge_cls, tmp_path, monkeypatch):
    """unlock_door, turn_light_on/off, activate_alarm fail closed with clear message and audit logs."""
    monkeypatch.setitem(security.policy_loader.POLICY["hardware"], "mode", "mqtt")
    bridge = bridge_cls()
    set_bridge(bridge)

    for fn in (unlock_door, turn_light_on, turn_light_off, activate_alarm):
        res = fn()
        assert res["status"] == "failed"
        assert res["hardware_connected"] is False
        assert res["text"] == UNREACHABLE_DEVICE_MSG
        assert UNREACHABLE_DEVICE_MSG in res["error"]

    # Multi-step tools (blink_count=3 and duration_seconds=6) must NOT spawn background threads on initial failure
    before_threads = {t.ident for t in threading.enumerate()}
    blink_res = turn_light_on(blink_count=3)
    alarm_res = activate_alarm(duration_seconds=6)
    time.sleep(0.1)
    after_threads = {t.ident for t in threading.enumerate()}

    assert blink_res["status"] == "failed"
    assert blink_res["hardware_connected"] is False
    assert alarm_res["status"] == "failed"
    assert alarm_res["hardware_connected"] is False
    assert before_threads == after_threads
    # 4 single calls + 1 blink_res + 1 alarm_res = 6 publish calls total (no background retry loop)
    assert len(bridge.publish_calls) == 6

    log_path = tmp_path / "logs" / "audit_log.jsonl"
    events = _read_audit_events(log_path)
    hw_cmds = [e for e in events if e.get("event") == "hardware_command"]
    hw_unreach = [e for e in events if e.get("event") == "hardware_unreachable"]
    assert len(hw_cmds) == 6
    assert all(e.get("ok") is False for e in hw_cmds)
    assert len(hw_unreach) == 6
    assert verify_audit_log() is True


def test_run_turn_and_worker_fail_closed_on_unreachable_hardware(tmp_path):
    """run_turn and worker direct_tool return ERROR at hardware stage with unreachable message."""
    bridge = TimeoutFakeBridge()
    set_bridge(bridge)

    # 1. Low-risk turn_light_on via run_turn
    mock_light = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": "turn_light_on", "arguments": {}}}],
        }
    }
    emitted: list[tuple[str, str, dict]] = []
    with patch("ollama.chat", return_value=mock_light):
        res = run_turn(
            text="Turn on the light",
            role="admin",
            session_id="unreach_light",
            emit=lambda s, st, d: emitted.append((s, st, d)),
        )

    assert res.decision == "ERROR"
    assert res.stopped_at == "hardware"
    assert UNREACHABLE_DEVICE_MSG in (res.reply or "")
    assert ("hardware", "error") in [(s, st) for s, st, _ in emitted]

    # 2. High-risk unlock_door approved by supervisor but device unreachable -> fails closed!
    scripted = ScriptedApprovalProvider(["y"])
    security.gateway.set_approval_manager(ApprovalManager(provider=scripted))
    try:
        mock_door = {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "unlock_door", "arguments": {}}}],
            }
        }
        with patch("ollama.chat", return_value=mock_door):
            res_door = run_turn(
                text="Unlock the front door",
                role="admin",
                session_id="unreach_door",
            )
    finally:
        security.gateway.set_approval_manager(ApprovalManager())

    assert res_door.decision == "ERROR"
    assert res_door.stopped_at == "hardware"
    assert UNREACHABLE_DEVICE_MSG in (res_door.reply or "")

    # 3. Direct worker tool dispatch also fails closed at hardware
    outbox = tmp_path / "outbox_direct.jsonl"
    direct_steps: list[tuple[str, str]] = []
    _process_direct_tool(
        {
            "id": "req_direct_unreach",
            "tool": "turn_light_on",
            "role": "admin",
            "username": "admin",
            "session_id": "manual_actuation",
        },
        lambda s, st, d: direct_steps.append((s, st)),
        outbox,
    )
    rows = [json.loads(line) for line in outbox.read_text(encoding="utf-8").splitlines() if line.strip()]
    final = [r for r in rows if r.get("final") is True][-1]
    assert final["decision"] == "ERROR"
    assert final["stopped_at"] == "hardware"
    assert UNREACHABLE_DEVICE_MSG in final["reply"]
    assert ("hardware", "error") in direct_steps


def _make_admin_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DASH_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("AEGIS_WEB_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "data"))
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = secrets.token_hex(32)
    return client


def test_hardware_ui_status_and_gate_wording(tmp_path, monkeypatch):
    """Top chip & Gate 8 wording reflect virtual vs connected vs unreachable vs office."""
    client = _make_admin_client(tmp_path, monkeypatch)

    # 1. Virtual Home
    set_bridge(VirtualBridge())
    h1 = client.get("/api/health").get_json()
    o1 = client.get("/api/overview").get_json()
    c1 = client.get("/console").get_data(as_text=True)
    assert h1["hardware_status"] == "virtual"
    assert o1["v2_stage_labels"][7] == "Device (simulated)"
    assert o1["kpis"]["device_status"]["hint"] == "Virtual Home (simulation)"
    assert "Virtual Home (simulation)" in c1

    # 2. Connected Hardware
    set_bridge(ConnectedFakeBridge())
    h2 = client.get("/api/health").get_json()
    o2 = client.get("/api/overview").get_json()
    c2 = client.get("/console").get_data(as_text=True)
    assert h2["hardware_status"] == "connected"
    assert o2["v2_stage_labels"][7] == "Device"
    assert o2["kpis"]["device_status"]["hint"] == "Hardware connected"
    assert "Hardware connected" in c2

    # 3. Unreachable Hardware
    set_bridge(RaisingFakeBridge())
    h3 = client.get("/api/health").get_json()
    o3 = client.get("/api/overview").get_json()
    c3 = client.get("/console").get_data(as_text=True)
    assert h3["hardware_status"] == "unreachable"
    assert o3["v2_stage_labels"][7] == "Device"
    assert o3["kpis"]["device_status"]["hint"] == "Hardware unreachable"
    assert "Hardware unreachable" in c3

    # 4. Office Sandbox
    try:
        agent_mod.load_environment("office")
        o4 = client.get("/api/overview").get_json()
        c4 = client.get("/console").get_data(as_text=True)
        assert o4["v2_stage_labels"][7] == "Tool"
        assert "Office sandbox (simulation)" in c4
    finally:
        agent_mod.load_environment("smart_home")


def test_console_poll_reports_real_completed_and_active_gates(tmp_path, monkeypatch):
    """A.2: /api/console/poll returns completed_gates, active_stage/gate, stopped_stage/gate."""
    client = _make_admin_client(tmp_path, monkeypatch)
    outbox_dir = tmp_path / "data" / "chat" / "outbox"
    outbox_dir.mkdir(parents=True, exist_ok=True)
    req_id = "req_poll_sync_01"
    ob = outbox_dir / f"{req_id}.jsonl"

    # 1. While model is thinking
    lines = [
        {"owner": "admin", "request_id": req_id},
        {"stage": "detection", "status": "pass", "detail": {}, "request_id": req_id},
        {"stage": "intent", "status": "pass", "detail": {}, "request_id": req_id},
        {"stage": "llm", "status": "running", "detail": {}, "request_id": req_id},
    ]
    ob.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    p1 = client.get(f"/api/console/poll/{req_id}").get_json()
    assert p1["status"] == "running"
    assert p1["completed_gates"] == [0, 1]
    assert p1["active_stage"] == "llm"
    assert p1["active_gate"] == 2
    assert p1["stopped_gate"] == -1

    # 2. When stopped at rbac
    lines.extend([
        {"stage": "llm", "status": "pass", "detail": {}, "request_id": req_id},
        {"stage": "rbac", "status": "running", "detail": {}, "request_id": req_id},
        {"stage": "rbac", "status": "block", "detail": {"reason": "denied"}, "request_id": req_id},
        {"final": True, "decision": "BLOCK", "stopped_at": "rbac", "reply": "Blocked", "request_id": req_id},
    ])
    ob.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    p2 = client.get(f"/api/console/poll/{req_id}").get_json()
    assert p2["status"] == "completed"
    assert p2["completed_gates"] == [0, 1, 2]
    assert p2["stopped_stage"] == "rbac"
    assert p2["stopped_gate"] == 3
