import json
from unittest.mock import patch
import pytest

from agent.agent import run_turn
import security.approval
from security.hardware import FakeBridge, set_bridge
import security.logger
import security.rate_limiter


def mock_tool_call(tool_name: str, args: dict | None = None):
    return {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": tool_name,
                        "arguments": args or {},
                    }
                }
            ],
        }
    }


def get_last_hardware_audit_entry():
    log_file = security.logger.get_log_file()
    if not log_file.exists():
        return None
    with open(log_file, "r", encoding="utf-8") as f:
        for line in reversed(f.readlines()):
            if line.strip():
                try:
                    entry = json.loads(line)
                    if entry.get("event") == "hardware_command":
                        return entry
                except Exception:
                    pass
    return None


@pytest.fixture(autouse=True)
def auto_approve_high_risk(monkeypatch):
    """Auto-approve high-risk actions so tests don't block waiting for human dashboard decision."""
    monkeypatch.setattr(
        security.approval.ApprovalManager,
        "request",
        lambda self, req: security.approval.ApprovalResult(approved=True, decided_by="admin_test", reason="Auto-approved for test")
    )


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Clear rate limits so tests in this module are never blocked by earlier test runs."""
    security.rate_limiter.CALL_TIMESTAMPS.clear()


@pytest.mark.parametrize("tool_name, prompt", [
    ("turn_light_on", "turn on the light"),
    ("turn_light_off", "turn off the light"),
    ("activate_alarm", "sound the alarm"),
    ("unlock_door", "unlock the door"),
])
def test_hardware_truth_ack_success(tool_name, prompt):
    bridge = FakeBridge()
    bridge.connected = True
    bridge.device_online_status = True
    set_bridge(bridge)

    with patch("ollama.chat", return_value=mock_tool_call(tool_name)):
        res = run_turn(text=prompt, role="admin", session_id="test_sess_truth")
    assert res.tool_called == tool_name
    assert isinstance(res.tool_result, dict)
    assert res.tool_result.get("status") == "success"
    assert res.decision == "ALLOW"
    assert "Failed" not in (res.reply or "")
    log_entry = get_last_hardware_audit_entry()
    assert log_entry is not None
    assert log_entry.get("ok") is True


@pytest.mark.parametrize("tool_name, prompt", [
    ("turn_light_on", "turn on the light"),
    ("turn_light_off", "turn off the light"),
    ("activate_alarm", "sound the alarm"),
    ("unlock_door", "unlock the door"),
])
def test_hardware_truth_disconnected_failure(tool_name, prompt):
    bridge = FakeBridge()
    bridge.connected = False  # Disconnected
    set_bridge(bridge)

    with patch("ollama.chat", return_value=mock_tool_call(tool_name)):
        res = run_turn(text=prompt, role="admin", session_id="test_sess_truth_disc")
    assert res.tool_called == tool_name
    assert isinstance(res.tool_result, dict)
    assert res.tool_result.get("status") == "failed"
    assert res.decision != "ALLOW", f"Decision was {res.decision}, expected not ALLOW on disconnected hardware!"
    assert "I have" not in (res.reply or "")
    assert "Failed" in (res.reply or "") or "failed" in (res.reply or "").lower()
    log_entry = get_last_hardware_audit_entry()
    assert log_entry is not None
    assert log_entry.get("ok") is False


@pytest.mark.parametrize("tool_name, prompt", [
    ("turn_light_on", "turn on the light"),
    ("turn_light_off", "turn off the light"),
    ("activate_alarm", "sound the alarm"),
    ("unlock_door", "unlock the door"),
])
def test_hardware_truth_no_ack_failure(tool_name, prompt):
    bridge = FakeBridge()
    bridge.connected = True
    bridge.device_online_status = True
    bridge.simulate_no_ack = True
    set_bridge(bridge)

    with patch("ollama.chat", return_value=mock_tool_call(tool_name)):
        res = run_turn(text=prompt, role="admin", session_id="test_sess_truth_noack")
    assert res.tool_called == tool_name
    assert isinstance(res.tool_result, dict)
    assert res.tool_result.get("status") == "failed"
    assert res.decision != "ALLOW", f"Decision was {res.decision}, expected not ALLOW on no-ack!"
    assert "I have" not in (res.reply or "")
    assert "Failed" in (res.reply or "") or "failed" in (res.reply or "").lower()
    log_entry = get_last_hardware_audit_entry()
    assert log_entry is not None
    assert log_entry.get("ok") is False


@pytest.mark.parametrize("tool_name, prompt", [
    ("turn_light_on", "turn on the light"),
    ("turn_light_off", "turn off the light"),
    ("activate_alarm", "sound the alarm"),
    ("unlock_door", "unlock the door"),
])
def test_hardware_truth_wrong_ack_failure(tool_name, prompt):
    bridge = FakeBridge()
    bridge.connected = True
    bridge.device_online_status = True
    bridge.simulate_wrong_ack = True
    set_bridge(bridge)

    with patch("ollama.chat", return_value=mock_tool_call(tool_name)):
        res = run_turn(text=prompt, role="admin", session_id="test_sess_truth_wrongack")
    assert res.tool_called == tool_name
    assert isinstance(res.tool_result, dict)
    assert res.tool_result.get("status") == "failed"
    assert res.decision != "ALLOW", f"Decision was {res.decision}, expected not ALLOW on wrong-ack!"
    assert "I have" not in (res.reply or "")
    assert "Failed" in (res.reply or "") or "failed" in (res.reply or "").lower()
    log_entry = get_last_hardware_audit_entry()
    assert log_entry is not None
    assert log_entry.get("ok") is False
