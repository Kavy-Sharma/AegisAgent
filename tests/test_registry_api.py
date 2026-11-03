"""
tests/test_registry_api.py - Verification for Registry Step 4:
1. Built command map equals tests/fixtures/cmd_map_snapshot.json (exact match).
2. Startup check fails if the environment maps a command to an unregistered tool name.
3. api_hardware_actuate with an unknown command or unmapped tool is rejected (400)
   and FakeBridge records zero actuations.
"""

from __future__ import annotations

import json
from pathlib import Path
import secrets
import time
import pytest

from agent.agent import ENVIRONMENT_META
from agent.environments.smart_home import COMMANDS, build_environment_meta
from security.hardware import FakeBridge, set_bridge
import security.registry
from web.api import HARDWARE_COMMANDS, validate_commands_against_registry
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


def test_built_command_map_equals_snapshot():
    """1. Built command map equals tests/fixtures/cmd_map_snapshot.json (exact match)."""
    snapshot_path = Path(__file__).resolve().parent / "fixtures" / "cmd_map_snapshot.json"
    assert snapshot_path.exists(), f"Snapshot fixture missing at {snapshot_path}"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

    assert HARDWARE_COMMANDS == snapshot
    assert ENVIRONMENT_META.get("commands") == snapshot
    assert COMMANDS == snapshot
    assert build_environment_meta().get("commands") == snapshot


def test_startup_check_fails_on_unregistered_tool():
    """2. Startup check fails if the environment maps a command to an unregistered tool name."""
    bad_commands = {
        "light_on": "turn_light_on",
        "laser_strike": "nonexistent_orbital_laser_tool",
    }
    with pytest.raises(ValueError) as exc_info:
        validate_commands_against_registry(bad_commands)

    error_msg = str(exc_info.value)
    assert "nonexistent_orbital_laser_tool" in error_msg
    assert "laser_strike" in error_msg
    assert "registry" in error_msg.lower()


def test_actuate_unknown_or_unregistered_command_rejected_zero_bridge_calls(client, monkeypatch):
    """3. api_hardware_actuate with an unknown command or unmapped tool is rejected (400)
    and FakeBridge records zero actuations.
    """
    bridge = FakeBridge()
    set_bridge(bridge)

    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    # Case A: Unknown / unmapped command string
    resp_unknown = client.post(
        "/api/hardware/actuate",
        headers={"X-CSRF-Token": csrf_token},
        json={"command": "completely_unknown_command_xyz"},
    )
    assert resp_unknown.status_code == 400
    assert "unmapped" in resp_unknown.get_json().get("error", "").lower()
    assert len(bridge.command_history) == 0

    # Case B: Command exists in map but targets an unregistered tool
    monkeypatch.setitem(HARDWARE_COMMANDS, "fake_cmd", "ghost_tool_not_in_registry")
    resp_unreg = client.post(
        "/api/hardware/actuate",
        headers={"X-CSRF-Token": csrf_token},
        json={"command": "fake_cmd"},
    )
    assert resp_unreg.status_code == 400
    assert "not in policy registry" in resp_unreg.get_json().get("error", "").lower()
    assert len(bridge.command_history) == 0



def test_actuate_tool_with_no_risk_rejected_zero_bridge_calls(client, monkeypatch):
    """4. api_hardware_actuate with a tool that has no risk level in policy is rejected (400)
    and FakeBridge records zero actuations.
    """
    bridge = FakeBridge()
    set_bridge(bridge)

    monkeypatch.setattr(
        "security.health.get_system_health",
        lambda: {"worker": {"alive": True}},
    )

    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    monkeypatch.setattr(security.registry, "risk", lambda tool: None)

    resp = client.post(
        "/api/hardware/actuate",
        headers={"X-CSRF-Token": csrf_token},
        json={"command": "light_on"},
    )
    assert resp.status_code == 400
    assert "Tool has no risk level in policy" in resp.get_json().get("error", "")
    assert len(bridge.command_history) == 0
