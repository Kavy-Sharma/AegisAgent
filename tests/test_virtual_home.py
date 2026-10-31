"""
Unit and integration tests for VirtualBridge (VirtualHome simulated adapter).
"""

import json
import os
from pathlib import Path
import time
import pytest

import security.hardware
import security.logger
import security.policy_loader
from security.virtual_home import VirtualBridge


def test_virtual_bridge_light_state(tmp_path):
    bridge = VirtualBridge()
    try:
        assert bridge.state["light"] == "off"
        assert bridge.state["light_on"] is False

        res = bridge.publish("light_on")
        assert res.ok is True
        assert bridge.state["light"] == "on"
        assert bridge.state["light_on"] is True
        assert "light_on" in bridge.command_history

        res2 = bridge.publish("light_off")
        assert res2.ok is True
        assert bridge.state["light"] == "off"
        assert bridge.state["light_on"] is False
    finally:
        bridge.close()


def test_virtual_bridge_unlock_then_auto_lock(tmp_path):
    # Use a fast 0.15s auto_lock_delay for snappy testing
    bridge = VirtualBridge(auto_lock_delay=0.15)
    try:
        assert bridge.state["door"] == "locked"
        assert bridge.state["door_locked"] is True

        res = bridge.publish("unlock_door")
        assert res.ok is True
        assert bridge.state["door"] == "unlocked"
        assert bridge.state["door_locked"] is False

        # Wait for auto-lock timer to fire
        time.sleep(0.25)
        assert bridge.state["door"] == "locked"
        assert bridge.state["door_locked"] is True
    finally:
        bridge.close()


def test_virtual_bridge_alarm_state(tmp_path):
    bridge = VirtualBridge()
    try:
        assert bridge.state["alarm"] == "off"
        assert bridge.state["alarm_on"] is False

        res = bridge.publish("alarm_on")
        assert res.ok is True
        assert bridge.state["alarm"] == "on"
        assert bridge.state["alarm_on"] is True
    finally:
        bridge.close()


def test_virtual_bridge_unknown_command_rejected(tmp_path):
    bridge = VirtualBridge()
    try:
        with pytest.raises(ValueError, match="not in hardware command allowlist"):
            bridge.publish("invalid_secret_command")

        assert "invalid_secret_command" not in bridge.command_history
    finally:
        bridge.close()


def test_virtual_bridge_label_virtual_present(tmp_path):
    bridge = VirtualBridge()
    try:
        assert bridge.adapter == "virtual"
        assert bridge.transport == "virtual"

        res = bridge.publish("light_on")
        assert res.adapter == "virtual"
        assert res["adapter"] == "virtual"
        assert res.get("adapter") == "virtual"

        # Verify audit log recorded adapter="virtual"
        log_file = security.logger.get_log_file()
        assert log_file.exists()
        with open(log_file, "r", encoding="utf-8") as f:
            lines = [l for l in f.readlines() if l.strip()]
        last_entry = json.loads(lines[-1])
        assert last_entry.get("event") == "hardware_command"
        assert last_entry.get("adapter") == "virtual"
    finally:
        bridge.close()


def test_virtual_bridge_state_file_written(tmp_path):
    bridge = VirtualBridge()
    try:
        state_file = bridge.get_state_file_path()
        assert state_file.exists()

        # Verify state file path is safely confined to test tmp_path
        assert str(tmp_path) in str(state_file)

        # Read state file and verify contents
        with open(state_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data.get("adapter") == "virtual"
        assert data.get("light") == "off"

        # Update state and verify atomic change in file
        bridge.publish("light_on")
        with open(state_file, "r", encoding="utf-8") as f:
            data2 = json.load(f)
        assert data2.get("light") == "on"
        assert data2.get("light_on") is True

        # Verify no orphaned temp files
        assert not state_file.with_suffix(".tmp").exists()
    finally:
        bridge.close()


def test_virtual_bridge_get_bridge_virtual_mode(tmp_path, monkeypatch):
    # Reset existing bridge instance to test get_bridge() factory
    security.hardware.set_bridge(None)
    monkeypatch.setitem(security.policy_loader.POLICY["hardware"], "mode", "virtual")

    bridge = security.hardware.get_bridge()
    try:
        assert isinstance(bridge, VirtualBridge)
        assert bridge.is_device_online() is True

        res = bridge.publish("ping")
        assert res.ok is True
        assert res.adapter == "virtual"
    finally:
        bridge.close()
        security.hardware.set_bridge(None)

