"""
tests/test_hardware_auto_default.py - Verification for Step 5:
D.2: Auto mode with no USB port -> get_bridge() returns VirtualBridge, no MQTT connection created.
D.3: Auto mode with CP210x port -> get_bridge() returns SerialHardwareBridge.
D.4: Auto mode with existing offline SerialHardwareBridge and empty ports -> stays SerialHardwareBridge, publish("unlock_door") fails.
D.5: Mode "mqtt" returns HardwareBridge; unknown mode returns HardwareBridge.
D.6: COMMAND_ALLOWLIST equals exactly {"light_on", "light_off", "unlock_door", "alarm_on", "alert_blocked", "ping"}.
"""

from unittest.mock import MagicMock, patch
import pytest

from security.hardware import (
    COMMAND_ALLOWLIST,
    HardwareBridge,
    SerialHardwareBridge,
    get_bridge,
    set_bridge,
)
import security.policy_loader
from security.virtual_home import VirtualBridge


class FakeSerialDevice:
    """Mock serial connection to test SerialHardwareBridge without hardware delays."""
    def __init__(self, response_map: dict | None = None):
        self.is_open = True
        self.written_bytes = b""
        self.response_map = response_map or {}
        self.in_waiting_buffer = ""

    @property
    def in_waiting(self) -> int:
        return len(self.in_waiting_buffer)

    def write(self, data: bytes):
        self.written_bytes += data
        cmd = data.decode("utf-8", errors="ignore").strip()
        if cmd in self.response_map:
            self.in_waiting_buffer += self.response_map[cmd] + "\n"

    def read(self, n: int) -> bytes:
        chunk = self.in_waiting_buffer[:n].encode("utf-8")
        self.in_waiting_buffer = self.in_waiting_buffer[n:]
        return chunk

    def reset_input_buffer(self):
        self.in_waiting_buffer = ""

    def close(self):
        self.is_open = False


@pytest.fixture(autouse=True)
def clean_bridge_singleton():
    """Reset the bridge singleton before and after each test."""
    set_bridge(None)
    yield
    set_bridge(None)


def test_auto_mode_no_usb_returns_virtual_bridge_no_mqtt(monkeypatch):
    """D.2: Auto mode with no ports returns VirtualBridge and paho MQTT client is never created or connected."""
    set_bridge(None)
    try:
        monkeypatch.setitem(security.policy_loader.POLICY["hardware"], "mode", "auto")

        with patch("serial.tools.list_ports.comports", return_value=[]), \
             patch("paho.mqtt.client.Client") as mock_paho_client, \
             patch("security.hardware.mqtt.Client") as mock_hw_client:
            bridge = get_bridge()
            assert isinstance(bridge, VirtualBridge)
            assert bridge.is_device_online() is True

            # Assert paho MQTT client was never created or connected
            mock_paho_client.assert_not_called()
            mock_hw_client.assert_not_called()

            # Verify simulation publish works cleanly
            res = bridge.publish("light_on")
            assert res.ok is True
            assert res.adapter == "virtual"
            bridge.close()
    finally:
        set_bridge(None)


def test_auto_mode_cp210x_returns_serial_bridge(monkeypatch):
    """D.3: Auto mode with a detected CP210x port returns SerialHardwareBridge."""
    set_bridge(None)
    try:
        monkeypatch.setitem(security.policy_loader.POLICY["hardware"], "mode", "auto")

        cp_port = MagicMock()
        cp_port.device = "COM5"
        cp_port.description = "CP2102 USB to UART Bridge Controller"
        cp_port.hwid = "USB VID:PID=10C4:EA60"

        with patch("serial.tools.list_ports.comports", return_value=[cp_port]):
            bridge = get_bridge()
            assert isinstance(bridge, SerialHardwareBridge)
            assert bridge.port == "COM5"
    finally:
        set_bridge(None)


def test_auto_mode_offline_serial_bridge_retains_serial_on_empty_ports(monkeypatch):
    """D.4: Auto mode with offline SerialHardwareBridge stays SerialHardwareBridge when comports is [],
    and publish('unlock_door') fails closed with ok=False when mock serial returns no ping_ack.
    """
    set_bridge(None)
    try:
        monkeypatch.setitem(security.policy_loader.POLICY["hardware"], "mode", "auto")

        offline_serial = SerialHardwareBridge(port="COM_OFFLINE")
        fake_serial = FakeSerialDevice({"ping": "NO_ACK_DEVICE_UNRECOGNIZED"})
        offline_serial._serial = fake_serial
        offline_serial._ping_acked_this_session = False
        offline_serial.device_online = False
        set_bridge(offline_serial)

        with patch("serial.tools.list_ports.comports", return_value=[]):
            bridge = get_bridge()
            # Assert bridge stays SerialHardwareBridge (NOT VirtualBridge)
            assert bridge is offline_serial
            assert isinstance(bridge, SerialHardwareBridge)
            assert not isinstance(bridge, VirtualBridge)

            # Actuate unlock_door -> ping sent, ping_ack not received -> ok=False, unlock_door never sent
            res = bridge.publish("unlock_door")
            assert res.ok is False
            assert "Device verification failed" in res.error
            assert b"unlock_door" not in fake_serial.written_bytes
            assert b"ping" in fake_serial.written_bytes
    finally:
        set_bridge(None)


def test_mode_mqtt_and_unknown_return_hardware_bridge(monkeypatch):
    """D.5: Mode 'mqtt' still returns HardwareBridge; unknown mode still returns HardwareBridge."""
    # 1. Explicit mode 'mqtt'
    set_bridge(None)
    try:
        monkeypatch.setitem(security.policy_loader.POLICY["hardware"], "mode", "mqtt")
        bridge_mqtt = get_bridge()
        assert isinstance(bridge_mqtt, HardwareBridge)
    finally:
        set_bridge(None)

    # 2. Unknown mode fallback
    set_bridge(None)
    try:
        monkeypatch.setitem(security.policy_loader.POLICY["hardware"], "mode", "unrecognized_mode_value")
        bridge_unknown = get_bridge()
        assert isinstance(bridge_unknown, HardwareBridge)
    finally:
        set_bridge(None)


def test_command_allowlist_exact():
    """D.6: COMMAND_ALLOWLIST equals exactly {"light_on","light_off","unlock_door","alarm_on","alert_blocked","ping"}."""
    set_bridge(None)
    try:
        expected = {"light_on", "light_off", "unlock_door", "alarm_on", "alert_blocked", "ping"}
        assert COMMAND_ALLOWLIST == expected
    finally:
        set_bridge(None)
