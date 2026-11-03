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


# ============================================================================
# STEP 5c VERIFICATION: Honest Status for Virtual Home & hardware_mode API
# ============================================================================

import json
import secrets
import time
from agent.worker import DeviceStatusSubscriber
from security.hardware import FakeBridge
from web.server import create_app


def test_virtual_bridge_device_status_fields(tmp_path):
    """Step 5c Part B: For VirtualBridge, worker writes simulated=True, broker_connected=False,
    transport='virtual', device_id='virtual-home', description='Virtual Home (simulation)', port='virtual'.
    """
    set_bridge(None)
    try:
        set_bridge(VirtualBridge())
        subscriber = DeviceStatusSubscriber(data_dir=tmp_path)
        subscriber._write_device_status(is_online=True)

        status_file = tmp_path / "device_status.json"
        assert status_file.exists()
        data = json.loads(status_file.read_text(encoding="utf-8"))

        assert data["transport"] == "virtual"
        assert data["simulated"] is True
        assert data["broker_connected"] is False
        assert data["device_id"] == "virtual-home"
        assert data["description"] == "Virtual Home (simulation)"
        assert data["port"] == "virtual"
        assert data["online"] is True
    finally:
        set_bridge(None)


def test_fake_and_real_bridge_device_status_simulated_false(tmp_path):
    """Step 5c Part B: For FakeBridge and real bridge, simulated=False and broker_connected is unchanged."""
    set_bridge(None)
    try:
        # 1. FakeBridge
        set_bridge(FakeBridge())
        subscriber = DeviceStatusSubscriber(data_dir=tmp_path)
        subscriber.broker_connected = True
        subscriber._write_device_status(is_online=True)

        status_file = tmp_path / "device_status.json"
        assert status_file.exists()
        data_fake = json.loads(status_file.read_text(encoding="utf-8"))

        assert data_fake["simulated"] is False
        assert data_fake["broker_connected"] is True
        assert data_fake["transport"] == "fake"

        # 2. SerialHardwareBridge
        set_bridge(SerialHardwareBridge(port="COM4"))
        subscriber.broker_connected = False
        subscriber._write_device_status(is_online=False)

        data_serial = json.loads(status_file.read_text(encoding="utf-8"))
        assert data_serial["simulated"] is False
        assert data_serial["broker_connected"] is False
        assert data_serial["transport"] == "usb_serial"
        assert data_serial["port"] == "COM4"
    finally:
        set_bridge(None)


def test_api_overview_and_health_hardware_mode(tmp_path, monkeypatch):
    """Step 5c Part C: /api/overview and /api/health return clear hardware_mode:
    'virtual' | 'usb' | 'mqtt' derived server-side from status.transport.
    """
    dash_sec = secrets.token_hex(32)
    web_sec = secrets.token_hex(32)
    monkeypatch.setenv("AEGIS_DASH_SECRET", dash_sec)
    monkeypatch.setenv("AEGIS_WEB_SECRET", web_sec)
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    csrf_token = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf_token

    # Case 1: Virtual transport -> hardware_mode 'virtual', status 'online', hint 'Virtual Home (simulation)'
    status_file = tmp_path / "device_status.json"
    status_file.write_text(json.dumps({
        "transport": "virtual",
        "simulated": True,
        "broker_connected": False,
        "online": True,
        "device_id": "virtual-home",
        "description": "Virtual Home (simulation)",
        "port": "virtual",
    }), encoding="utf-8")

    res_overview = client.get("/api/overview")
    assert res_overview.status_code == 200
    ov_data = res_overview.get_json()
    assert ov_data["hardware_mode"] == "virtual"
    assert ov_data["kpis"]["device_status"]["hardware_mode"] == "virtual"
    assert ov_data["kpis"]["device_status"]["status"] == "online"
    assert ov_data["kpis"]["device_status"]["hint"] == "Virtual Home (simulation)"

    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    h_data = res_health.get_json()
    assert h_data["hardware_mode"] == "virtual"

    # Case 2: USB serial transport -> hardware_mode 'usb'
    status_file.write_text(json.dumps({
        "transport": "usb_serial",
        "simulated": False,
        "broker_connected": True,
        "online": True,
        "port": "COM11",
    }), encoding="utf-8")

    res_overview_usb = client.get("/api/overview")
    assert res_overview_usb.status_code == 200
    ov_usb_data = res_overview_usb.get_json()
    assert ov_usb_data["hardware_mode"] == "usb"
    assert ov_usb_data["kpis"]["device_status"]["hardware_mode"] == "usb"

    res_health_usb = client.get("/api/health")
    assert res_health_usb.status_code == 200
    assert res_health_usb.get_json()["hardware_mode"] == "usb"

    # Case 3: MQTT transport -> hardware_mode 'mqtt'
    status_file.write_text(json.dumps({
        "transport": "mqtt",
        "simulated": False,
        "broker_connected": True,
        "online": True,
    }), encoding="utf-8")

    res_overview_mqtt = client.get("/api/overview")
    assert res_overview_mqtt.status_code == 200
    ov_mqtt_data = res_overview_mqtt.get_json()
    assert ov_mqtt_data["hardware_mode"] == "mqtt"
    assert ov_mqtt_data["kpis"]["device_status"]["hardware_mode"] == "mqtt"

    res_health_mqtt = client.get("/api/health")
    assert res_health_mqtt.status_code == 200
    assert res_health_mqtt.get_json()["hardware_mode"] == "mqtt"


def test_missing_device_status_file_derives_virtual_from_active_bridge(tmp_path, monkeypatch):
    """Cold-start missing file test: when device_status.json does not exist yet,
    hardware_mode falls back to the active bridge / policy auto mode. If VirtualBridge
    is active, hardware_mode must be 'virtual', status 'online', and hint 'Virtual Home (simulation)'.
    """
    set_bridge(None)
    try:
        set_bridge(VirtualBridge())
        dash_sec = secrets.token_hex(32)
        web_sec = secrets.token_hex(32)
        monkeypatch.setenv("AEGIS_DASH_SECRET", dash_sec)
        monkeypatch.setenv("AEGIS_WEB_SECRET", web_sec)
        monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))

        status_file = tmp_path / "device_status.json"
        if status_file.exists():
            status_file.unlink()

        app = create_app()
        app.config["TESTING"] = True
        client = app.test_client()

        csrf_token = secrets.token_hex(32)
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"
            sess["last_activity"] = time.time()
            sess["csrf_token"] = csrf_token

        # Even with no device_status.json file, /api/overview must report 'virtual'
        res_overview = client.get("/api/overview")
        assert res_overview.status_code == 200
        ov_data = res_overview.get_json()
        assert ov_data["hardware_mode"] == "virtual"
        assert ov_data["kpis"]["device_status"]["hardware_mode"] == "virtual"
        assert ov_data["kpis"]["device_status"]["status"] == "online"
        assert ov_data["kpis"]["device_status"]["hint"] == "Virtual Home (simulation)"

        # /api/health must report 'virtual'
        res_health = client.get("/api/health")
        assert res_health.status_code == 200
        h_data = res_health.get_json()
        assert h_data["hardware_mode"] == "virtual"
    finally:
        set_bridge(None)
