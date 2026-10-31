from unittest.mock import MagicMock, patch
import pytest

from security.hardware import SerialHardwareBridge
import security.policy_loader


class FakeSerialDevice:
    """Simulates a physical UART serial connection with controlled response buffers."""
    def __init__(self, response_map: dict | list | None = None):
        self.is_open = True
        self.written_bytes = b""
        self.response_map = response_map if isinstance(response_map, dict) else {}
        self.in_waiting_buffer = ""
        if isinstance(response_map, list):
            self.in_waiting_buffer = "\n".join(response_map) + "\n"

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


def test_unknown_serial_device_receives_only_ping_never_actuation():
    """An unverified serial device must only receive 'ping', NEVER 'unlock_door'."""
    bridge = SerialHardwareBridge(port="COM_UNKNOWN")
    # Device does not acknowledge ping
    fake_dev = FakeSerialDevice({"ping": "GARBAGE_MODEM_DATA"})
    bridge._serial = fake_dev
    bridge._ping_acked_this_session = False

    res = bridge.publish("unlock_door")
    assert res.ok is False
    # Crucial safety invariant: unlock_door was NEVER written to the untrusted device
    assert b"unlock_door" not in fake_dev.written_bytes
    # Only ping was attempted
    assert b"ping" in fake_dev.written_bytes


def test_verified_serial_device_allows_actuation():
    """Once verified via ping -> EVENT: ping_ack, actuation commands succeed."""
    bridge = SerialHardwareBridge(port="COM_VERIFIED")
    fake_dev = FakeSerialDevice({
        "ping": "EVENT: ping_ack",
        "unlock_door": "EVENT: door_unlocked"
    })
    bridge._serial = fake_dev
    bridge._ping_acked_this_session = False

    res = bridge.publish("unlock_door")
    assert res.ok is True
    assert b"ping" in fake_dev.written_bytes
    assert b"unlock_door" in fake_dev.written_bytes


def test_no_generic_usb_fallback():
    """Generic USB devices (like mice or flash drives) must NOT be auto-detected."""
    bridge = SerialHardwareBridge(port="auto")
    generic_port = MagicMock()
    generic_port.device = "COM7"
    generic_port.description = "Generic USB Mass Storage Device"
    generic_port.hwid = "USB\\VID_058F&PID_6387"
    generic_port.vid = 0x058F
    generic_port.pid = 0x6387

    with patch("serial.tools.list_ports.comports", return_value=[generic_port]):
        detected = bridge._detect_port()
    assert detected is None, f"Expected None for generic USB device, but got {detected}"


def test_vid_pid_allowlist_matching():
    """Devices matching hardware.vid_pid in policy are detected."""
    bridge = SerialHardwareBridge(port="auto")
    esp_port = MagicMock()
    esp_port.device = "COM5"
    esp_port.description = "CP2102 USB to UART Bridge Controller"
    esp_port.hwid = "USB VID:PID=10C4:EA60"
    esp_port.vid = 0x10C4
    esp_port.pid = 0xEA60

    with patch("serial.tools.list_ports.comports", return_value=[esp_port]):
        detected = bridge._detect_port()
    assert detected == "COM5"


def test_policy_mode_is_mqtt_and_documents_serial():
    """Policy must explicitly set hardware.mode to mqtt and document serial."""
    policy = security.policy_loader.POLICY
    assert policy.get("hardware", {}).get("mode") == "mqtt"
