import json
import secrets
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

import pytest

import security.hardware
from agent.worker import DeviceStatusSubscriber, WorkerHeartbeatThread
from security.hardware import SerialHardwareBridge, get_bridge, set_bridge
from security.virtual_home import VirtualBridge
from web.server import create_app


class _FakePort:
    def __init__(self, device, description, hwid):
        self.device = device
        self.description = description
        self.hwid = hwid


class _FakeSerial:
    def __init__(self, responses=None):
        self.is_open = True
        self._responses = list(responses or ["EVENT: ping_ack\n"])
        self._buf = bytearray()
        self.writes = []
        self.reset_calls = 0

    def open(self):
        self.is_open = True

    def reset_input_buffer(self):
        self.reset_calls += 1

    def write(self, data):
        self.writes.append(data)
        if self._responses:
            chunk = self._responses.pop(0)
            self._buf.extend(chunk.encode("utf-8"))

    @property
    def in_waiting(self):
        return len(self._buf)

    def read(self, n):
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def close(self):
        self.is_open = False


def test_auto_mode_hotplug_upgrades_fallback_virtual_bridge(monkeypatch):
    """Auto mode fallback VirtualBridge upgrades to SerialHardwareBridge when USB appears."""
    set_bridge(None)
    try:
        ports_state = [[]]

        def fake_comports():
            return list(ports_state[0])

        monkeypatch.setattr("serial.tools.list_ports.comports", fake_comports)
        monkeypatch.setattr("serial.Serial", lambda *a, **kw: _FakeSerial())

        bridge1 = get_bridge()
        assert isinstance(bridge1, VirtualBridge)

        ports_state[0] = [
            _FakePort(
                "COM11",
                "Silicon Labs CP210x USB to UART Bridge (COM11)",
                "USB VID:PID=10C4:EA60 SER=0001",
            )
        ]

        bridge2 = get_bridge()
        assert isinstance(bridge2, SerialHardwareBridge)
        assert bridge2.port == "COM11"
    finally:
        set_bridge(None)


def test_explicit_virtual_bridge_not_overridden_by_comports(monkeypatch):
    """Explicit set_bridge(VirtualBridge()) stays VirtualBridge even if USB ports exist."""
    set_bridge(None)
    try:
        monkeypatch.setattr(
            "serial.tools.list_ports.comports",
            lambda: [
                _FakePort(
                    "COM11",
                    "Silicon Labs CP210x USB to UART Bridge (COM11)",
                    "USB VID:PID=10C4:EA60",
                )
            ],
        )
        explicit_vb = VirtualBridge()
        set_bridge(explicit_vb)
        assert get_bridge() is explicit_vb
    finally:
        set_bridge(None)


def test_serial_is_device_online_waits_for_boot_banner(monkeypatch):
    """Newly opened ESP32 serial port waits up to 1.4s boot window before pinging."""
    bridge = SerialHardwareBridge(port="COM99")
    fake_ser = _FakeSerial(["EVENT: ping_ack\n"])
    bridge._serial = fake_ser
    now_holder = [1000.0]
    slept = []

    bridge._last_opened_at = 999.9
    bridge._last_ping_time = 0.0

    monkeypatch.setattr(security.hardware.time, "time", lambda: now_holder[0])
    monkeypatch.setattr(
        security.hardware.time,
        "sleep",
        lambda secs: (slept.append(secs), now_holder.__setitem__(0, now_holder[0] + secs)),
    )

    assert bridge.is_device_online() is True
    assert slept and slept[0] >= 1.25
    assert fake_ser.writes == [b"ping\n"]


def test_worker_refresh_hardware_transitions_virtual_to_serial(tmp_path, monkeypatch):
    """WorkerHeartbeatThread._refresh_hardware writes virtual then usb_serial after USB hotplug."""
    set_bridge(None)
    try:
        ports_state = [[]]
        monkeypatch.setattr("serial.tools.list_ports.comports", lambda: list(ports_state[0]))
        monkeypatch.setattr("serial.Serial", lambda *a, **kw: _FakeSerial(["EVENT: ping_ack\n"]))
        monkeypatch.setattr(security.hardware.time, "sleep", lambda _s: None)

        sub = DeviceStatusSubscriber(data_dir=tmp_path)
        sub.start()
        hb = WorkerHeartbeatThread(tmp_path, "2026-01-01T00:00:00+00:00")
        hb.subscriber = sub

        hb._refresh_hardware()
        st1 = json.loads((tmp_path / "device_status.json").read_text(encoding="utf-8"))
        assert st1["transport"] == "virtual"
        assert st1["simulated"] is True
        assert st1["broker_connected"] is False

        ports_state[0] = [
            _FakePort(
                "COM11",
                "Silicon Labs CP210x USB to UART Bridge (COM11)",
                "USB VID:PID=10C4:EA60",
            )
        ]
        hb._refresh_hardware()
        st2 = json.loads((tmp_path / "device_status.json").read_text(encoding="utf-8"))
        assert st2["transport"] == "usb_serial"
        assert st2["simulated"] is False
        assert st2["broker_connected"] is True
        assert st2["online"] is True
        assert st2["port"] == "COM11"

        # Disconnect USB -> automatically reverts to Virtual Home simulation
        ports_state[0] = []
        hb._refresh_hardware()
        st3 = json.loads((tmp_path / "device_status.json").read_text(encoding="utf-8"))
        assert st3["transport"] == "virtual"
        assert st3["simulated"] is True
        assert st3["broker_connected"] is False
        assert st3["online"] is True
        assert st3["description"] == "Virtual Home (simulation)"
        assert isinstance(get_bridge(), VirtualBridge)

        # Reconnect USB -> automatically returns to SerialHardwareBridge
        ports_state[0] = [
            _FakePort(
                "COM11",
                "Silicon Labs CP210x USB to UART Bridge (COM11)",
                "USB VID:PID=10C4:EA60",
            )
        ]
        hb._refresh_hardware()
        st4 = json.loads((tmp_path / "device_status.json").read_text(encoding="utf-8"))
        assert st4["transport"] == "usb_serial"
        assert st4["simulated"] is False
        assert st4["online"] is True
    finally:
        set_bridge(None)


def _admin_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DASH_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("AEGIS_WEB_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    csrf = secrets.token_hex(32)
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["real_role"] = "admin"
        sess["last_activity"] = time.time()
        sess["csrf_token"] = csrf
    return client, {"X-CSRF-Token": csrf}


def test_api_hardware_status_includes_virtual_device_state(tmp_path, monkeypatch):
    client, _ = _admin_client(tmp_path, monkeypatch)
    (tmp_path / "device_status.json").write_text(
        json.dumps({"transport": "virtual", "simulated": True, "online": True}),
        encoding="utf-8",
    )
    (tmp_path / "virtual_home_state.json").write_text(
        json.dumps({"light": "on", "light_on": True, "door": "locked", "door_locked": True, "alarm": "off", "alarm_on": False}),
        encoding="utf-8",
    )

    res = client.get("/api/hardware/status")
    assert res.status_code == 200
    data = res.get_json()
    assert data["simulated"] is True
    assert data["hardware_mode"] == "virtual"
    assert data["device_state"]["light_on"] is True
    assert data["device_state"]["door_locked"] is True

    (tmp_path / "device_status.json").write_text(
        json.dumps({
            "transport": "usb_serial",
            "simulated": False,
            "broker_connected": True,
            "online": True,
            "port": "COM11",
            "timestamp": time.time(),
        }),
        encoding="utf-8",
    )
    res_usb = client.get("/api/hardware/status")
    assert res_usb.status_code == 200
    data_usb = res_usb.get_json()
    assert data_usb["simulated"] is False
    assert data_usb["hardware_mode"] == "usb"
    assert data_usb["hardware_status"] == "connected"
    assert data_usb["device_state"] is None


@pytest.mark.parametrize(
    "body",
    [
        {"command": "light_on", "args": [1]},
        {"command": "light_on", "args": {"blink_count": 0}},
        {"command": "light_on", "args": {"blink_count": 11}},
        {"command": "light_on", "args": {"blink_count": True}},
        {"command": "light_on", "args": {"extra": 1}},
        {"command": "alarm_on", "args": {"duration_seconds": 0}},
        {"command": "alarm_on", "args": {"duration_seconds": 31}},
        {"command": "unlock_door", "args": {"force": True}},
    ],
)
def test_api_hardware_actuate_rejects_invalid_args_with_400(tmp_path, monkeypatch, body):
    client, headers = _admin_client(tmp_path, monkeypatch)
    res = client.post("/api/hardware/actuate", json=body, headers=headers)
    assert res.status_code == 400
    assert "error" in res.get_json()


def test_api_hardware_actuate_passes_validated_args_and_approval(tmp_path, monkeypatch):
    client, headers = _admin_client(tmp_path, monkeypatch)
    (tmp_path / "worker_status.json").write_text(
        json.dumps({
            "alive": True,
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
            "pid": 12345,
        }),
        encoding="utf-8",
    )
    (tmp_path / "device_status.json").write_text(
        json.dumps({"transport": "virtual", "simulated": True, "online": True}),
        encoding="utf-8",
    )

    res_alarm = client.post(
        "/api/hardware/actuate",
        json={"command": "alarm_on", "args": {"duration_seconds": 5}},
        headers=headers,
    )
    assert res_alarm.status_code == 202
    alarm_data = res_alarm.get_json()
    assert alarm_data["status"] == "pending_approval"
    inbox_files = list((tmp_path / "chat" / "inbox").glob("req_*.json"))
    assert len(inbox_files) == 1
    queued = json.loads(inbox_files[0].read_text(encoding="utf-8"))
    assert queued["tool"] == {"name": "activate_alarm", "args": {"duration_seconds": 5}}


class _StalledSerial:
    """Simulates an ESP32 stalled in MQTT connecting... for ~4.2s before replying."""

    def __init__(self, clock_holder, delay_secs, reply_line):
        self.is_open = True
        self._clock = clock_holder
        self._delay = delay_secs
        self._reply = reply_line
        self._write_t = None
        self._mqtt_emitted = False
        self._buf = bytearray()

    def reset_input_buffer(self):
        self._buf.clear()

    def write(self, data):
        self._write_t = self._clock[0]
        self._mqtt_emitted = False
        self._buf.extend(b"MQTT connecting...\r\n")

    @property
    def in_waiting(self):
        if self._write_t is not None and not self._mqtt_emitted:
            if self._clock[0] - self._write_t >= self._delay:
                self._mqtt_emitted = True
                self._buf.extend((self._reply + "\r\n").encode("utf-8"))
        return len(self._buf)

    def read(self, n):
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def close(self):
        self.is_open = False


def test_serial_publish_and_ping_tolerate_esp32_mqtt_stall(monkeypatch):
    """publish() and is_device_online() survive 4.2s ESP32 MQTT retry stalls cleanly."""
    bridge = SerialHardwareBridge(port="COM99")
    clock = [2000.0]
    monkeypatch.setattr(security.hardware.time, "time", lambda: clock[0])
    monkeypatch.setattr(
        security.hardware.time,
        "sleep",
        lambda s: clock.__setitem__(0, clock[0] + s),
    )

    bridge._serial = _StalledSerial(clock, delay_secs=4.2, reply_line="EVENT: ping_ack")
    bridge._last_opened_at = 0.0
    bridge._last_ping_time = 0.0
    assert bridge.is_device_online() is True
    assert bridge._ping_acked_this_session is True

    bridge._serial = _StalledSerial(clock, delay_secs=4.2, reply_line="EVENT: light_on_done")
    res = bridge.publish("light_on")
    assert res.ok is True


def test_serial_is_device_online_single_miss_hysteresis_then_offline(monkeypatch):
    """Single timeout while USB port stays listed keeps online=True; 2nd consecutive miss flips False."""
    bridge = SerialHardwareBridge(port="COM11")
    bridge._detected_port = "COM11"
    bridge._serial = _FakeSerial(["NO_MATCH\n"])
    bridge.device_online = True
    bridge._last_opened_at = 0.0
    clock = [3000.0]
    monkeypatch.setattr(security.hardware.time, "time", lambda: clock[0])
    monkeypatch.setattr(
        security.hardware.time,
        "sleep",
        lambda s: clock.__setitem__(0, clock[0] + s),
    )
    monkeypatch.setattr(security.hardware, "find_usb_serial_ports", lambda *_a, **_kw: ["COM11"])

    bridge._last_ping_time = 0.0
    assert bridge.is_device_online() is True  # 1st miss tolerated while COM11 present

    clock[0] += 10.0
    assert bridge.is_device_online() is False  # 2nd consecutive miss -> offline


def test_turn_light_off_preempts_active_blink_worker(monkeypatch):
    """Calling turn_light_off stops any lingering turn_light_on blink sequence immediately."""
    import agent.tools as tools

    class _SeqFakeBridge:
        transport = "virtual"

        def __init__(self):
            self.cmds = []

        def is_device_online(self):
            return True

        def publish(self, cmd):
            self.cmds.append(cmd)
            return security.hardware.HardwareCommandResult(ok=True)

    b = _SeqFakeBridge()
    set_bridge(b)
    try:
        tools.turn_light_on(blink_count=6)
        time.sleep(0.05)
        tools.turn_light_off()
        count_at_off = len(b.cmds)
        time.sleep(0.8)
        assert b.cmds[-1] == "light_off"
        assert len(b.cmds) == count_at_off
    finally:
        set_bridge(None)


def test_worker_hardware_mode_switch_virtual_and_auto(tmp_path, monkeypatch):
    """_process_hardware_mode switches offline SerialHardwareBridge -> Virtual Home and back cleanly."""
    from agent.worker import _process_hardware_mode

    set_bridge(None)
    try:
        ports_state = [[]]
        monkeypatch.setattr("serial.tools.list_ports.comports", lambda: list(ports_state[0]))
        monkeypatch.setattr("serial.Serial", lambda *a, **kw: _FakeSerial(["EVENT: ping_ack\n"]))
        monkeypatch.setattr(security.hardware.time, "sleep", lambda _s: None)

        offline = SerialHardwareBridge(port="COM11")
        offline.device_online = False
        set_bridge(offline)

        sub = DeviceStatusSubscriber(data_dir=tmp_path)
        sub.broker_connected = True
        sub._write_device_status(is_online=False)
        dev_usb = json.loads((tmp_path / "device_status.json").read_text(encoding="utf-8"))
        assert dev_usb["device_id"] == "esp32-01"
        assert dev_usb["transport"] == "usb_serial"

        outbox = tmp_path / "out_v.jsonl"
        _process_hardware_mode({"id": "req_1", "role": "admin", "username": "admin", "mode": "virtual"}, outbox, sub)
        final_v = json.loads(outbox.read_text(encoding="utf-8").splitlines()[-1])
        assert final_v["decision"] == "ALLOW"
        assert isinstance(get_bridge(), VirtualBridge)

        dev_v = json.loads((tmp_path / "device_status.json").read_text(encoding="utf-8"))
        assert dev_v["transport"] == "virtual"
        assert dev_v["simulated"] is True
        assert dev_v["device_id"] == "virtual-home"

        # Because no USB was connected during switch, plugging USB back in later still auto-detects!
        ports_state[0] = [_FakePort("COM11", "Silicon Labs CP210x USB to UART Bridge (COM11)", "USB VID:PID=10C4:EA60")]
        assert isinstance(get_bridge(), SerialHardwareBridge)
    finally:
        set_bridge(None)


def test_api_hardware_mode_validation_and_role(tmp_path, monkeypatch):
    client, headers = _admin_client(tmp_path, monkeypatch)

    res_bad = client.post("/api/hardware/mode", json={"mode": "bogus"}, headers=headers)
    assert res_bad.status_code == 400

    with client.session_transaction() as sess:
        sess["role"] = "guest"
    res_forbidden = client.post("/api/hardware/mode", json={"mode": "virtual"}, headers=headers)
    assert res_forbidden.status_code == 403


def test_role_toggle_menu_rendered_only_for_real_admin(tmp_path, monkeypatch):
    client, _ = _admin_client(tmp_path, monkeypatch)

    # 1. Real admin in admin role -> sees Switch to Guest mode
    r1 = client.get("/overview")
    assert r1.status_code == 200
    html1 = r1.get_data(as_text=True)
    assert 'id="role-toggle-btn"' in html1
    assert "Switch to Guest mode" in html1

    # 2. Real admin simulating guest role -> STILL sees Switch back to Admin
    with client.session_transaction() as sess:
        sess["role"] = "guest"
        sess["real_role"] = "admin"
    r2 = client.get("/overview")
    html2 = r2.get_data(as_text=True)
    assert 'id="role-toggle-btn"' in html2
    assert "Switch back to Admin" in html2

    # 3. Genuine guest (real_role=guest) -> never sees role-toggle-btn
    with client.session_transaction() as sess:
        sess["role"] = "guest"
        sess["real_role"] = "guest"
    r3 = client.get("/overview")
    html3 = r3.get_data(as_text=True)
    assert 'id="role-toggle-btn"' not in html3
