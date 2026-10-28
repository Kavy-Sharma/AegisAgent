"""
Phase 7 -- Hardware Bridge & MQTT Integration Framework
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
import uuid

import paho.mqtt.client as mqtt

from security import logger, policy_loader

COMMAND_ALLOWLIST = {"light_on", "light_off", "unlock_door", "alarm_on", "alert_blocked", "ping"}


def load_env_file():
    """Reads a local .env file into os.environ without external dependencies."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip("'\""))


load_env_file()


def _get_data_dir() -> Path:
    return Path(os.environ.get("AEGIS_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))


@dataclass
class HardwareCommandResult:
    ok: bool
    error: str | None = None


class HardwareBridge:
    def __init__(self, policy_dict: dict | None = None):
        if policy_dict is None:
            policy_dict = policy_loader.POLICY

        hw_cfg = policy_dict.get("hardware", {})
        self.host = hw_cfg.get("broker_host", "127.0.0.1")
        self.port = int(hw_cfg.get("broker_port", 1883))
        self.device_id = hw_cfg.get("device_id", "esp32-01")
        self.timeout = float(hw_cfg.get("publish_timeout_seconds", 5))

        self.user = os.environ.get("AEGIS_MQTT_USER", "")
        self.password = os.environ.get("AEGIS_MQTT_PASS", "")

        self.cmd_topic = f"aegis/cmd/{self.device_id}"
        self.status_topic = f"aegis/status/{self.device_id}"

        self.device_online = False
        self.transport = "mqtt"
        self.description = f"MQTT Broker ({self.host}:{self.port})"
        self.client = None
        self._connect_event = threading.Event()
        self._status_event = threading.Event()
        self._connected = False
        self._connect_error = None

    def _create_client(self) -> mqtt.Client:
        client_id = f"aegis_gateway_{uuid.uuid4().hex[:8]}"
        if hasattr(mqtt, "CallbackAPIVersion"):
            client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2,
                client_id=client_id,
            )
        else:
            client = mqtt.Client(
                client_id=client_id,
            )

        if self.user and self.password:
            client.username_pw_set(self.user, self.password)

        client.on_connect = self._on_connect
        client.on_message = self._on_message
        if hasattr(client, "on_connect_fail"):
            client.on_connect_fail = self._on_connect_fail

        return client

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            self._connected = True
            client.subscribe(self.status_topic, qos=1)
            self._connect_event.set()
        else:
            self._connected = False
            self._connect_error = f"MQTT connection rejected (reason code: {reason_code})"
            self._connect_event.set()

    def _on_connect_fail(self, client, userdata):
        self._connected = False
        self._connect_error = "MQTT broker connection failed"
        self._connect_event.set()

    def _on_message(self, client, userdata, msg):
        try:
            if msg.topic == self.status_topic:
                payload = msg.payload.decode("utf-8").strip()
                self.device_online = (payload == "online")
                self._status_event.set()
        except Exception:
            pass

    def is_device_online(self) -> bool:
        return self.device_online

    def publish(self, command: str) -> HardwareCommandResult:
        if command not in COMMAND_ALLOWLIST:
            raise ValueError(f"Command '{command}' is not in hardware command allowlist")

        ok = False
        error_msg = None

        self._connect_event.clear()
        self._status_event.clear()
        self._connected = False
        self._connect_error = None
        self.device_online = False

        client = self._create_client()
        self.client = client

        try:
            connected_socket = False
            try:
                client.connect(self.host, self.port, keepalive=60)
                client.loop_start()
                connected_socket = True
            except Exception as e:
                ok = False
                error_msg = f"MQTT connection error: {e}"

            if connected_socket:
                if not self._connect_event.wait(timeout=5.0):
                    ok = False
                    error_msg = "MQTT connection timed out waiting for CONNACK"
                elif not self._connected:
                    ok = False
                    error_msg = self._connect_error or "MQTT connection failed"
                else:
                    # Subscribe to status topic and wait up to about 3 s for retained message
                    client.subscribe(self.status_topic, qos=1)
                    self._status_event.wait(timeout=3.0)

                    if not self.device_online:
                        ok = False
                        error_msg = "Device offline - command not delivered"
                    else:
                        payload_dict = {
                            "command": command,
                            "ts": time.time(),
                            "nonce": str(uuid.uuid4()),
                        }
                        payload_str = json.dumps(payload_dict)

                        try:
                            info = client.publish(self.cmd_topic, payload_str, qos=1)
                            info.wait_for_publish(timeout=self.timeout)
                            if info.is_published():
                                ok = True
                            else:
                                ok = False
                                error_msg = "MQTT publish acknowledgement timed out"
                        except Exception as e:
                            ok = False
                            error_msg = f"MQTT publish failed: {e}"

        except Exception as e:
            ok = False
            error_msg = f"MQTT error: {e}"
        finally:
            try:
                client.loop_stop()
            except Exception:
                pass
            try:
                client.disconnect()
            except Exception:
                pass

        logger.log_hardware_command(command, ok, error_msg)
        return HardwareCommandResult(ok=ok, error=error_msg)


class FakeBridge:
    def __init__(self, policy_dict: dict | None = None):
        self.command_history: list[str] = []
        self.connected: bool = True
        self.device_online_status: bool = True
        self.transport = "fake"
        self.port = "simulated"
        self.description = "Simulated Hardware Bridge"

    def is_device_online(self) -> bool:
        return self.connected and self.device_online_status

    def publish(self, command: str) -> HardwareCommandResult:
        if command not in COMMAND_ALLOWLIST:
            raise ValueError(f"Command '{command}' is not in hardware command allowlist")

        if not self.connected:
            ok = False
            error_msg = "Broker unreachable (simulated)"
        elif not self.device_online_status:
            ok = False
            error_msg = "Device offline - command not delivered"
        else:
            self.command_history.append(command)
            ok = True
            error_msg = None

        logger.log_hardware_command(command, ok, error_msg)
        return HardwareCommandResult(ok=ok, error=error_msg)


class SerialHardwareBridge:
    """
    Direct USB Serial transport for ESP32 hardware device.
    Enforces periodic ping/ACK for liveness and verified ACK for command delivery.
    Bridges maintain state in memory; worker subscriber is the single writer to disk.
    """
    def __init__(self, port: str | None = None, baud: int = 115200, policy_dict: dict | None = None):
        if policy_dict is None:
            policy_dict = policy_loader.POLICY

        hw_cfg = policy_dict.get("hardware", {})
        self.port_setting = port or hw_cfg.get("serial_port", "auto")
        self.baud = int(hw_cfg.get("baud_rate", baud))
        self.device_id = hw_cfg.get("device_id", "esp32-01")
        self.device_online = False
        self._lock = threading.RLock()
        self._serial = None
        self._detected_port = None
        self._detected_desc = None
        self._last_opened_at = 0.0
        self._last_ping_time = 0.0
        self._try_connect()

    @property
    def transport(self) -> str:
        return "usb_serial"

    @property
    def port(self) -> str:
        return str(self._detected_port or self.port_setting or "unknown")

    @property
    def description(self) -> str:
        return str(self._detected_desc or "USB Serial ESP32 Device")

    def _detect_port(self) -> str | None:
        try:
            import serial.tools.list_ports
            ports = list(serial.tools.list_ports.comports())
            for p in ports:
                desc = (p.description or "").lower()
                hwid = (p.hwid or "").lower()
                if any(k in desc or k in hwid for k in ["cp210", "ch340", "ftdi", "usb to uart", "esp32", "silicon labs"]):
                    self._detected_desc = p.description
                    return p.device
            for p in ports:
                if "usb" in (p.hwid or "").lower() or "usb" in (p.description or "").lower():
                    self._detected_desc = p.description
                    return p.device
        except Exception:
            pass
        return None

    def _format_port_name(self, port_str: str) -> str:
        if os.name == "nt" and port_str.upper().startswith("COM"):
            try:
                num = int(port_str[3:])
                if num >= 10 and not port_str.startswith(r"\\.\ "):
                    return rf"\\.\{port_str}"
            except ValueError:
                pass
        return port_str

    def _try_connect(self) -> bool:
        with self._lock:
            if self._serial is not None and getattr(self._serial, "is_open", False):
                return True
            target_port = self.port_setting
            if not target_port or target_port == "auto":
                target_port = self._detect_port()
            if not target_port:
                self.device_online = False
                return False

            self._detected_port = target_port
            fmt_port = self._format_port_name(target_port)
            try:
                import serial
                s = serial.Serial()
                s.port = fmt_port
                s.baudrate = self.baud
                s.timeout = 0.25
                s.write_timeout = 1.0
                try:
                    s.dtr = False
                    s.rts = False
                except Exception:
                    pass
                s.open()
                self._serial = s
                self._last_opened_at = time.time()
                return True
            except Exception:
                self.device_online = False
                return False

    def is_device_online(self) -> bool:
        """
        Determines device online status by periodically sending a 'ping' command
        and verifying an ACK response from the physical device (not just checking is_open).
        """
        with self._lock:
            now = time.time()
            if now - self._last_ping_time < 3.0:
                return self.device_online

            if not self._serial or not getattr(self._serial, "is_open", False):
                if not self._try_connect():
                    self.device_online = False
                    self._last_ping_time = now
                    return False

            try:
                try:
                    self._serial.reset_input_buffer()
                except Exception:
                    pass

                self._serial.write(b"ping\n")
                t0 = time.time()
                ack_found = False
                while time.time() - t0 < 0.4:
                    if self._serial.in_waiting:
                        chunk = self._serial.read(self._serial.in_waiting).decode("utf-8", errors="ignore")
                        if any(k in chunk for k in ("STATUS:online", "ping_ack", "EVENT:", "USB_RECV:")):
                            ack_found = True
                            break
                    time.sleep(0.02)

                self.device_online = ack_found
                self._last_ping_time = now
                return self.device_online
            except Exception:
                self.device_online = False
                self._last_ping_time = now
                try:
                    if self._serial:
                        self._serial.close()
                except Exception:
                    pass
                self._serial = None
                return False

    def publish(self, command: str) -> HardwareCommandResult:
        if command not in COMMAND_ALLOWLIST:
            raise ValueError(f"Command '{command}' is not in hardware command allowlist")

        with self._lock:
            if not self._serial or not getattr(self._serial, "is_open", False):
                if not self._try_connect():
                    logger.log_hardware_command(command, False, "USB hardware not connected")
                    return HardwareCommandResult(ok=False, error="USB hardware not connected")

            try:
                # If newly opened, wait a moment for ESP32 boot banner if needed
                if time.time() - self._last_opened_at < 1.4:
                    time.sleep(max(0.05, 1.4 - (time.time() - self._last_opened_at)))

                try:
                    self._serial.reset_input_buffer()
                except Exception:
                    pass

                line_to_send = f"{command}\n".encode("utf-8")
                self._serial.write(line_to_send)

                t0 = time.time()
                ack_found = False
                while time.time() - t0 < 0.8:
                    if self._serial.in_waiting:
                        chunk = self._serial.read(self._serial.in_waiting).decode("utf-8", errors="ignore")
                        if any(k in chunk for k in ("EVENT:", "USB_RECV:", "done", "door", "alarm", "alert", "STATUS:", "ping_ack")):
                            ack_found = True
                            break
                    time.sleep(0.02)

                if not ack_found:
                    self.device_online = False
                    logger.log_hardware_command(command, False, "no ACK from device")
                    return HardwareCommandResult(ok=False, error="no ACK from device")

                self.device_online = True
                logger.log_hardware_command(command, True, None)
                return HardwareCommandResult(ok=True)
            except Exception as e:
                self.device_online = False
                try:
                    if self._serial:
                        self._serial.close()
                except Exception:
                    pass
                self._serial = None
                logger.log_hardware_command(command, False, str(e))
                return HardwareCommandResult(ok=False, error=str(e))


_bridge_instance = None


def get_bridge():
    global _bridge_instance
    if _bridge_instance is None:
        hw_cfg = policy_loader.POLICY.get("hardware", {})
        mode = hw_cfg.get("mode", "mqtt")

        if mode == "fake":
            _bridge_instance = FakeBridge()
        elif mode == "serial":
            _bridge_instance = SerialHardwareBridge()
        elif mode == "mqtt":
            _bridge_instance = HardwareBridge()
        elif mode == "auto":
            # Check if USB serial device is available first
            try:
                import serial.tools.list_ports
                ports = list(serial.tools.list_ports.comports())
                usb_ports = [
                    p.device for p in ports
                    if any(k in (p.description or "").lower() or k in (p.hwid or "").lower()
                           for k in ["cp210", "ch340", "ftdi", "usb to uart", "esp32", "silicon labs"])
                ]
                if usb_ports:
                    _bridge_instance = SerialHardwareBridge(port=usb_ports[0])
            except Exception:
                pass

            if _bridge_instance is None:
                _bridge_instance = HardwareBridge()
        else:
            # Mode not fake: fail closed to HardwareBridge (never silent FakeBridge)
            _bridge_instance = HardwareBridge()

    return _bridge_instance


def set_bridge(bridge):
    global _bridge_instance
    _bridge_instance = bridge


_last_alert_time = 0.0


def reset_alert_debounce():
    global _last_alert_time
    _last_alert_time = 0.0


def trigger_block_alert():
    """
    Triggers the physical red alert_blocked LED on the hardware device in a background thread.
    Enforces a 2-second debounce filter. Never raises or disrupts caller flow.
    """
    global _last_alert_time
    alert_on_block = policy_loader.POLICY.get("hardware", {}).get("alert_on_block", True)
    if not alert_on_block:
        return

    now = time.time()
    if now - _last_alert_time < 2.0:
        return  # Debounce filter
    _last_alert_time = now

    def _do_alert():
        try:
            bridge = get_bridge()
            bridge.publish("alert_blocked")
        except Exception:
            pass  # Never crash agent or change decision

    threading.Thread(target=_do_alert, daemon=True).start()


