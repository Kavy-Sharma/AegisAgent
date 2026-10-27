"""
Phase 7 — Hardware Bridge & MQTT Integration Framework
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import threading
import time
import uuid

import paho.mqtt.client as mqtt

from security import logger, policy_loader

COMMAND_ALLOWLIST = {"light_on", "light_off", "unlock_door", "alarm_on", "alert_blocked"}


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


_bridge_instance = None


def get_bridge():
    global _bridge_instance
    if _bridge_instance is None:
        mode = policy_loader.POLICY.get("hardware", {}).get("mode", "fake")
        if mode == "mqtt":
            try:
                _bridge_instance = HardwareBridge()
            except Exception:
                _bridge_instance = FakeBridge()
        else:
            _bridge_instance = FakeBridge()
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
    Triggers the physical red alert_blocked LED on the hardware device.
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

    try:
        bridge = get_bridge()
        bridge.publish("alert_blocked")
    except Exception:
        pass  # Never crash agent or change decision

