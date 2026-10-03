"""
Phase 7 — Hardware Bridge & MQTT Integration Framework
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
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
        self.timeout = float(hw_cfg.get("publish_timeout_seconds", 3))

        self.user = os.environ.get("AEGIS_MQTT_USER", "")
        self.password = os.environ.get("AEGIS_MQTT_PASS", "")

        self.cmd_topic = f"aegis/cmd/{self.device_id}"
        self.status_topic = f"aegis/status/{self.device_id}"

        self.device_online = False
        self.client = mqtt.Client(client_id=f"aegis_gateway_{uuid.uuid4().hex[:8]}")

        if self.user and self.password:
            self.client.username_pw_set(self.user, self.password)

        self.client.on_message = self._on_message
        self.client.on_connect = self._on_connect

        try:
            self.client.connect_async(self.host, self.port, keepalive=60)
            self.client.loop_start()
        except Exception as e:
            # Client stays unconnected; publish calls will report failure cleanly
            pass

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            client.subscribe(self.status_topic, qos=1)

    def _on_message(self, client, userdata, msg):
        try:
            payload = msg.payload.decode("utf-8").strip()
            if payload == "online":
                self.device_online = True
            elif payload == "offline":
                self.device_online = False
        except Exception:
            pass

    def is_device_online(self) -> bool:
        return self.device_online

    def publish(self, command: str) -> HardwareCommandResult:
        if command not in COMMAND_ALLOWLIST:
            raise ValueError(f"Command '{command}' is not in hardware command allowlist")

        payload_dict = {
            "command": command,
            "ts": time.time(),
            "nonce": str(uuid.uuid4()),
        }
        payload_str = json.dumps(payload_dict)

        ok = False
        error_msg = None

        try:
            info = self.client.publish(self.cmd_topic, payload_str, qos=1)
            info.wait_for_publish(timeout=self.timeout)
            if info.is_published():
                ok = True
            else:
                ok = False
                error_msg = "MQTT publish acknowledgement timed out"
        except Exception as e:
            ok = False
            error_msg = f"MQTT error: {e}"

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

