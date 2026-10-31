"""
VirtualHome Bridge (Simulated Hardware Adapter)

Provides an in-memory simulation adapter for home automation devices:
- Light (on / off)
- Door (locked / unlocked, auto-locks after 3s)
- Alarm (on / off)
- Ping / Alert Blocked

Conforms to the HardwareBridge interface (is_device_online, publish)
and returns HardwareCommandResult with adapter="virtual".
State is written atomically to data/virtual_home_state.json after every change.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import threading
from datetime import datetime, timezone
from typing import Any

from security import logger
from security.hardware import COMMAND_ALLOWLIST, HardwareCommandResult


def _get_data_dir() -> Path:
    return Path(os.environ.get("AEGIS_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))


class VirtualBridge:
    """
    In-memory simulation bridge that matches the HardwareBridge interface.
    """

    def __init__(self, policy_dict: dict | None = None, auto_lock_delay: float = 3.0, state_file: Path | None = None):
        self.transport = "virtual"
        self.adapter = "virtual"
        self.port = "virtual"
        self.description = "Virtual Home Simulated Bridge"
        self.connected: bool = True
        self.device_online_status: bool = True
        self.command_history: list[str] = []
        self.auto_lock_delay: float = auto_lock_delay
        self._state_file = state_file

        self._lock = threading.Lock()
        self._relock_timer: threading.Timer | None = None

        self.state: dict[str, Any] = {
            "light": "off",
            "door": "locked",
            "alarm": "off",
            "door_locked": True,
            "light_on": False,
            "alarm_on": False,
            "last_command": None,
            "adapter": "virtual",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_state()

    def get_state_file_path(self) -> Path:
        if self._state_file is not None:
            return self._state_file
        return _get_data_dir() / "virtual_home_state.json"

    def is_device_online(self) -> bool:
        return self.connected and self.device_online_status

    def _save_state(self) -> None:
        target_path = self.get_state_file_path()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write via temporary file in the same directory
        temp_file = target_path.with_suffix(".tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
            os.replace(temp_file, target_path)
        except Exception:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass

    def _relock_door(self) -> None:
        with self._lock:
            self.state["door"] = "locked"
            self.state["door_locked"] = True
            self.state["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._save_state()

    def publish(self, command: str) -> HardwareCommandResult:
        if command not in COMMAND_ALLOWLIST:
            raise ValueError(f"Command '{command}' is not in hardware command allowlist")

        with self._lock:
            if not self.connected or not self.device_online_status:
                ok = False
                error_msg = "Virtual device offline"
            else:
                ok = True
                error_msg = None
                self.command_history.append(command)
                self.state["last_command"] = command
                self.state["updated_at"] = datetime.now(timezone.utc).isoformat()

                if command == "light_on":
                    self.state["light"] = "on"
                    self.state["light_on"] = True
                elif command == "light_off":
                    self.state["light"] = "off"
                    self.state["light_on"] = False
                elif command == "unlock_door":
                    self.state["door"] = "unlocked"
                    self.state["door_locked"] = False
                    if self._relock_timer and self._relock_timer.is_alive():
                        self._relock_timer.cancel()
                    self._relock_timer = threading.Timer(self.auto_lock_delay, self._relock_door)
                    self._relock_timer.daemon = True
                    self._relock_timer.start()
                elif command == "alarm_on":
                    self.state["alarm"] = "on"
                    self.state["alarm_on"] = True
                elif command == "ping":
                    pass
                elif command == "alert_blocked":
                    self.state["alert_blocked_active"] = True

                self._save_state()

        logger.log_hardware_command(command, ok, error_msg, adapter="virtual")
        return HardwareCommandResult(ok=ok, error=error_msg, adapter="virtual")

    def close(self) -> None:
        if self._relock_timer and self._relock_timer.is_alive():
            self._relock_timer.cancel()

