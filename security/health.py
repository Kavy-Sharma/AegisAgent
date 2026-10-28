"""
Phase 8A-fix -- Single Source of Truth for System Health & Telemetry

WHAT THIS FILE DOES:
Provides get_system_health() -> dict as the authoritative health inspection function
for all dashboard pages and CLI status commands.
Covers:
1. Agent Worker (alive if last_heartbeat < 10s old, plus busy flag and current_request_id).
2. Ollama Engine (polled by worker).
3. Broker link (worker's MQTT connection status).
4. ESP32 Hardware Device (derived from device_status.json: broker_connected false -> 'unknown';
   otherwise retained state 'online'/'offline'; no file -> 'unknown'. Does not mark unknown
   merely because last_seen is old).
5. Audit Log Hash Chain (cached verification result, re-verified at most once every 30s).
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Any

from security.verify_log import check_audit_log_status

ROOT_DIR = Path(__file__).resolve().parent.parent

# Module-level cache for audit log verification: (is_intact: bool, message: str, checked_at: float)
_audit_cache: tuple[bool, str, float] | None = None


def _get_data_dir() -> Path:
    return Path(os.environ.get("AEGIS_DATA_DIR", ROOT_DIR / "data"))


def get_system_health(force_audit_check: bool = False) -> dict[str, Any]:
    """
    Returns the comprehensive runtime health dictionary across all subsystems.
    This is the single source of truth for all UIs and health checks.
    """
    global _audit_cache
    now = time.time()
    now_utc = datetime.now(timezone.utc)
    data_dir = _get_data_dir()

    # 1. Worker Status
    worker_file = data_dir / "worker_status.json"
    worker_alive = False
    worker_busy = False
    worker_pid = None
    current_request_id = None
    last_hb_str = None
    model_warm = False
    ollama_ok = False
    worker_detail = "Worker not running"

    if worker_file.exists():
        try:
            w_data = json.loads(worker_file.read_text(encoding="utf-8"))
            last_hb_str = w_data.get("last_heartbeat")
            if last_hb_str:
                hb_dt = datetime.fromisoformat(last_hb_str)
                if hb_dt.tzinfo is None:
                    hb_dt = hb_dt.replace(tzinfo=timezone.utc)
                age = (now_utc - hb_dt).total_seconds()
                # Worker considered alive if heartbeat is less than 10s old
                if age < 10.0:
                    worker_alive = True

            worker_busy = bool(w_data.get("busy", False))
            current_request_id = w_data.get("current_request_id")
            worker_pid = w_data.get("pid")
            model_warm = bool(w_data.get("model_warm", False))
            ollama_ok = bool(w_data.get("ollama_ok", False))

            if worker_alive:
                state_str = "Busy" if worker_busy else "Idle"
                worker_detail = f"PID {worker_pid} ({state_str})"
            else:
                worker_detail = "Heartbeat expired (>10s)"
        except Exception:
            worker_detail = "Invalid worker status"

    # 2. Broker & Device Status
    device_file = data_dir / "device_status.json"
    broker_connected = False
    device_status = "unknown"
    device_last_seen = None
    device_since = None
    device_transport = "mqtt"
    device_port = None
    device_desc = None

    if device_file.exists():
        try:
            d_data = json.loads(device_file.read_text(encoding="utf-8"))
            broker_connected = bool(d_data.get("broker_connected", False))
            device_last_seen = d_data.get("last_seen")
            device_since = d_data.get("since")
            device_transport = d_data.get("transport", "mqtt")
            device_port = d_data.get("port")
            device_desc = d_data.get("description")

            # Rule: broker_connected false -> "unknown"; otherwise last retained state "online"/"offline"
            if not broker_connected:
                device_status = "unknown"
            else:
                is_online = d_data.get("online")
                if is_online is None:
                    is_online = d_data.get("device_online")

                if is_online is True:
                    device_status = "online"
                elif is_online is False:
                    device_status = "offline"
                else:
                    device_status = "unknown"
        except Exception:
            device_status = "unknown"
    else:
        # No file -> "unknown"
        device_status = "unknown"
        broker_connected = False

    # If worker is not alive, ollama is not reachable via worker and device status is unknown
    if not worker_alive:
        ollama_ok = False
        if worker_file.exists() or not broker_connected:
            device_status = "unknown"

    # 3. Ollama Status
    ollama_status = "ready" if ollama_ok else "offline"

    # 4. Broker Status
    broker_status = "connected" if broker_connected else "disconnected"

    # 5. Audit Chain Verification (cached, re-verified at most once per 30s)
    if force_audit_check or _audit_cache is None or (now - _audit_cache[2]) >= 30.0:
        is_intact, msg = check_audit_log_status()
        _audit_cache = (is_intact, msg, now)
    else:
        is_intact, msg, _ = _audit_cache

    return {
        "worker": {
            "alive": worker_alive,
            "busy": worker_busy,
            "current_request_id": current_request_id,
            "pid": worker_pid,
            "last_heartbeat": last_hb_str,
            "model_warm": model_warm,
            "ollama_ok": ollama_ok,
            "detail": worker_detail,
        },
        "ollama": {
            "ok": ollama_ok,
            "status": ollama_status,
        },
        "broker": {
            "connected": broker_connected,
            "status": broker_status,
        },
        "device": {
            "status": device_status,  # "online", "offline", "unknown"
            "broker_connected": broker_connected,
            "last_seen": device_last_seen,
            "since": device_since,
            "transport": device_transport,
            "port": device_port,
            "description": device_desc,
        },
        "audit_chain": {
            "intact": is_intact,
            "message": msg,
            "last_checked": _audit_cache[2],
        },
    }
