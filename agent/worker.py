"""
Phase 8A & Phase 8A-fix -- Agent Worker Service

WHAT THIS FILE DOES:
1. Polls data/chat/inbox/*.json every 0.3s for incoming user requests.
2. Validates request IDs and inbox file stems against ^[A-Za-z0-9_-]{8,64}$ before
   building ANY path. Prevents path traversal (e.g. '../../evil').
3. Verifies cryptographic signature using security.signing.
4. Enforces replay protection: rejects if |now - ts| > 60s or nonce was seen before
   (maintains seen_nonces capped at 2000 in memory + data/chat/seen_nonces.json).
5. Enforces valid kind ('chat', 'direct_tool') and roles defined in policy.yaml.
6. Dispatches chat requests to run_turn(text, role, session_id, emit) with role taken
   strictly from the signed request.
7. Dispatches 'direct_tool' requests through gateway.evaluate(..., emit=emit) without
   duplicating policy checks; rate limit counted exactly once.
8. Streams execution steps to data/chat/outbox/<id>.jsonl and writes final reply and decision.
9. Runs worker heartbeat on a daemon thread every 2s with busy and current_request_id fields,
   and refreshes ollama_ok every 15s with a cheap ollama.list() (2s timeout).
10. Maintains MQTT device status and events, recording broker_connected in device_status.json.
11. Handles graceful shutdown on Ctrl+C and never crashes on a single bad request.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import threading
import time

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import ollama
from agent.agent import AVAILABLE_FUNCTIONS, MODEL, TOOL_SCHEMAS, TurnResult, run_turn
import security.gateway
import security.hardware
import security.logger
import security.policy_loader
import security.rate_limiter
import security.signing

ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def _get_data_dir() -> Path:
    data_dir = Path(os.environ.get("AEGIS_DATA_DIR", ROOT_DIR / "data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


class DeviceStatusSubscriber:
    """Maintains a persistent MQTT subscription for hardware status and events."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.client = None
        self.is_running = False
        self.broker_connected = False
        self._last_state = None
        self._since = None
        self._status_lock = threading.Lock()

        hw_cfg = security.policy_loader.POLICY.get("hardware", {})
        self.mode = hw_cfg.get("mode", "mqtt")
        self.host = hw_cfg.get("broker_host", "127.0.0.1")
        self.port = int(hw_cfg.get("broker_port", 1883))
        self.device_id = hw_cfg.get("device_id", "esp32-01")

        self.status_topic = f"aegis/status/{self.device_id}"
        self.event_topic = f"aegis/status/{self.device_id}/event"

        self.user = os.environ.get("AEGIS_MQTT_USER", "")
        self.password = os.environ.get("AEGIS_MQTT_PASS", "")

    def _write_device_status(self, is_online: bool | None = None):
        with self._status_lock:
            status_file = self.data_dir / "device_status.json"
            now_iso = datetime.now(timezone.utc).isoformat()
            current = {}
            if status_file.exists():
                try:
                    current = json.loads(status_file.read_text(encoding="utf-8"))
                except Exception:
                    current = {}

            current["broker_connected"] = bool(self.broker_connected)
            if is_online is not None:
                if is_online != self._last_state:
                    self._last_state = is_online
                    self._since = now_iso
                current["online"] = is_online
                current["device_online"] = is_online
                current["last_seen"] = now_iso
                current["since"] = self._since or now_iso
                current["timestamp"] = time.time()
                try:
                    active_bridge = security.hardware.get_bridge()
                    if hasattr(active_bridge, "transport"):
                        current["transport"] = str(active_bridge.transport)
                    if hasattr(active_bridge, "port"):
                        current["port"] = str(active_bridge.port)
                    if hasattr(active_bridge, "description"):
                        current["description"] = str(active_bridge.description)
                except Exception:
                    pass

            tmp_file = status_file.with_name(f"device_status.tmp.{secrets.token_hex(4)}")
            try:
                with open(tmp_file, "w", encoding="utf-8") as f:
                    f.write(json.dumps(current, indent=2))
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except Exception:
                        pass
                os.replace(tmp_file, status_file)
            except Exception:
                pass

    def start(self):
        if self.mode in ("auto", "serial"):
            try:
                bridge = security.hardware.get_bridge()
                if isinstance(bridge, security.hardware.SerialHardwareBridge):
                    is_on = bridge.is_device_online()
                    self.broker_connected = True
                    self._write_device_status(is_online=is_on)
                    self.is_running = True
                    print(f"[WORKER] USB Serial hardware subscriber active (port={getattr(bridge, 'port', 'unknown')}, online={is_on})")
                else:
                    self.broker_connected = True
                    self._write_device_status(is_online=bridge.is_device_online())
                    self.is_running = True
            except Exception as e:
                print(f"[WORKER] USB Serial initialization note: {e}")
            return

        if self.mode != "mqtt":
            return

        try:
            import paho.mqtt.client as mqtt

            client_id = f"aegis_worker_{secrets.token_hex(4)}"
            if hasattr(mqtt, "CallbackAPIVersion"):
                self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
            else:
                self.client = mqtt.Client(client_id=client_id)

            if self.user and self.password:
                self.client.username_pw_set(self.user, self.password)

            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.on_message = self._on_message

            self.client.connect(self.host, self.port, keepalive=60)
            self.client.loop_start()
            self.is_running = True
            print(f"[WORKER] MQTT subscriber active on {self.status_topic}")
        except Exception as e:
            self.broker_connected = False
            self._write_device_status()
            print(f"[WORKER] MQTT subscriber could not connect ({e}). Continuing.")

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            self.broker_connected = True
            self._write_device_status()
            client.subscribe(self.status_topic, qos=1)
            client.subscribe(self.event_topic, qos=1)
        else:
            self.broker_connected = False
            self._write_device_status()

    def _on_disconnect(self, client, userdata, flags_or_rc=None, reason_code=None, properties=None):
        self.broker_connected = False
        self._write_device_status()

    def _on_message(self, client, userdata, msg):
        try:
            payload = msg.payload.decode("utf-8").strip()
            now_iso = datetime.now(timezone.utc).isoformat()

            if msg.topic == self.status_topic:
                is_online = (payload.lower() == "online")
                self._write_device_status(is_online=is_online)

            elif msg.topic == self.event_topic:
                events_file = self.data_dir / "device_events.jsonl"
                try:
                    event_data = json.loads(payload)
                except Exception:
                    event_data = {"event": payload}

                if "timestamp" not in event_data:
                    event_data["timestamp"] = now_iso

                # Read existing lines, cap at last 500
                existing_lines = []
                if events_file.exists():
                    try:
                        existing_lines = events_file.read_text(encoding="utf-8").strip().splitlines()
                    except Exception:
                        existing_lines = []

                existing_lines.append(json.dumps(event_data))
                capped = existing_lines[-500:]

                tmp_events = events_file.with_name(f"device_events.tmp.{secrets.token_hex(4)}")
                with open(tmp_events, "w", encoding="utf-8") as f:
                    f.write("\n".join(capped) + "\n")
                os.replace(tmp_events, events_file)

        except Exception as e:
            print(f"[WORKER] MQTT message error: {e}")

    def stop(self):
        self.broker_connected = False
        self._write_device_status()
        if self.client and self.is_running:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass
            self.is_running = False


class WorkerHeartbeatThread(threading.Thread):
    """Daemon thread writing heartbeat every 2s and refreshing ollama_ok every 15s."""

    def __init__(self, data_dir: Path, started_at_iso: str):
        super().__init__(daemon=True)
        self.data_dir = data_dir
        self.started_at_iso = started_at_iso
        self.running = True
        self.busy = False
        self.current_request_id = None
        self.ollama_ok = False
        self.model_warm = False
        self._last_ollama_check = 0.0
        self._last_hw_check = 0.0

    def run(self):
        while self.running:
            now = time.time()
            if now - self._last_ollama_check >= 15.0:
                self._refresh_ollama()
                self._last_ollama_check = now

            if now - self._last_hw_check >= 3.0:
                self._refresh_hardware()
                self._last_hw_check = now

            self.write_heartbeat()
            time.sleep(2.0)

    def _refresh_hardware(self):
        try:
            hw_cfg = security.policy_loader.POLICY.get("hardware", {})
            mode = hw_cfg.get("mode", "auto")
            if mode in ("auto", "serial"):
                bridge = security.hardware.get_bridge()
                if hasattr(bridge, "is_device_online"):
                    is_on = bridge.is_device_online()
                    if hasattr(self, "subscriber") and self.subscriber:
                        self.subscriber.broker_connected = True
                        self.subscriber._write_device_status(is_online=is_on)
        except Exception:
            pass

    def _refresh_ollama(self):
        try:
            client = ollama.Client(timeout=2.0)
            client.list()
            self.ollama_ok = True
        except Exception:
            self.ollama_ok = False

    def write_heartbeat(self):
        status_data = {
            "busy": self.busy,
            "current_request_id": self.current_request_id,
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
            "model_warm": self.model_warm,
            "ollama_ok": self.ollama_ok,
            "pid": os.getpid(),
            "started_at": self.started_at_iso,
        }
        status_file = self.data_dir / "worker_status.json"
        tmp_file = status_file.with_name(f"worker_status.tmp.{secrets.token_hex(4)}")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                f.write(json.dumps(status_data, indent=2))
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
            os.replace(tmp_file, status_file)
        except Exception:
            pass

    def set_busy(self, busy: bool, request_id: str | None = None):
        self.busy = busy
        self.current_request_id = request_id
        self.write_heartbeat()

    def stop(self):
        self.running = False


def _write_heartbeat(
    data_dir: Path,
    started_at_iso: str,
    ollama_ok: bool,
    model_warm: bool,
    busy: bool = False,
    current_request_id: str | None = None,
):
    """Module-level heartbeat writer kept for backward compatibility."""
    status_data = {
        "busy": busy,
        "current_request_id": current_request_id,
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "model_warm": model_warm,
        "ollama_ok": ollama_ok,
        "pid": os.getpid(),
        "started_at": started_at_iso,
    }
    status_file = data_dir / "worker_status.json"
    tmp_file = status_file.with_name(f"worker_status.tmp.{secrets.token_hex(4)}")
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(status_data, indent=2))
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp_file, status_file)
    except Exception:
        pass


def _load_seen_nonces(data_dir: Path) -> list[str]:
    nonces_file = data_dir / "chat" / "seen_nonces.json"
    if not nonces_file.exists():
        return []
    try:
        data = json.loads(nonces_file.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data[-2000:]
    except Exception:
        pass
    return []


def _save_seen_nonces(data_dir: Path, nonces: list[str]):
    chat_dir = data_dir / "chat"
    chat_dir.mkdir(parents=True, exist_ok=True)
    nonces_file = chat_dir / "seen_nonces.json"
    tmp_file = nonces_file.with_name(f"seen_nonces.tmp.{secrets.token_hex(4)}")
    try:
        capped = nonces[-2000:]
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(capped))
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp_file, nonces_file)
    except Exception:
        pass


def _write_rejection_outbox(outbox_file: Path, message: str):
    err_line = {
        "detail": {"error": message},
        "stage": "worker",
        "status": "error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    final_line = {
        "decision": "BLOCK",
        "error": message,
        "final": True,
        "reply": f"Request rejected: {message}.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with open(outbox_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(err_line) + "\n")
            f.write(json.dumps(final_line) + "\n")
            f.flush()
    except Exception:
        pass


def _process_direct_tool(req: dict, emit, outbox_file: Path):
    username = req.get("username", "guest")
    if security.quarantine.is_quarantined(username):
        msg = f"Account '{username}' is in containment lockdown (quarantined). Admin release required."
        for s in ("detection", "intent", "llm", "rbac", "rate_limit", "approval", "hardware", "output_scan"):
            emit(s, "skip", {"reason": "User quarantined"})
        final = {
            "decision": "BLOCK",
            "error": msg,
            "final": True,
            "reply": f"Request blocked: {msg}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(outbox_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(final) + "\n")
            f.flush()
        return
    raw_tool = req.get("tool")
    if isinstance(raw_tool, str):
        tool_name = raw_tool
        tool_args = {}
    elif isinstance(raw_tool, dict):
        tool_name = raw_tool.get("name", "")
        tool_args = raw_tool.get("args", {}) or {}
    else:
        tool_name = ""
        tool_args = {}

    user_text = req.get("text") or f"Direct execution of {tool_name}"
    role = req.get("role", "guest")
    session_id = req.get("session_id", "direct_tool_session")

    emit("detection", "skip", {"reason": "direct_tool bypasses prompt injection scan"})
    emit("intent", "skip", {"reason": "direct_tool bypasses intent lock"})
    emit("llm", "skip", {"reason": "direct_tool bypasses LLM"})

    # Evaluate permissions, rate limits, and approvals via gateway.evaluate without duplicate checks
    eval_res = security.gateway.evaluate(
        tool_name=tool_name,
        tool_args=tool_args,
        user_text=user_text,
        role=role,
        session_id=session_id,
        emit=emit,
    )
    decision = eval_res.get("decision")
    reason = eval_res.get("reason", "")

    if decision != "ALLOW":
        for s in ("hardware", "output_scan"):
            emit(s, "skip", {"reason": f"Blocked: {reason}"})
        final = {
            "decision": "BLOCK",
            "error": reason,
            "final": True,
            "reply": f"Request blocked by policy: {reason}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(outbox_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(final) + "\n")
            f.flush()
        return

    # Hardware execution
    emit("hardware", "running", {"args": tool_args, "tool": tool_name})
    try:
        if tool_name not in AVAILABLE_FUNCTIONS:
            raise RuntimeError(f"Tool '{tool_name}' has no registered execution function")
        expected_args = TOOL_SCHEMAS.get(tool_name, set())
        clean_args = {k: v for k, v in tool_args.items() if k in expected_args}
        tool_res = AVAILABLE_FUNCTIONS[tool_name](**clean_args)
        emit("hardware", "pass", {"result": str(tool_res), "tool": tool_name})
    except Exception as e:
        emit("hardware", "error", {"error": str(e), "tool": tool_name})
        emit("output_scan", "skip", {"reason": "Hardware execution error"})
        final = {
            "decision": "ERROR",
            "error": str(e),
            "final": True,
            "reply": f"Execution error: {e}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(outbox_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(final) + "\n")
            f.flush()
        return

    # Output scan
    emit("output_scan", "skip", {"reason": "direct_tool does not generate conversational text"})

    final = {
        "decision": "ALLOW",
        "error": None,
        "final": True,
        "reply": f"Executed {tool_name} successfully: {tool_res}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_called": tool_name,
        "tool_result": tool_res,
    }
    with open(outbox_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(final) + "\n")
        f.flush()


def prune_stale_files(data_dir: Path | None = None):
    """
    Prunes files older than 24h from outbox and decisions, and purges expired pending approvals.
    Runs at worker startup and hourly.
    """
    if data_dir is None:
        data_dir = _get_data_dir()
    now = time.time()
    cutoff_24h = now - (24 * 3600)

    # 1. Prune data/chat/outbox/*.jsonl > 24h
    outbox_dir = data_dir / "chat" / "outbox"
    if outbox_dir.exists():
        for p in outbox_dir.glob("*.jsonl"):
            try:
                if p.stat().st_mtime < cutoff_24h:
                    p.unlink(missing_ok=True)
            except Exception:
                pass

    # 2. Purge data/approvals/pending/*.json (expired or > 24h)
    pending_dir = data_dir / "approvals" / "pending"
    if pending_dir.exists():
        for p in pending_dir.glob("*.json"):
            try:
                stale = False
                if p.stat().st_mtime < cutoff_24h:
                    stale = True
                else:
                    try:
                        data = json.loads(p.read_text(encoding="utf-8"))
                        expires_at = data.get("expires_at", 0)
                        if expires_at and expires_at < now:
                            stale = True
                    except Exception:
                        stale = True
                if stale:
                    p.unlink(missing_ok=True)
            except Exception:
                pass

    # 3. Prune data/approvals/decisions/*.json > 24h
    decisions_dir = data_dir / "approvals" / "decisions"
    if decisions_dir.exists():
        for p in decisions_dir.glob("*.json"):
            try:
                if p.stat().st_mtime < cutoff_24h:
                    p.unlink(missing_ok=True)
            except Exception:
                pass


def run_worker():
    data_dir = _get_data_dir()
    inbox_dir = data_dir / "chat" / "inbox"
    outbox_dir = data_dir / "chat" / "outbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)
    outbox_dir.mkdir(parents=True, exist_ok=True)

    # VULN-08: Prune outbox and purge stale approvals at worker startup
    prune_stale_files(data_dir)

    # High fix: Single-worker lockfile to prevent double actuation
    lock_file_path = data_dir / "worker.lock"
    lock_fd = None
    try:
        lock_fd = open(lock_file_path, "a+")
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock_fd.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.seek(0)
        lock_fd.truncate()
        lock_fd.write(f"{os.getpid()}\n")
        lock_fd.flush()
    except (OSError, IOError) as e:
        print(f"[WORKER] Fatal: Another worker is already running (lock held at {lock_file_path}: {e}). Exiting.")
        sys.exit(1)

    started_at_iso = datetime.now(timezone.utc).isoformat()
    print("=" * 60)
    print(" AegisAgent Worker Service ".center(60, "="))
    print(f" PID: {os.getpid()} | Started: {started_at_iso}")
    print(f" Polling: {inbox_dir}")
    print("=" * 60)

    # Warm up Ollama model
    ollama_ok = False
    model_warm = False
    print("[WORKER] Warming up Ollama model...")
    try:
        ollama.chat(model=MODEL, messages=[{"role": "user", "content": "hi"}], keep_alive="30m")
        ollama_ok = True
        model_warm = True
        print("[WORKER] Model warmed up and ready.")
    except Exception as e:
        print(f"[WORKER] Notice: Ollama not reachable on start ({e}). Continuing.")

    # Start Heartbeat Daemon Thread
    hb_thread = WorkerHeartbeatThread(data_dir, started_at_iso)
    hb_thread.ollama_ok = ollama_ok
    hb_thread.model_warm = model_warm
    hb_thread.write_heartbeat()
    hb_thread.start()

    # Load seen nonces
    seen_nonces_list = _load_seen_nonces(data_dir)
    seen_nonces_set = set(seen_nonces_list)

    # Start MQTT Subscriber
    device_subscriber = DeviceStatusSubscriber(data_dir)
    device_subscriber.start()
    hb_thread.subscriber = device_subscriber

    running = True

    def _sig_handler(sig, frame):
        nonlocal running
        print("\n[WORKER] Shutdown signal received. Exiting...")
        running = False

    signal.signal(signal.SIGINT, _sig_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sig_handler)

    last_prune_time = time.time()
    while running:
        # VULN-08: Hourly pruning
        if time.time() - last_prune_time >= 3600:
            try:
                prune_stale_files(data_dir)
            except Exception:
                pass
            last_prune_time = time.time()

        inbox_files = sorted(inbox_dir.glob("*.json"))
        for req_file in inbox_files:
            stem = req_file.stem
            is_stem_valid = bool(ID_PATTERN.match(stem))

            try:
                content = req_file.read_text(encoding="utf-8").strip()
                if not content:
                    try:
                        req_file.unlink()
                    except Exception:
                        pass
                    continue
                req = json.loads(content)
            except Exception as e:
                # Audit worker_rejected for malformed JSON
                security.logger.log_event(
                    "worker_rejected",
                    {
                        "error": str(e),
                        "file": req_file.name,
                        "reason": "malformed_json",
                    },
                )
                if is_stem_valid:
                    outbox_file = outbox_dir / f"{stem}.jsonl"
                    _write_rejection_outbox(outbox_file, "malformed JSON in request")

                try:
                    req_file.unlink()
                except Exception:
                    pass
                continue

            # Validate ID against ID_PATTERN
            req_id = req.get("id")
            is_id_valid = isinstance(req_id, str) and bool(ID_PATTERN.match(req_id))

            # Validate kind
            kind = req.get("kind", "chat")
            is_kind_valid = kind in ("chat", "direct_tool")

            # Validate role defined in policy.yaml
            valid_roles = set(security.policy_loader.POLICY.get("roles", {}).keys())
            role = req.get("role", "guest")
            is_role_valid = isinstance(role, str) and (role in valid_roles)

            # Validate timestamp (epoch seconds, |now - ts| <= 60s)
            ts = req.get("ts")
            is_ts_valid = False
            if ts is not None and isinstance(ts, (int, float)):
                if abs(time.time() - float(ts)) <= 60.0:
                    is_ts_valid = True

            # Validate nonce (16 random bytes hex = 32 hex chars)
            nonce = req.get("nonce")
            is_nonce_valid = (
                isinstance(nonce, str)
                and len(nonce) == 32
                and all(c in "0123456789abcdefABCDEF" for c in nonce)
            )
            is_nonce_new = is_nonce_valid and (nonce not in seen_nonces_set)

            # Check signature
            sig = req.get("signature")
            sign_payload = {k: v for k, v in req.items() if k != "signature"}
            is_sig_valid = bool(sig and security.signing.verify(sign_payload, sig))

            # Determine rejection reason
            reject_reason = None
            reject_detail = None

            if not is_sig_valid:
                reject_reason = "bad_or_missing_signature"
                reject_detail = "invalid or missing cryptographic signature"
            elif not is_id_valid:
                reject_reason = "invalid_request_id"
                reject_detail = "request id format is invalid"
            elif not is_kind_valid:
                reject_reason = "unknown_kind"
                reject_detail = f"unknown request kind '{kind}'"
            elif not is_role_valid:
                reject_reason = "invalid_role"
                reject_detail = f"role '{role}' is not defined in policy"
            elif not is_ts_valid:
                reject_reason = "stale_timestamp"
                reject_detail = "request timestamp is missing or outside 60-second window"
            elif not is_nonce_valid:
                reject_reason = "invalid_nonce"
                reject_detail = "request nonce is missing or not a 16-byte hex token"
            elif not is_nonce_new:
                reject_reason = "replayed_nonce"
                reject_detail = "request nonce has already been seen (replay detected)"

            if reject_reason is not None:
                security.logger.log_event(
                    "worker_rejected",
                    {
                        "file": req_file.name,
                        "id": req_id if is_id_valid else "invalid",
                        "reason": reject_reason,
                        "username": req.get("username", "unknown"),
                    },
                )
                # Unsigned/invalid requests: use the inbox file stem (also validated) for outbox, never req["id"].
                # If stem is invalid, write no outbox file at all.
                if is_stem_valid:
                    outbox_file = outbox_dir / f"{stem}.jsonl"
                    _write_rejection_outbox(outbox_file, reject_detail)

                try:
                    req_file.unlink()
                except Exception:
                    pass
                continue

            # Record seen nonce and persist atomically
            seen_nonces_set.add(nonce)
            seen_nonces_list.append(nonce)
            if len(seen_nonces_list) > 2000:
                seen_nonces_list = seen_nonces_list[-2000:]
                seen_nonces_set = set(seen_nonces_list)
            _save_seen_nonces(data_dir, seen_nonces_list)

            # Valid request: build outbox path using validated req_id
            outbox_file = outbox_dir / f"{req_id}.jsonl"

            # Remove inbox file once read
            try:
                req_file.unlink()
            except Exception:
                pass

            def emit(stage: str, status: str, detail: dict):
                step = {
                    "detail": detail,
                    "stage": stage,
                    "status": status,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "owner": req.get("username", "guest"),
                }
                with open(outbox_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(step) + "\n")
                    f.flush()

            # Process request with busy state in heartbeat thread
            hb_thread.set_busy(True, req_id)
            try:
                if kind == "direct_tool":
                    _process_direct_tool(req, emit, outbox_file)
                else:
                    assigned_role = role
                    user_text = req.get("text", "")
                    session_id = req.get("session_id", "default")

                    res = run_turn(text=user_text, role=assigned_role, session_id=session_id, emit=emit, request_id=req_id, username=req.get("username", "guest"))
                    final = {
                        "decision": res.decision,
                        "error": res.error,
                        "final": True,
                        "reply": res.reply,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "tool_called": res.tool_called,
                        "tool_result": res.tool_result,
                        "owner": req.get("username", "guest"),
                    }
                    with open(outbox_file, "a", encoding="utf-8") as f:
                        f.write(json.dumps(final) + "\n")
                        f.flush()
            except Exception as e:
                print(f"[WORKER] Error processing request {req_id}: {e}")
                err_final = {
                    "decision": "ERROR",
                    "error": str(e),
                    "final": True,
                    "reply": f"Worker encountered an internal error: {e}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                with open(outbox_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(err_final) + "\n")
                    f.flush()
            finally:
                hb_thread.set_busy(False, None)

        time.sleep(0.3)

    hb_thread.stop()
    device_subscriber.stop()
    if lock_fd:
        try:
            if os.name == "nt":
                import msvcrt
                lock_fd.seek(0)
                msvcrt.locking(lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            lock_fd.close()
        except Exception:
            pass
    print("[WORKER] Worker stopped gracefully.")


if __name__ == "__main__":
    run_worker()
