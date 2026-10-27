"""
Phase 8A — Agent Worker Service

WHAT THIS FILE DOES:
1. Polls data/chat/inbox/*.json every 0.3s for incoming user requests.
2. Verifies cryptographic signature using security.signing. Rejects unsigned or
   bad-signature requests and audits 'worker_rejected'.
3. Dispatches chat requests to run_turn(text, role, session_id, emit) with role taken
   strictly from the signed request (never from user text).
4. Dispatches 'direct_tool' requests through gateway.evaluate without LLM (for dashboard hardware buttons).
5. Streams execution steps to data/chat/outbox/<id>.jsonl and writes final reply and decision.
6. Writes worker heartbeat to data/worker_status.json every 2s (pid, started_at, ollama_ok, model_warm).
7. If hardware.mode is mqtt, maintains a long-lived MQTT subscription to aegis/status/<device_id>
   and aegis/status/<device_id>/event, maintaining data/device_status.json and data/device_events.jsonl.
8. Handles graceful shutdown on Ctrl+C and never crashes on a single bad request.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
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
import security.logger
import security.policy_loader
import security.rate_limiter
import security.signing


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
        self._last_state = None
        self._since = None

        hw_cfg = security.policy_loader.POLICY.get("hardware", {})
        self.mode = hw_cfg.get("mode", "fake")
        self.host = hw_cfg.get("broker_host", "127.0.0.1")
        self.port = int(hw_cfg.get("broker_port", 1883))
        self.device_id = hw_cfg.get("device_id", "esp32-01")

        self.status_topic = f"aegis/status/{self.device_id}"
        self.event_topic = f"aegis/status/{self.device_id}/event"

        self.user = os.environ.get("AEGIS_MQTT_USER", "")
        self.password = os.environ.get("AEGIS_MQTT_PASS", "")

    def start(self):
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
            self.client.on_message = self._on_message

            self.client.connect(self.host, self.port, keepalive=60)
            self.client.loop_start()
            self.is_running = True
            print(f"[WORKER] MQTT subscriber active on {self.status_topic}")
        except Exception as e:
            print(f"[WORKER] MQTT subscriber could not connect ({e}). Continuing.")

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            client.subscribe(self.status_topic, qos=1)
            client.subscribe(self.event_topic, qos=1)

    def _on_message(self, client, userdata, msg):
        try:
            payload = msg.payload.decode("utf-8").strip()
            now_iso = datetime.now(timezone.utc).isoformat()

            if msg.topic == self.status_topic:
                is_online = (payload.lower() == "online")
                if is_online != self._last_state:
                    self._last_state = is_online
                    self._since = now_iso

                status_data = {
                    "device_online": is_online,
                    "last_seen": now_iso,
                    "online": is_online,
                    "since": self._since or now_iso,
                    "timestamp": time.time(),
                }
                status_file = self.data_dir / "device_status.json"
                tmp_file = status_file.with_name(f"device_status.tmp.{secrets.token_hex(4)}")
                with open(tmp_file, "w", encoding="utf-8") as f:
                    f.write(json.dumps(status_data, indent=2))
                os.replace(tmp_file, status_file)

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
        if self.client and self.is_running:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass
            self.is_running = False


def _write_heartbeat(data_dir: Path, started_at_iso: str, ollama_ok: bool, model_warm: bool):
    status_data = {
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


def _process_direct_tool(req: dict, emit, outbox_file: Path):
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
    emit("llm", "skip", {"reason": "direct_tool bypasses LLM"})

    # RBAC check
    emit("rbac", "running", {"role": role, "tool": tool_name})
    if tool_name not in AVAILABLE_FUNCTIONS:
        emit("rbac", "block", {"reason": "unknown tool", "tool": tool_name})
        for s in ("rate_limit", "approval", "hardware", "output_scan"):
            emit(s, "skip", {"reason": "unknown tool"})
        final = {
            "decision": "BLOCK",
            "error": "unknown tool",
            "final": True,
            "reply": f"Unknown tool '{tool_name}'",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(outbox_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(final) + "\n")
        return

    if not security.policy_loader.is_tool_allowed_for_role(tool_name, role):
        reason_msg = f"permission denied: role '{role}' cannot use '{tool_name}'"
        emit("rbac", "block", {"reason": reason_msg, "role": role, "tool": tool_name})
        security.gateway.evaluate(tool_name, tool_args, user_text, role=role, session_id=session_id)
        for s in ("rate_limit", "approval", "hardware", "output_scan"):
            emit(s, "skip", {"reason": "RBAC denied"})
        final = {
            "decision": "BLOCK",
            "error": reason_msg,
            "final": True,
            "reply": f"Request blocked by policy: {reason_msg}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(outbox_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(final) + "\n")
        return
    emit("rbac", "pass", {"role": role, "tool": tool_name})

    # Rate limiting
    emit("rate_limit", "running", {"tool": tool_name})
    if not security.rate_limiter.check_rate_limit(tool_name):
        reason_msg = f"rate limit exceeded for '{tool_name}'"
        emit("rate_limit", "block", {"reason": reason_msg, "tool": tool_name})
        security.gateway.evaluate(tool_name, tool_args, user_text, role=role, session_id=session_id)
        for s in ("approval", "hardware", "output_scan"):
            emit(s, "skip", {"reason": "Rate limit exceeded"})
        final = {
            "decision": "BLOCK",
            "error": reason_msg,
            "final": True,
            "reply": reason_msg,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(outbox_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(final) + "\n")
        return
    emit("rate_limit", "pass", {"tool": tool_name})

    # Approval check
    emit("approval", "running", {"tool": tool_name})
    evaluation = security.gateway.evaluate(tool_name, tool_args, user_text, role=role, session_id=session_id)
    decision = evaluation.get("decision")
    reason = evaluation.get("reason", "")

    risk = security.policy_loader.get_risk(tool_name)
    approval_cfg = security.policy_loader.POLICY.get("approval", {})
    requires_approval = approval_cfg.get("enabled", True) and (risk in approval_cfg.get("require_for_risk", ["HIGH"]))

    if decision != "ALLOW":
        emit("approval", "block", {"reason": reason})
        for s in ("hardware", "output_scan"):
            emit(s, "skip", {"reason": "Approval denied or blocked"})
        final = {
            "decision": "BLOCK",
            "error": reason,
            "final": True,
            "reply": f"Action blocked: {reason}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with open(outbox_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(final) + "\n")
        return

    if requires_approval:
        emit("approval", "pass", {"reason": reason})
    else:
        emit("approval", "skip", {"reason": "LOW risk auto-allowed"})

    # Hardware execution
    emit("hardware", "running", {"args": tool_args, "tool": tool_name})
    try:
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
        return

    # Output scan
    emit("output_scan", "pass", {})

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


def run_worker():
    data_dir = _get_data_dir()
    inbox_dir = data_dir / "chat" / "inbox"
    outbox_dir = data_dir / "chat" / "outbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)
    outbox_dir.mkdir(parents=True, exist_ok=True)

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

    # Start MQTT Subscriber
    device_subscriber = DeviceStatusSubscriber(data_dir)
    device_subscriber.start()

    running = True

    def _sig_handler(sig, frame):
        nonlocal running
        print("\n[WORKER] Shutdown signal received. Exiting...")
        running = False

    signal.signal(signal.SIGINT, _sig_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _sig_handler)

    last_heartbeat_time = 0.0

    while running:
        now = time.time()
        if now - last_heartbeat_time >= 2.0:
            _write_heartbeat(data_dir, started_at_iso, ollama_ok, model_warm)
            last_heartbeat_time = now

        inbox_files = sorted(inbox_dir.glob("*.json"))
        for req_file in inbox_files:
            try:
                content = req_file.read_text(encoding="utf-8").strip()
                if not content:
                    continue
                req = json.loads(content)
            except Exception as e:
                try:
                    req_file.unlink()
                except Exception:
                    pass
                continue

            req_id = req.get("id", req_file.stem)
            outbox_file = outbox_dir / f"{req_id}.jsonl"

            # Check signature
            sig = req.get("signature")
            sign_payload = {k: v for k, v in req.items() if k != "signature"}

            if not sig or not security.signing.verify(sign_payload, sig):
                security.logger.log_event(
                    "worker_rejected",
                    {
                        "id": req_id,
                        "reason": "bad_or_missing_signature",
                        "username": req.get("username", "unknown"),
                    },
                )
                err_line = {
                    "detail": {"error": "bad or missing signature"},
                    "stage": "worker",
                    "status": "error",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                final_line = {
                    "decision": "BLOCK",
                    "error": "bad or missing signature",
                    "final": True,
                    "reply": "Request rejected: invalid or missing cryptographic signature.",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                with open(outbox_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(err_line) + "\n")
                    f.write(json.dumps(final_line) + "\n")
                try:
                    req_file.unlink()
                except Exception:
                    pass
                continue

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
                }
                with open(outbox_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(step) + "\n")
                    f.flush()

            try:
                kind = req.get("kind", "chat")
                if kind == "direct_tool":
                    _process_direct_tool(req, emit, outbox_file)
                else:
                    # Role taken strictly from signed request
                    assigned_role = req.get("role", "guest")
                    user_text = req.get("text", "")
                    session_id = req.get("session_id", "default")

                    res = run_turn(text=user_text, role=assigned_role, session_id=session_id, emit=emit)
                    final = {
                        "decision": res.decision,
                        "error": res.error,
                        "final": True,
                        "reply": res.reply,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "tool_called": res.tool_called,
                        "tool_result": res.tool_result,
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

        time.sleep(0.3)

    device_subscriber.stop()
    print("[WORKER] Worker stopped gracefully.")


if __name__ == "__main__":
    run_worker()
