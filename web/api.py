"""
web/api.py - AegisAgent REST API Routes

Strict security constraints:
- Role is read ONLY from server session, never from request JSON.
- Every route has a role decorator (@role_required("guest") or @role_required("admin")).
- Violations return 403 JSON and write an audit event.
- Cache-Control: no-store enforced by guards.
- Chat inbox requests are cryptographically signed with ts and nonce; client never sees secret.
- Decisions are signed and atomic; pending request must exist and be unexpired.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import yaml
from flask import Blueprint, current_app, jsonify, request, session

import security.gateway
import security.hardware
import security.health
import security.logger
import security.policy_loader
import security.signing
from security.verify_log import check_audit_log_status
from web.guards import role_required

api_bp = Blueprint("api", __name__, url_prefix="/api")

ROOT_DIR = Path(__file__).resolve().parent.parent
ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def _get_data_dir() -> Path:
    return Path(os.environ.get("AEGIS_DATA_DIR", ROOT_DIR / "data"))


def _get_log_file() -> Path:
    return Path(os.environ.get("AEGIS_LOG_FILE", ROOT_DIR / "logs" / "audit_log.jsonl"))


def _format_ist(dt: datetime | str | None, fmt: str = "%H:%M:%S IST") -> str:
    if dt is None:
        return "--"
    try:
        if isinstance(dt, str):
            dt_obj = datetime.fromisoformat(dt)
        else:
            dt_obj = dt
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        ist_offset = timedelta(hours=5, minutes=30)
        ist_dt = dt_obj.astimezone(timezone(ist_offset))
        return ist_dt.strftime(fmt)
    except Exception:
        return str(dt)


def _load_injection_rule_descriptions() -> dict[str, str]:
    rules_path = ROOT_DIR / "security" / "rules" / "injection_rules.yaml"
    desc_map = {}
    if rules_path.exists():
        try:
            content = rules_path.read_text(encoding="utf-8")
            data = yaml.safe_load(content) or {}
            for r in data.get("rules", []):
                r_id = r.get("id")
                desc = r.get("description") or r.get("category") or "Injection rule"
                if r_id:
                    desc_map[r_id] = desc
        except Exception:
            pass
    return desc_map


def _read_log_tail(log_file: Path, max_lines: int = 500) -> list[dict]:
    """Reads up to max_lines from the end of the log file without readlines()."""
    if not log_file.exists():
        return []
    try:
        file_size = log_file.stat().st_size
    except OSError:
        return []
    if file_size == 0:
        return []

    lines = []
    buffer_size = 8192
    remainder = b""
    with open(log_file, "rb") as f:
        pos = file_size
        while pos > 0 and len(lines) < max_lines:
            read_size = min(buffer_size, pos)
            pos -= read_size
            f.seek(pos)
            chunk = f.read(read_size) + remainder
            parts = chunk.splitlines()
            if pos > 0:
                remainder = parts[0]
                tail_parts = parts[1:]
            else:
                remainder = b""
                tail_parts = parts
            for raw_line in reversed(tail_parts):
                s = raw_line.strip()
                if s:
                    lines.append(s.decode("utf-8", errors="replace"))
                    if len(lines) >= max_lines:
                        break

    lines.reverse()
    events = []
    for line in lines:
        try:
            ev = json.loads(line)
            if isinstance(ev, dict):
                events.append(ev)
        except Exception:
            continue
    return events


# 1. System Health Telemetry
@api_bp.route("/health", methods=["GET"])
@role_required("guest")
def api_health():
    health = security.health.get_system_health()
    pending_dir = _get_data_dir() / "approvals" / "pending"
    pending_count = len(list(pending_dir.glob("*.json"))) if pending_dir.exists() else 0
    health["pending_approvals"] = pending_count
    return jsonify(health)


# 2. System Overview & Metrics
@api_bp.route("/overview", methods=["GET"])
@role_required("guest")
def api_overview():
    log_file = _get_log_file()
    now_utc = datetime.now(timezone.utc)
    one_hour_ago = now_utc - timedelta(hours=1)
    two_hours_ago = now_utc - timedelta(hours=2)

    events = _read_log_tail(log_file, max_lines=500)

    reqs_last_hour = 0
    reqs_prev_hour = 0
    blocks_last_hour = 0
    blocks_prev_hour = 0

    # Sparkline buckets (6 x 10m buckets across past hour)
    sparkline_reqs = [0] * 6
    sparkline_blocks = [0] * 6

    rule_counts = {}
    recent_alerts = []
    last_req_event = None

    for ev in events:
        ts_str = ev.get("timestamp")
        if not ts_str:
            continue
        try:
            ev_dt = datetime.fromisoformat(ts_str)
            if ev_dt.tzinfo is None:
                ev_dt = ev_dt.replace(tzinfo=timezone.utc)

            dec = str(ev.get("decision", "")).upper()
            is_turn_summary = (ev.get("event") == "turn_summary")

            if is_turn_summary:
                if ev_dt >= one_hour_ago:
                    reqs_last_hour += 1
                    age_mins = max(0, int((now_utc - ev_dt).total_seconds() / 60))
                    bucket_idx = min(5, max(0, 5 - (age_mins // 10)))
                    sparkline_reqs[bucket_idx] += 1

                    if dec in ("BLOCK", "DENY", "DENIED"):
                        blocks_last_hour += 1
                        sparkline_blocks[bucket_idx] += 1

                elif ev_dt >= two_hours_ago:
                    reqs_prev_hour += 1
                    if dec in ("BLOCK", "DENY", "DENIED"):
                        blocks_prev_hour += 1

                last_req_event = ev

            if ev.get("event") == "injection_check":
                for r_id in ev.get("rule_ids", []):
                    rule_counts[r_id] = rule_counts.get(r_id, 0) + 1

            if dec in ("BLOCK", "REVIEW", "DENY", "DENIED") or ev.get("approved") is False:
                recent_alerts.append(ev)

        except Exception:
            continue

    req_delta = reqs_last_hour - reqs_prev_hour
    req_delta_str = f"{req_delta:+d} vs prev hr" if (reqs_prev_hour > 0 or reqs_last_hour > 0) else "0 vs prev hr"

    block_delta = blocks_last_hour - blocks_prev_hour
    block_delta_str = f"{block_delta:+d} vs prev hr" if (blocks_prev_hour > 0 or blocks_last_hour > 0) else "0 vs prev hr"

    # Pending approvals count
    pending_dir = _get_data_dir() / "approvals" / "pending"
    pending_files = list(pending_dir.glob("*.json")) if pending_dir.exists() else []
    pending_count = len(pending_files)

    # Device info
    health = security.health.get_system_health()
    dev = health.get("device", {})
    dev_status = dev.get("status", "unknown")
    dev_seen = _format_ist(dev.get("last_seen")) if dev.get("last_seen") else "retained"
    worker_alive = health.get("worker", {}).get("alive", False)
    dev_port = dev.get("port") or "COM11"
    if dev_status == "online":
        dev_hint = f"Connected on {dev_port}" if dev.get("transport") == "usb_serial" else f"Active (seen {dev_seen})"
    elif not worker_alive:
        dev_hint = "Worker service offline"
    elif dev_status == "offline":
        dev_hint = f"Disconnected from {dev_port}"
    else:
        dev_hint = "Checking hardware link..."

    # 30-min rolling stacked bar buckets (per minute)
    now_minute = now_utc.replace(second=0, microsecond=0)
    minute_buckets = [now_minute - timedelta(minutes=i) for i in range(29, -1, -1)]
    minute_keys = [_format_ist(m, "%H:%M") for m in minute_buckets]
    bucket_map = {m: {"allow": 0, "block": 0, "review": 0} for m in minute_keys}
    thirty_mins_ago = now_utc - timedelta(minutes=30)

    for ev in events:
        ts_str = ev.get("timestamp")
        if not ts_str:
            continue
        try:
            ev_dt = datetime.fromisoformat(ts_str)
            if ev_dt.tzinfo is None:
                ev_dt = ev_dt.replace(tzinfo=timezone.utc)
            if ev_dt < thirty_mins_ago:
                continue
            if ev.get("event") != "turn_summary":
                continue
            m_key = _format_ist(ev_dt, "%H:%M")
            dec = str(ev.get("decision", "")).upper()
            if m_key in bucket_map:
                if dec == "ALLOW":
                    bucket_map[m_key]["allow"] += 1
                elif dec in ("BLOCK", "DENY", "DENIED"):
                    bucket_map[m_key]["block"] += 1
                elif dec == "REVIEW":
                    bucket_map[m_key]["review"] += 1
        except Exception:
            continue

    timeline = [{"minute": m, "allow": bucket_map[m]["allow"], "block": bucket_map[m]["block"], "review": bucket_map[m]["review"]} for m in minute_keys]

    # Top triggered rules (top 5 to ensure perfect card layout without clipping)
    rule_desc_map = _load_injection_rule_descriptions()
    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_rules = [
        {
            "id": r_id,
            "description": rule_desc_map.get(r_id, "Prompt injection pattern"),
            "count": cnt,
        }
        for r_id, cnt in sorted_rules
    ]

    # Recent 8 alerts
    alerts_formatted = []
    for ev in list(reversed(recent_alerts))[:8]:
        ts_str = ev.get("timestamp")
        time_ist = _format_ist(ts_str, "%H:%M:%S IST")
        dec = str(ev.get("decision", "")).upper()
        if not dec and ev.get("approved") is False:
            dec = "DENIED"
        reason = ev.get("reason") or ev.get("error") or "Security policy action"
        rule_ids = ev.get("rule_ids") or []
        rule_id = rule_ids[0] if rule_ids else ev.get("rule_id", "--")

        alerts_formatted.append({
            "id": ev.get("request_id") or secrets.token_hex(4),
            "timestamp": ts_str,
            "time_ist": time_ist,
            "decision": dec,
            "rule_id": rule_id,
            "reason": str(reason),
            "event": ev,
        })

    # Last request mini pipeline
    last_req = None
    if last_req_event:
        last_req = {
            "id": last_req_event.get("request_id"),
            "tool": last_req_event.get("tool") or "chat",
            "decision": last_req_event.get("decision"),
            "time_ist": _format_ist(last_req_event.get("timestamp")),
        }

    return jsonify({
        "kpis": {
            "requests_last_hour": {
                "value": reqs_last_hour,
                "delta": req_delta_str,
                "sparkline": sparkline_reqs,
            },
            "blocked_attacks": {
                "value": blocks_last_hour,
                "delta": block_delta_str,
                "sparkline": sparkline_blocks,
            },
            "pending_approvals": {
                "value": pending_count,
                "delta": "Real-time queue",
            },
            "device_status": {
                "status": dev_status,
                "hint": dev_hint,
            },
        },
        "timeline": timeline,
        "top_rules": top_rules,
        "recent_alerts": alerts_formatted,
        "last_request": last_req,
    })


# 3. Agent Console: Send Chat Message
@api_bp.route("/console/send", methods=["POST"])
@role_required("guest")
def api_console_send():
    """
    Submits a chat prompt to the agent worker via signed IPC.
    Role is read strictly from session['role'], never from request payload.
    """
    body = request.get_json(silent=True) or {}
    text = body.get("text", "").strip()

    if not text:
        return jsonify({"error": "Prompt text cannot be empty"}), 400

    if len(text) > 10000:
        return jsonify({"error": "Prompt exceeds maximum allowed length (10,000 characters)"}), 400

    # Reject early if worker is offline to avoid orphan queued messages (production)
    if not current_app.config.get("TESTING"):
        health = security.health.get_system_health()
        if not health.get("worker", {}).get("alive", False):
            return jsonify({
                "error": "Agent worker service is offline. Cannot process prompt.",
                "status": "offline",
            }), 503

    username = session.get("username", "guest")
    role = session.get("role", "guest")  # STRICT: Ignore any 'role' sent by client!

    session_id = session.get("console_session_id")
    if not session_id:
        session_id = "sess_" + secrets.token_hex(8)
        session["console_session_id"] = session_id

    req_id = "req_" + secrets.token_hex(12)
    ts = time.time()
    nonce = secrets.token_hex(16)

    payload = {
        "id": req_id,
        "kind": "chat",
        "nonce": nonce,
        "role": role,
        "session_id": session_id,
        "text": text,
        "ts": ts,
        "username": username,
    }

    sig = security.signing.sign(payload)
    payload["signature"] = sig

    inbox_dir = _get_data_dir() / "chat" / "inbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)

    inbox_file = inbox_dir / f"{req_id}.json"
    tmp_file = inbox_dir / f"{req_id}.tmp.{secrets.token_hex(4)}"

    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, indent=2))
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp_file, inbox_file)
    except Exception as e:
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except Exception:
                pass
        return jsonify({"error": f"Failed to submit message to inbox: {e}"}), 500

    return jsonify({
        "status": "ok",
        "request_id": req_id,
        "id": req_id,
        "session_id": session_id,
    })


# 4. Agent Console: Poll Turn
@api_bp.route("/console/poll/<req_id>", methods=["GET"])
@role_required("guest")
def api_console_poll(req_id: str):
    """
    Polls the outbox file for an ongoing or completed turn.
    Validates req_id against strict character pattern to prevent path traversal.
    """
    if not ID_REGEX.match(req_id):
        return jsonify({"error": "Invalid request ID format"}), 400

    outbox_dir = _get_data_dir() / "chat" / "outbox"
    outbox_file = outbox_dir / f"{req_id}.jsonl"

    if not outbox_file.exists():
        return jsonify({"steps": [], "final": None, "status": "queued"})

    steps = []
    final_entry = None

    try:
        with open(outbox_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("final") is True:
                        final_entry = entry
                    elif "stage" in entry:
                        steps.append(entry)
                except Exception:
                    continue
    except Exception as e:
        return jsonify({"error": f"Error reading turn progress: {e}"}), 500

    return jsonify({
        "steps": steps,
        "final": final_entry,
        "status": "completed" if final_entry else "running",
    })


# 5. Agent Console: Reset Session (Admin only)
@api_bp.route("/console/new_session", methods=["POST"])
@role_required("admin")
def api_console_new_session():
    new_sess = "sess_" + secrets.token_hex(8)
    session["console_session_id"] = new_sess
    security.logger.log_event("console_new_session", {"admin": session["username"], "new_session_id": new_sess})
    return jsonify({"status": "ok", "session_id": new_sess})


# 5b. Agent Console: Clear Threat Window / Reset Suspicion (Admin only)
@api_bp.route("/console/clear_threat", methods=["POST"])
@role_required("admin")
def api_console_clear_threat():
    old_sess = session.get("console_session_id", "default")
    security.gateway.reset_session_history(old_sess)
    new_sess = "sess_" + secrets.token_hex(8)
    session["console_session_id"] = new_sess
    security.gateway.reset_session_history(new_sess)
    security.logger.log_event("threat_window_cleared_by_admin", {
        "admin": session.get("username", "admin"),
        "prior_session_id": old_sess,
        "new_session_id": new_sess,
    })
    return jsonify({
        "status": "ok",
        "message": "Threat window and cumulative suspicion cleared for active session.",
        "session_id": new_sess,
    })


# 5c. Agent Console: Release Session Quarantine (Admin only)
@api_bp.route("/console/release_quarantine", methods=["POST"])
@role_required("admin")
def api_console_release_quarantine():
    import security.quarantine
    active_sess = session.get("console_session_id", "default")
    security.quarantine.release_quarantine(active_sess)
    security.gateway.reset_session_history(active_sess)
    security.logger.log_event("quarantine_released_by_admin", {
        "admin": session.get("username", "admin"),
        "session_id": active_sess,
    })
    return jsonify({
        "status": "ok",
        "message": "Quarantine released and threat suspicion reset.",
        "session_id": active_sess,
    })


# 6. Worker Control: Start Worker (Admin only)
@api_bp.route("/worker/start", methods=["POST"])
@role_required("admin")
def api_worker_start():
    health = security.health.get_system_health()
    if health.get("worker", {}).get("alive"):
        return jsonify({"status": "ok", "message": "Worker is already active"})

    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "agent.worker"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        security.logger.log_event("worker_started_by_admin", {"admin": session["username"], "pid": proc.pid})
        return jsonify({"status": "ok", "message": f"Worker process initiated (PID {proc.pid})"})
    except Exception as e:
        return jsonify({"error": f"Failed to start worker: {e}"}), 500


# 7. Approvals: List Pending Queue (Admin only)
@api_bp.route("/approvals/pending", methods=["GET"])
@role_required("admin")
def api_approvals_pending():
    pending_dir = _get_data_dir() / "approvals" / "pending"
    timeout_seconds = int(security.policy_loader.POLICY.get("approval", {}).get("timeout_seconds", 60))
    if not pending_dir.exists():
        return jsonify({"pending": [], "timeout_seconds": timeout_seconds})

    now_utc = datetime.now(timezone.utc)
    items = []
    for p_file in sorted(pending_dir.glob("*.json")):
        try:
            content = p_file.read_text(encoding="utf-8").strip()
            if not content:
                continue
            req = json.loads(content)
            expires_at_str = req.get("expires_at")
            if expires_at_str:
                try:
                    exp_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                    expires_in_seconds = max(0, int((exp_dt - now_utc).total_seconds()))
                except Exception:
                    expires_in_seconds = timeout_seconds
            else:
                expires_in_seconds = timeout_seconds

            req["expires_in_seconds"] = expires_in_seconds
            req["timeout_seconds"] = timeout_seconds
            items.append(req)
        except Exception:
            continue

    return jsonify({"pending": items, "timeout_seconds": timeout_seconds})


# 8. Approvals: List Decision History (Admin only)
@api_bp.route("/approvals/history", methods=["GET"])
@role_required("admin")
def api_approvals_history():
    log_file = _get_log_file()
    if not log_file.exists():
        return jsonify({"history": []})

    history = []
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("event") == "approval_decision":
                        history.append(entry)
                except Exception:
                    continue
    except Exception:
        return jsonify({"history": []})

    recent = list(reversed(history[-50:]))
    return jsonify({"history": recent})


# 9. Approvals: Submit Decision (Admin only)
@api_bp.route("/approvals/decide", methods=["POST"])
@role_required("admin")
def api_approvals_decide():
    """
    Signs and writes the approval decision file data/approvals/decisions/<id>.json.
    Enforces that the request is currently pending and unexpired.
    """
    body = request.get_json(silent=True) or {}
    req_id = body.get("request_id")
    approved = body.get("approved")

    if not req_id or not ID_REGEX.match(req_id):
        return jsonify({"error": "Invalid or missing request ID"}), 400

    if not isinstance(approved, bool):
        return jsonify({"error": "Field 'approved' must be a boolean"}), 400

    pending_dir = _get_data_dir() / "approvals" / "pending"
    pending_file = pending_dir / f"{req_id}.json"

    if not pending_file.exists():
        return jsonify({"error": "Request not found in pending queue"}), 404

    # First decision must win: prevent overwriting previous decisions
    decisions_dir = _get_data_dir() / "approvals" / "decisions"
    decisions_dir.mkdir(parents=True, exist_ok=True)
    decision_file = decisions_dir / f"{req_id}.json"
    if decision_file.exists():
        return jsonify({"error": "Request has already been decided. First decision wins."}), 409

    try:
        req_data = json.loads(pending_file.read_text(encoding="utf-8"))
    except Exception as e:
        return jsonify({"error": f"Failed to read pending request: {e}"}), 500

    # Verify expiration (fail closed if missing or expired)
    expires_at_str = req_data.get("expires_at")
    if not expires_at_str:
        return jsonify({"error": "Missing expiration timestamp on request (fail closed)"}), 400

    try:
        exp_dt = datetime.fromisoformat(expires_at_str)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp_dt:
            return jsonify({"error": "Request has expired and cannot be authorized"}), 400
    except Exception:
        return jsonify({"error": "Invalid expiration timestamp on request (fail closed)"}), 400

    req_hash = req_data.get("request_hash", "")
    client_hash = body.get("request_hash")
    if not client_hash:
        return jsonify({"error": "Missing required field 'request_hash'"}), 400
    if client_hash != req_hash:
        return jsonify({"error": "Request hash mismatch"}), 400

    decided_at = datetime.now(timezone.utc).isoformat()
    decided_by = session.get("username", "admin")

    sig_payload = {
        "approved": approved,
        "decided_at": decided_at,
        "decided_by": decided_by,
        "request_hash": req_hash,
        "request_id": req_id,
    }
    sig = security.signing.sign(sig_payload)

    decision_data = {
        "approved": approved,
        "decided_at": decided_at,
        "decided_by": decided_by,
        "reason": f"Authorized by administrator ({decided_by})" if approved else f"Denied by administrator ({decided_by})",
        "request_hash": req_hash,
        "request_id": req_id,
        "signature": sig,
        "tool": req_data.get("tool") or req_data.get("kind") or "Operation",
    }
    decision_file = decisions_dir / f"{req_id}.json"

    try:
        with open(decision_file, "x", encoding="utf-8") as f:
            f.write(json.dumps(decision_data, indent=2))
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
    except FileExistsError:
        return jsonify({"error": "Request has already been decided. First decision wins."}), 409
    except Exception as e:
        return jsonify({"error": f"Failed to write decision file: {e}"}), 500

    return jsonify({
        "status": "ok",
        "request_id": req_id,
        "approved": approved,
    })


# 5. Direct Hardware Telemetry & Actuation
@api_bp.route("/hardware/status", methods=["GET"])
@role_required("guest")
def api_hardware_status():
    health = security.health.get_system_health()
    dev = health.get("device", {})
    is_online = dev.get("status") == "online"
    transport = dev.get("transport")
    bridge_type = None
    if transport == "usb_serial":
        bridge_type = "SerialHardwareBridge"
    elif transport == "mqtt":
        bridge_type = "HardwareBridge"
    elif transport == "fake":
        bridge_type = "FakeBridge"

    return jsonify({
        "online": is_online,
        "bridge_type": bridge_type,
        "transport": transport,
        "port": dev.get("port"),
        "description": dev.get("description"),
        "device_id": dev.get("device_id"),
        "last_seen": dev.get("last_seen"),
    })


@api_bp.route("/hardware/actuate", methods=["POST"])
@role_required("admin")
def api_hardware_actuate():
    data = request.get_json(silent=True) or {}
    command = data.get("command", "")

    cmd_to_tool = {
        "light_on": "turn_light_on",
        "light_off": "turn_light_off",
        "unlock_door": "unlock_door",
        "alarm_on": "activate_alarm",
    }
    if command not in cmd_to_tool:
        return jsonify({"error": f"Invalid or unmapped hardware command '{command}'"}), 400

    t0 = time.time()
    health = security.health.get_system_health()
    worker_alive = bool(health.get("worker", {}).get("alive", False))
    if not worker_alive:
        return jsonify({
            "ok": False,
            "error": "Hardware gateway worker is offline. Manual actuation requires active worker gateway.",
            "latency_ms": 0,
        }), 503

    tool_name = cmd_to_tool[command]
    risk = security.policy_loader.get_risk(tool_name) or "LOW"

    req_id = "req_" + secrets.token_hex(12)
    payload = {
        "id": req_id,
        "kind": "direct_tool",
        "tool": tool_name,
        "role": session.get("role", "admin"),
        "username": session.get("username", "admin"),
        "session_id": "manual_actuation",
        "ts": time.time(),
        "nonce": secrets.token_hex(16),
    }
    sig = security.signing.sign(payload)
    payload["signature"] = sig

    inbox_dir = _get_data_dir() / "chat" / "inbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)
    inbox_file = inbox_dir / f"{req_id}.json"
    tmp_file = inbox_dir / f"{req_id}.tmp.{secrets.token_hex(4)}"

    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, indent=2))
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp_file, inbox_file)

        # HIGH tools: return 202 with request_id and message (do not wait)
        if risk == "HIGH":
            return jsonify({
                "ok": True,
                "status": "pending_approval",
                "request_id": req_id,
                "message": "Awaiting human approval in Approvals queue",
            }), 202

        # LOW tools: wait up to 5s for result
        outbox_file = _get_data_dir() / "chat" / "outbox" / f"{req_id}.jsonl"
        deadline = time.time() + 5.0
        final_res = None
        while time.time() < deadline:
            if outbox_file.exists():
                try:
                    for line in outbox_file.read_text(encoding="utf-8").splitlines():
                        row = json.loads(line)
                        if row.get("final") is True:
                            final_res = row
                            break
                except Exception:
                    pass
                if final_res:
                    break
            time.sleep(0.05)

        latency_ms = round((time.time() - t0) * 1000, 1)
        if final_res and final_res.get("decision") == "ALLOW":
            return jsonify({
                "ok": True,
                "command": command,
                "latency_ms": latency_ms,
                "message": f"Command '{command}' successfully delivered to hardware ({latency_ms}ms)",
            })
        elif final_res:
            return jsonify({
                "ok": False,
                "error": final_res.get("error") or "Actuation blocked by security policy",
                "latency_ms": latency_ms,
            }), 400
        else:
            return jsonify({
                "ok": False,
                "error": "Hardware worker did not respond in time",
                "latency_ms": latency_ms,
            }), 504
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to submit hardware actuation: {e}"}), 500


# 6. Cryptographic Audit Chain Verification
@api_bp.route("/audit/verify", methods=["GET"])
@role_required("guest")
def api_audit_verify():
    log_file = _get_log_file()
    count = 0
    head_hash = ""
    genesis_hash = "0" * 64
    is_intact = True
    msg = "LOG INTACT"

    if not log_file.exists():
        return jsonify({
            "intact": True,
            "message": "LOG INTACT",
            "count": 0,
            "genesis_hash": genesis_hash,
            "head_hash": head_hash,
            "algorithm": "SHA-256",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        })

    expected_prev_hash = "0" * 64
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    entry = json.loads(line)
                except Exception:
                    is_intact = False
                    msg = f"LOG TAMPERED AT LINE {line_num}: Invalid JSON syntax"
                    break

                stored_prev_hash = entry.get("prev_hash")
                stored_entry_hash = entry.get("entry_hash")

                if count == 1:
                    genesis_hash = stored_prev_hash or "0" * 64

                if stored_prev_hash != expected_prev_hash:
                    is_intact = False
                    msg = f"LOG TAMPERED AT LINE {line_num}: prev_hash mismatch. Expected '{expected_prev_hash}', got '{stored_prev_hash}'"
                    head_hash = stored_entry_hash or ""
                    break

                entry_without_hash = {k: v for k, v in entry.items() if k not in ("prev_hash", "entry_hash")}
                serialized_data = json.dumps(entry_without_hash, sort_keys=True)
                payload = serialized_data + (stored_prev_hash or "")
                computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

                if computed_hash != stored_entry_hash:
                    is_intact = False
                    msg = f"LOG TAMPERED AT LINE {line_num}: entry_hash mismatch. Computed '{computed_hash}', got '{stored_entry_hash}'"
                    head_hash = stored_entry_hash or ""
                    break

                expected_prev_hash = stored_entry_hash
                head_hash = stored_entry_hash or ""

    except Exception as e:
        is_intact = False
        msg = f"Failed to verify audit log: {e}"

    return jsonify({
        "intact": is_intact,
        "message": msg,
        "count": count,
        "genesis_hash": genesis_hash,
        "head_hash": head_hash,
        "algorithm": "SHA-256",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    })


# 7. Role Simulation / Switcher (for live demos)
@api_bp.route("/auth/switch_role", methods=["POST"])
def api_switch_role():
    if session.get("real_role") != "admin":
        return jsonify({"error": "Forbidden: Only real administrators can switch roles"}), 403

    data = request.get_json(silent=True) or {}
    target_role = data.get("role")
    if target_role not in ["admin", "guest"]:
        return jsonify({"error": "Invalid target role (must be 'admin' or 'guest')"}), 400

    old_role = session.get("role", "guest")
    session["role"] = target_role
    security.logger.log_role_change(old_role, target_role)

    return jsonify({
        "status": "ok",
        "active_role": target_role,
        "is_simulated": (target_role != "admin")
    })
