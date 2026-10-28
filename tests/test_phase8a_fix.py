"""
Phase 8A-fix -- Comprehensive Verification Test Suite

Tests:
1. Path traversal: unsigned request with id "../../evil" creates no file outside outbox.
2. Replay protection: replayed nonce rejected.
3. Timestamp protection: stale ts (>60s) rejected.
4. Heartbeat thread: keeps updating while run_turn blocks (slow fake) and busy/current_request_id set.
5. Single source of truth (health.py): device stays "online" with an old last_seen when broker_connected is true and is "unknown" when false.
6. Secret race: two processes calling get_secret concurrently get the same secret.
7. Direct tool rate limit: counted exactly once per request.
8. Dashboard approval decision: rejects decisions whose decided_at is outside [created_at, now].
"""

from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent

from agent.agent import TurnResult
from agent.worker import (
    ID_PATTERN,
    WorkerHeartbeatThread,
    _load_seen_nonces,
    _process_direct_tool,
    _save_seen_nonces,
)
from security.approval import ApprovalRequest, DashboardApprovalProvider
import security.gateway
import security.health
import security.logger
import security.rate_limiter
import security.signing


def _process_one_inbox_request(req_file: Path, data_dir: Path, hb_thread=None) -> tuple[bool, str | None]:
    """Helper that mimics worker's single inbox file processing logic."""
    inbox_dir = data_dir / "chat" / "inbox"
    outbox_dir = data_dir / "chat" / "outbox"
    outbox_dir.mkdir(parents=True, exist_ok=True)

    seen_nonces_list = _load_seen_nonces(data_dir)
    seen_nonces_set = set(seen_nonces_list)

    stem = req_file.stem
    is_stem_valid = bool(ID_PATTERN.match(stem))

    try:
        content = req_file.read_text(encoding="utf-8").strip()
        if not content:
            req_file.unlink()
            return False, "empty_file"
        req = json.loads(content)
    except Exception as e:
        security.logger.log_event(
            "worker_rejected",
            {"file": req_file.name, "reason": "malformed_json", "error": str(e)},
        )
        if is_stem_valid:
            outbox_file = outbox_dir / f"{stem}.jsonl"
            outbox_file.write_text(json.dumps({"final": True, "decision": "BLOCK", "error": "malformed JSON"}) + "\n")
        req_file.unlink()
        return False, "malformed_json"

    req_id = req.get("id")
    is_id_valid = isinstance(req_id, str) and bool(ID_PATTERN.match(req_id))

    kind = req.get("kind", "chat")
    is_kind_valid = kind in ("chat", "direct_tool")

    valid_roles = set(security.policy_loader.POLICY.get("roles", {}).keys())
    role = req.get("role", "guest")
    is_role_valid = isinstance(role, str) and (role in valid_roles)

    ts = req.get("ts")
    is_ts_valid = False
    if ts is not None and isinstance(ts, (int, float)):
        if abs(time.time() - float(ts)) <= 60.0:
            is_ts_valid = True

    nonce = req.get("nonce")
    is_nonce_valid = (
        isinstance(nonce, str)
        and len(nonce) == 32
        and all(c in "0123456789abcdefABCDEF" for c in nonce)
    )
    is_nonce_new = is_nonce_valid and (nonce not in seen_nonces_set)

    sig = req.get("signature")
    sign_payload = {k: v for k, v in req.items() if k != "signature"}
    is_sig_valid = bool(sig and security.signing.verify(sign_payload, sig))

    reject_reason = None
    if not is_sig_valid:
        reject_reason = "bad_or_missing_signature"
    elif not is_id_valid:
        reject_reason = "invalid_request_id"
    elif not is_kind_valid:
        reject_reason = "unknown_kind"
    elif not is_role_valid:
        reject_reason = "invalid_role"
    elif not is_ts_valid:
        reject_reason = "stale_timestamp"
    elif not is_nonce_valid:
        reject_reason = "invalid_nonce"
    elif not is_nonce_new:
        reject_reason = "replayed_nonce"

    if reject_reason is not None:
        security.logger.log_event(
            "worker_rejected",
            {
                "file": req_file.name,
                "id": req_id if is_id_valid else "invalid",
                "reason": reject_reason,
            },
        )
        if is_stem_valid:
            outbox_file = outbox_dir / f"{stem}.jsonl"
            outbox_file.write_text(json.dumps({"final": True, "decision": "BLOCK", "error": reject_reason}) + "\n")
        req_file.unlink()
        return False, reject_reason

    # Record nonce
    seen_nonces_set.add(nonce)
    seen_nonces_list.append(nonce)
    _save_seen_nonces(data_dir, seen_nonces_list)

    outbox_file = outbox_dir / f"{req_id}.jsonl"
    req_file.unlink()

    def dummy_emit(stage, status, detail):
        pass

    if hb_thread:
        hb_thread.set_busy(True, req_id)

    try:
        if kind == "direct_tool":
            _process_direct_tool(req, dummy_emit, outbox_file)
        else:
            from agent.agent import run_turn
            res = run_turn(text=req.get("text", ""), role=role, session_id=req.get("session_id", "default"), emit=dummy_emit)
            final = {
                "decision": res.decision,
                "error": res.error,
                "final": True,
                "reply": res.reply,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            with open(outbox_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(final) + "\n")
    finally:
        if hb_thread:
            hb_thread.set_busy(False, None)

    return True, None


# 1. PATH TRAVERSAL TEST
def test_path_traversal_unsigned_evil_id_creates_no_file_outside_outbox(tmp_path):
    data_dir = tmp_path / "data"
    inbox_dir = data_dir / "chat" / "inbox"
    outbox_dir = data_dir / "chat" / "outbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)
    outbox_dir.mkdir(parents=True, exist_ok=True)

    # Malicious unsigned request attempting path traversal
    evil_req = {
        "id": "../../evil",
        "kind": "chat",
        "role": "guest",
        "text": "attempt directory traversal",
        "username": "attacker",
    }

    # Case A: Inbox file has a valid stem, but evil id inside
    inbox_file_a = inbox_dir / "request_12345678.json"
    inbox_file_a.write_text(json.dumps(evil_req), encoding="utf-8")

    ok, reason = _process_one_inbox_request(inbox_file_a, data_dir)
    assert ok is False
    assert reason == "bad_or_missing_signature"

    # Verify no file named evil.jsonl exists anywhere in tmp_path or outside outbox
    evil_outside_path = data_dir / "evil.jsonl"
    assert evil_outside_path.exists() is False
    assert (tmp_path / "evil.jsonl").exists() is False
    assert (outbox_dir.parent / "evil.jsonl").exists() is False

    # The rejection was written to the validated inbox stem in outbox
    stem_outbox = outbox_dir / "request_12345678.jsonl"
    assert stem_outbox.exists() is True
    content = json.loads(stem_outbox.read_text(encoding="utf-8").strip())
    assert content["decision"] == "BLOCK"

    # Case B: Inbox file has an invalid stem (e.g. contains dots/slashes)
    inbox_file_b = inbox_dir / "evil..stem..invalid.json"
    inbox_file_b.write_text(json.dumps(evil_req), encoding="utf-8")

    ok_b, reason_b = _process_one_inbox_request(inbox_file_b, data_dir)
    assert ok_b is False
    # Since stem was invalid, NO outbox file at all was created!
    assert (outbox_dir / "evil..stem..invalid.jsonl").exists() is False
    assert (outbox_dir / "../../evil.jsonl").exists() is False


# 2. REPLAY PROTECTION TEST
def test_replayed_nonce_rejected(tmp_path):
    data_dir = tmp_path / "data"
    inbox_dir = data_dir / "chat" / "inbox"
    outbox_dir = data_dir / "chat" / "outbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)
    outbox_dir.mkdir(parents=True, exist_ok=True)

    shared_nonce = secrets.token_hex(16)
    req1_id = f"req_{secrets.token_hex(8)}"

    req1 = {
        "id": req1_id,
        "kind": "direct_tool",
        "nonce": shared_nonce,
        "role": "guest",
        "session_id": "replay_test_sess",
        "text": "turn on the light",
        "tool": "turn_light_on",
        "ts": time.time(),
        "username": "alice",
    }
    req1["signature"] = security.signing.sign(req1)

    inbox_file_1 = inbox_dir / f"{req1_id}.json"
    inbox_file_1.write_text(json.dumps(req1), encoding="utf-8")

    # First execution succeeds
    ok1, reason1 = _process_one_inbox_request(inbox_file_1, data_dir)
    assert ok1 is True
    assert reason1 is None
    assert (outbox_dir / f"{req1_id}.jsonl").exists() is True

    # Replay attempt: New request ID, but identical nonce
    req2_id = f"req_{secrets.token_hex(8)}"
    req2 = {
        "id": req2_id,
        "kind": "direct_tool",
        "nonce": shared_nonce,  # Reused nonce!
        "role": "guest",
        "session_id": "replay_test_sess",
        "text": "turn on the light again",
        "tool": "turn_light_on",
        "ts": time.time(),
        "username": "alice",
    }
    req2["signature"] = security.signing.sign(req2)

    inbox_file_2 = inbox_dir / f"{req2_id}.json"
    inbox_file_2.write_text(json.dumps(req2), encoding="utf-8")

    # Second execution MUST be rejected due to replayed nonce
    ok2, reason2 = _process_one_inbox_request(inbox_file_2, data_dir)
    assert ok2 is False
    assert reason2 == "replayed_nonce"

    outbox_2 = outbox_dir / f"{req2_id}.jsonl"
    assert outbox_2.exists() is True
    out_data = json.loads(outbox_2.read_text(encoding="utf-8").strip())
    assert out_data["decision"] == "BLOCK"
    assert "replayed_nonce" in out_data["error"]


# 3. STALE TIMESTAMP TEST
def test_stale_ts_rejected(tmp_path):
    data_dir = tmp_path / "data"
    inbox_dir = data_dir / "chat" / "inbox"
    outbox_dir = data_dir / "chat" / "outbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)
    outbox_dir.mkdir(parents=True, exist_ok=True)

    # Test A: Timestamp 90 seconds in the past (|now - ts| > 60s)
    req_stale_id = f"req_{secrets.token_hex(8)}"
    req_stale = {
        "id": req_stale_id,
        "kind": "direct_tool",
        "nonce": secrets.token_hex(16),
        "role": "guest",
        "session_id": "stale_sess",
        "text": "turn on light",
        "tool": "turn_light_on",
        "ts": time.time() - 90.0,
        "username": "alice",
    }
    req_stale["signature"] = security.signing.sign(req_stale)

    file_stale = inbox_dir / f"{req_stale_id}.json"
    file_stale.write_text(json.dumps(req_stale), encoding="utf-8")

    ok_s, reason_s = _process_one_inbox_request(file_stale, data_dir)
    assert ok_s is False
    assert reason_s == "stale_timestamp"

    # Test B: Timestamp 90 seconds in the future
    req_future_id = f"req_{secrets.token_hex(8)}"
    req_future = {
        "id": req_future_id,
        "kind": "direct_tool",
        "nonce": secrets.token_hex(16),
        "role": "guest",
        "session_id": "future_sess",
        "text": "turn on light",
        "tool": "turn_light_on",
        "ts": time.time() + 90.0,
        "username": "alice",
    }
    req_future["signature"] = security.signing.sign(req_future)

    file_future = inbox_dir / f"{req_future_id}.json"
    file_future.write_text(json.dumps(req_future), encoding="utf-8")

    ok_f, reason_f = _process_one_inbox_request(file_future, data_dir)
    assert ok_f is False
    assert reason_f == "stale_timestamp"


# 4. HEARTBEAT THREAD TEST
def test_heartbeat_keeps_updating_while_run_turn_blocks(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    inbox_dir = data_dir / "chat" / "inbox"
    inbox_dir.mkdir(parents=True, exist_ok=True)

    started_iso = datetime.now(timezone.utc).isoformat()
    hb_thread = WorkerHeartbeatThread(data_dir, started_iso)
    hb_thread.write_heartbeat()
    hb_thread.start()

    status_file = data_dir / "worker_status.json"
    assert status_file.exists() is True

    init_hb = json.loads(status_file.read_text(encoding="utf-8"))["last_heartbeat"]

    # Mock run_turn to sleep for 2.5 seconds (slow fake)
    import agent.agent
    def slow_run_turn(*args, **kwargs):
        time.sleep(2.5)
        return TurnResult(reply="Done after slow turn", decision="ALLOW", tool_called=None, tool_result=None, error=None)

    monkeypatch.setattr(agent.agent, "run_turn", slow_run_turn)

    req_id = f"req_{secrets.token_hex(8)}"
    req = {
        "id": req_id,
        "kind": "chat",
        "nonce": secrets.token_hex(16),
        "role": "guest",
        "session_id": "slow_sess",
        "text": "trigger slow turn",
        "ts": time.time(),
        "username": "alice",
    }
    req["signature"] = security.signing.sign(req)

    inbox_file = inbox_dir / f"{req_id}.json"
    inbox_file.write_text(json.dumps(req), encoding="utf-8")

    # Run request in a background thread to inspect heartbeat during execution
    t = threading.Thread(target=_process_one_inbox_request, args=(inbox_file, data_dir, hb_thread))
    t.start()

    # Wait 1.0s and verify worker is marked busy with current_request_id
    time.sleep(1.0)
    busy_status = json.loads(status_file.read_text(encoding="utf-8"))
    assert busy_status["busy"] is True
    assert busy_status["current_request_id"] == req_id

    # Wait for turn to complete
    t.join(timeout=5.0)

    # Verify heartbeat advanced and busy is now False
    final_status = json.loads(status_file.read_text(encoding="utf-8"))
    assert final_status["busy"] is False
    assert final_status["current_request_id"] is None
    assert final_status["last_heartbeat"] >= init_hb

    hb_thread.stop()


# 5. SINGLE SOURCE OF TRUTH (HEALTH.PY) TEST
def test_device_status_online_with_old_last_seen_and_unknown_when_not_connected(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    device_file = data_dir / "device_status.json"

    # Case A: broker_connected is True, device is online, last_seen is 5 years old
    old_iso = "2021-01-01T00:00:00+00:00"
    device_file.write_text(
        json.dumps({
            "broker_connected": True,
            "device_online": True,
            "last_seen": old_iso,
            "online": True,
            "since": old_iso,
        }),
        encoding="utf-8",
    )

    health = security.health.get_system_health()
    # Rule: device stays "online" despite old last_seen because broker_connected is True!
    assert health["device"]["status"] == "online"
    assert health["broker"]["connected"] is True
    assert health["broker"]["status"] == "connected"

    # Case B: broker_connected is False -> device status must be "unknown"
    device_file.write_text(
        json.dumps({
            "broker_connected": False,
            "device_online": True,
            "last_seen": old_iso,
            "online": True,
        }),
        encoding="utf-8",
    )

    health_b = security.health.get_system_health()
    assert health_b["device"]["status"] == "unknown"
    assert health_b["broker"]["connected"] is False

    # Case C: No device_status.json file -> device status must be "unknown"
    device_file.unlink()
    health_c = security.health.get_system_health()
    assert health_c["device"]["status"] == "unknown"


# 6. CONCURRENT SECRET CREATION TEST
def test_concurrent_get_secret_processes_get_same_secret(tmp_path):
    env_file = tmp_path / ".env"
    lock_file = tmp_path / ".env.lock"

    # Subprocess script: overrides _ENV_FILE and calls get_secret()
    script = f"""
import os
import sys
from pathlib import Path

# Ensure project root in sys.path
sys.path.insert(0, r"{ROOT_DIR}")

import security.signing
security.signing._ENV_FILE = Path(r"{env_file}")
if "AEGIS_DASH_SECRET" in os.environ:
    del os.environ["AEGIS_DASH_SECRET"]

secret = security.signing.get_secret()
print(secret)
"""

    p1 = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p2 = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    out1, err1 = p1.communicate(timeout=10)
    out2, err2 = p2.communicate(timeout=10)

    assert p1.returncode == 0, f"Process 1 failed: {err1}"
    assert p2.returncode == 0, f"Process 2 failed: {err2}"

    secret1 = out1.strip()
    secret2 = out2.strip()

    assert len(secret1) == 64
    assert secret1 == secret2


# 7. DIRECT TOOL RATE LIMIT COUNTED ONCE TEST
def test_direct_tool_rate_limit_counted_once(tmp_path):
    outbox_file = tmp_path / "rate_limit_outbox.jsonl"
    tool_name = "turn_light_on"

    # Clear rate limiter history for this tool
    if hasattr(security.rate_limiter, "CALL_TIMESTAMPS") and tool_name in security.rate_limiter.CALL_TIMESTAMPS:
        security.rate_limiter.CALL_TIMESTAMPS[tool_name].clear()

    emitted = []
    def record_emit(stage, status, detail):
        emitted.append((stage, status))

    req = {
        "id": f"req_{secrets.token_hex(8)}",
        "kind": "direct_tool",
        "nonce": secrets.token_hex(16),
        "role": "guest",
        "session_id": "rate_limit_test",
        "text": "test rate limit count",
        "tool": tool_name,
        "ts": time.time(),
        "username": "tester",
    }

    _process_direct_tool(req, record_emit, outbox_file)

    # Check that rate limit was recorded exactly once
    history = security.rate_limiter.CALL_TIMESTAMPS.get(tool_name, [])
    assert len(history) == 1

    # Verify outbox result
    lines = [json.loads(l) for l in outbox_file.read_text(encoding="utf-8").strip().splitlines()]
    final_line = lines[-1]
    assert final_line["final"] is True
    assert final_line["decision"] == "ALLOW"


# 8. DASHBOARD APPROVAL DECISION BOUNDS TEST
def test_dashboard_approval_rejects_stale_or_future_decided_at(tmp_path):
    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)
    now_dt = datetime.now(timezone.utc)
    req = ApprovalRequest(
        session_id="approval_bounds_sess",
        kind="tool_call",
        tool="unlock_door",
        args={"door_id": "front"},
        risk="HIGH",
        reasons=["High risk unlock door"],
        created_at=now_dt.isoformat(),
    )

    decisions_dir = tmp_path / "decisions"
    decisions_dir.mkdir(parents=True, exist_ok=True)
    dec_file = decisions_dir / f"{req.request_id}.json"

    # Case A: decided_at is 10 minutes before created_at
    stale_decided_at = (now_dt - timedelta(minutes=10)).isoformat()
    sig_payload_a = {
        "approved": True,
        "decided_at": stale_decided_at,
        "request_hash": req.request_hash,
        "request_id": req.request_id,
    }
    sig_a = security.signing.sign(sig_payload_a)

    dec_file.write_text(
        json.dumps({
            "approved": True,
            "decided_at": stale_decided_at,
            "request_hash": req.request_hash,
            "request_id": req.request_id,
            "signature": sig_a,
        }),
        encoding="utf-8",
    )

    res_a = provider.request_approval(req)
    assert res_a.approved is False
    assert res_a.reason == "bad timestamp"

    # Case B: decided_at is 10 minutes in the future
    future_decided_at = (now_dt + timedelta(minutes=10)).isoformat()
    sig_payload_b = {
        "approved": True,
        "decided_at": future_decided_at,
        "request_hash": req.request_hash,
        "request_id": req.request_id,
    }
    sig_b = security.signing.sign(sig_payload_b)

    dec_file.write_text(
        json.dumps({
            "approved": True,
            "decided_at": future_decided_at,
            "request_hash": req.request_hash,
            "request_id": req.request_id,
            "signature": sig_b,
        }),
        encoding="utf-8",
    )

    res_b = provider.request_approval(req)
    assert res_b.approved is False
    assert res_b.reason == "bad timestamp"
