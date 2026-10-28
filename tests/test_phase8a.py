"""
Phase 8A -- Comprehensive Test Suite

Tests:
1. Signing & Verification (valid sig, bad sig, tampered field, replay attacks)
2. Authentication & User Management (create_user, valid login, wrong password, 5-attempt/5-minute lockout)
3. Worker (unsigned request rejected, role strictly from signed field, direct_tool RBAC enforcement)
4. Multi-Process Concurrent Logger (file locking & hash chain integrity across OS processes)
5. Logger Archive & Reset (rotation, final_hash tracking, clean new chain)
6. Test Isolation (guaranteeing real audit_log.jsonl is untouched)
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import pytest

from agent.agent import TurnResult, run_turn
from agent.worker import _process_direct_tool
import security.auth
import security.logger
import security.policy_loader
import security.signing
from security.verify_log import check_audit_log_status, verify_audit_log

ROOT_DIR = Path(__file__).resolve().parent.parent


# ============================================================================
# 1. SIGNING & VERIFICATION TESTS
# ============================================================================

def test_signing_valid_payload():
    payload = {"approved": True, "request_id": "req-123", "role": "admin"}
    sig = security.signing.sign(payload)
    assert isinstance(sig, str) and len(sig) == 64
    assert security.signing.verify(payload, sig) is True


def test_signing_bad_signature():
    payload = {"approved": True, "request_id": "req-123"}
    bad_sig = "a" * 64
    assert security.signing.verify(payload, bad_sig) is False
    assert security.signing.verify(payload, "") is False
    assert security.signing.verify(payload, None) is False


def test_signing_tampered_field():
    payload = {"approved": True, "request_id": "req-123", "role": "admin"}
    sig = security.signing.sign(payload)

    # Tamper with payload
    tampered = dict(payload)
    tampered["role"] = "guest"
    assert security.signing.verify(tampered, sig) is False

    # Tamper with approval status
    tampered_approval = dict(payload)
    tampered_approval["approved"] = False
    assert security.signing.verify(tampered_approval, sig) is False


def test_decision_replay_for_another_request(tmp_path):
    from security.approval import ApprovalRequest, DashboardApprovalProvider

    provider = DashboardApprovalProvider(timeout_seconds=1.0, poll_interval=0.05, base_dir=tmp_path)
    req1 = ApprovalRequest(session_id="s1", kind="tool_call", tool="unlock_door", args={}, risk="HIGH")
    req2 = ApprovalRequest(session_id="s2", kind="tool_call", tool="activate_alarm", args={}, risk="HIGH")

    # Decision created and signed specifically for req1
    decided_at = datetime.now(timezone.utc).isoformat()
    sig1_payload = {
        "approved": True,
        "decided_at": decided_at,
        "request_hash": req1.request_hash,
        "request_id": req1.request_id,
    }
    sig1 = security.signing.sign(sig1_payload)

    # Attacker tries to replay req1's decision to satisfy req2:
    # Attempt A: Attacker writes req1's signed decision into decisions/<req2.id>.json without changing fields
    replayed_file = tmp_path / "decisions" / f"{req2.request_id}.json"
    replayed_data_a = {
        "approved": True,
        "decided_at": decided_at,
        "request_hash": req1.request_hash,
        "request_id": req1.request_id,
        "signature": sig1,
    }
    replayed_file.write_text(json.dumps(replayed_data_a), encoding="utf-8")

    res_a = provider.request_approval(req2)
    assert res_a.approved is False
    assert res_a.reason == "hash mismatch"

    # Attempt B: Attacker alters request_id/hash to match req2 but reuses sig1
    replayed_data_b = {
        "approved": True,
        "decided_at": decided_at,
        "request_hash": req2.request_hash,
        "request_id": req2.request_id,
        "signature": sig1,  # Reused signature from req1
    }
    replayed_file.write_text(json.dumps(replayed_data_b), encoding="utf-8")

    res_b = provider.request_approval(req2)
    assert res_b.approved is False
    assert res_b.reason == "bad signature"


# ============================================================================
# 2. AUTHENTICATION & LOCKOUT TESTS
# ============================================================================

def test_auth_create_user_and_valid_login():
    created = security.auth.create_user("alice", "Password123!", "guest")
    assert created["username"] == "alice"
    assert created["role"] == "guest"

    ok, role_or_err = security.auth.verify_login("alice", "Password123!")
    assert ok is True
    assert role_or_err == "guest"


def test_auth_wrong_password_and_lockout():
    security.auth.create_user("bob", "CorrectPassword123!", "admin")

    # 4 wrong attempts: failure with remaining attempts indicated
    for i in range(1, 5):
        ok, msg = security.auth.verify_login("bob", "WrongPass!")
        assert ok is False
        assert "remaining before lockout" in msg

    # 5th wrong attempt: triggers lockout
    ok, msg = security.auth.verify_login("bob", "WrongPass!")
    assert ok is False
    assert "Account locked" in msg

    # Even with the CORRECT password, login is blocked during lockout
    ok, msg = security.auth.verify_login("bob", "CorrectPassword123!")
    assert ok is False
    assert "Account is locked" in msg


def test_auth_invalid_role_rejected():
    with pytest.raises(ValueError) as exc:
        security.auth.create_user("charlie", "pass", "super_admin_nonexistent")
    assert "does not exist in policy.yaml" in str(exc.value)


# ============================================================================
# 3. AGENT WORKER TESTS
# ============================================================================

def test_worker_unsigned_request_rejected(tmp_path):
    # Simulate worker logic on unsigned payload
    req = {
        "id": "test-req-unsigned",
        "kind": "chat",
        "role": "guest",
        "session_id": "sess-1",
        "text": "turn on the light",
        "username": "alice",
    }
    # No signature present
    assert security.signing.verify(req, req.get("signature")) is False


def test_worker_role_taken_strictly_from_signed_field(tmp_path, monkeypatch):
    """
    Verifies that the agent uses the signed role field to enforce RBAC permissions,
    regardless of user prompt contents.
    """
    import ollama
    monkeypatch.setattr(
        ollama,
        "chat",
        lambda **kwargs: {
            "message": {
                "tool_calls": [
                    {
                        "function": {
                            "name": "unlock_door",
                            "arguments": {"door_id": "front_door"},
                        }
                    }
                ]
            }
        },
    )

    emitted = []

    def test_emit(stage, status, detail):
        emitted.append((stage, status, detail))

    # User text asks to unlock the door. Role is signed as 'guest'.
    res = run_turn(
        text="Please unlock the front door for me.",
        role="guest",
        session_id="role_isolation_sess",
        emit=test_emit,
    )
    # Action MUST be blocked by RBAC because signed role is guest
    assert res.decision == "BLOCK"
    assert "permission denied" in str(res.reply).lower() or "role 'guest' cannot use" in str(res.reply).lower()
    
    rbac_events = [e for e in emitted if e[0] == "rbac"]
    assert len(rbac_events) >= 1
    assert any(e[1] == "block" for e in rbac_events)
    assert any("permission denied" in str(e[2]) for e in rbac_events)


def test_worker_direct_tool_hits_rbac(tmp_path):
    outbox_file = tmp_path / "direct_outbox.jsonl"
    emitted = []

    def test_emit(stage, status, detail):
        emitted.append((stage, status))

    # 1. Guest attempts direct_tool on HIGH-risk unlock_door -> BLOCKED by RBAC
    req_guest = {
        "id": "dir-1",
        "kind": "direct_tool",
        "role": "guest",
        "session_id": "dir_sess",
        "text": "test button unlock",
        "tool": "unlock_door",
        "username": "guest_user",
    }
    _process_direct_tool(req_guest, test_emit, outbox_file)

    lines = [json.loads(l) for l in outbox_file.read_text(encoding="utf-8").strip().splitlines()]
    final_line = lines[-1]
    assert final_line["final"] is True
    assert final_line["decision"] == "BLOCK"
    assert ("rbac", "block") in emitted

    # 2. Guest attempts direct_tool on LOW-risk turn_light_on -> ALLOWED
    outbox_file_2 = tmp_path / "direct_outbox_2.jsonl"
    emitted_2 = []

    def test_emit_2(stage, status, detail):
        emitted_2.append((stage, status))

    req_guest_light = {
        "id": "dir-2",
        "kind": "direct_tool",
        "role": "guest",
        "session_id": "dir_sess_2",
        "text": "test button light",
        "tool": "turn_light_on",
        "username": "guest_user",
    }
    _process_direct_tool(req_guest_light, test_emit_2, outbox_file_2)

    lines_2 = [json.loads(l) for l in outbox_file_2.read_text(encoding="utf-8").strip().splitlines()]
    final_line_2 = lines_2[-1]
    assert final_line_2["final"] is True
    assert final_line_2["decision"] == "ALLOW"
    assert ("hardware", "pass") in emitted_2


# ============================================================================
# 4. MULTI-PROCESS CONCURRENT LOGGER TESTS
# ============================================================================

def test_concurrent_logger_safe_hash_chain(tmp_path):
    """
    Spawns two independent OS processes that append to the same log file concurrently.
    Verifies that the cross-process file lock ensures LOG INTACT and all entries preserved.
    """
    log_file = tmp_path / "concurrent_audit_log.jsonl"
    log_file.touch()

    worker_code = """
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import security.logger
security.logger.set_log_file(Path(sys.argv[2]))
proc_id = sys.argv[3]
count = int(sys.argv[4])
for i in range(count):
    security.logger.log_decision(
        tool="turn_light_on",
        args={"proc": proc_id, "i": i},
        role="guest",
        risk="LOW",
        decision="ALLOW",
        reason=f"proc {proc_id} step {i}",
    )
"""

    p1 = subprocess.Popen([sys.executable, "-c", worker_code, str(ROOT_DIR), str(log_file), "proc1", "20"])
    p2 = subprocess.Popen([sys.executable, "-c", worker_code, str(ROOT_DIR), str(log_file), "proc2", "20"])

    p1.wait(timeout=15)
    p2.wait(timeout=15)

    assert p1.returncode == 0
    assert p2.returncode == 0

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 40

    is_intact, msg = check_audit_log_status(log_file)
    assert is_intact is True
    assert msg == "LOG INTACT"


# ============================================================================
# 5. LOGGER ARCHIVE & RESET TESTS
# ============================================================================

def test_logger_archive_and_reset(tmp_path):
    log_file = tmp_path / "logs" / "audit_log.jsonl"
    security.logger.set_log_file(log_file)

    # Log 3 entries
    for i in range(3):
        security.logger.log_decision(
            tool="read_temperature",
            args={"index": i},
            role="guest",
            risk="LOW",
            decision="ALLOW",
            reason=f"step {i}",
        )

    last_hash_before_reset = security.logger._get_last_entry_hash(log_file)
    assert last_hash_before_reset != "0" * 64

    # Perform archive and reset
    reset_entry = security.logger.archive_and_reset("periodic rotation")

    assert reset_entry["event"] == "log_archive_reset"
    assert reset_entry["final_hash"] == last_hash_before_reset
    assert reset_entry["prev_hash"] == "0" * 64

    # Verify archived file exists in archive/ and is intact
    archive_dir = log_file.parent / "archive"
    archived_files = list(archive_dir.glob("*.jsonl"))
    assert len(archived_files) == 1
    archived_file = archived_files[0]

    ok_arch, msg_arch = check_audit_log_status(archived_file)
    assert ok_arch is True
    assert msg_arch == "LOG INTACT"

    # Verify new log file starts with reset entry and is intact
    ok_new, msg_new = check_audit_log_status(log_file)
    assert ok_new is True
    assert msg_new == "LOG INTACT"

    # Append new decisions to new log file
    security.logger.log_decision(
        tool="turn_light_off",
        args={},
        role="guest",
        risk="LOW",
        decision="ALLOW",
        reason="after reset",
    )

    ok_after, msg_after = check_audit_log_status(log_file)
    assert ok_after is True
    assert msg_after == "LOG INTACT"


# ============================================================================
# 6. TEST ISOLATION VERIFICATION
# ============================================================================

def test_isolation_guarantee(tmp_path):
    """
    Verifies that test environment is isolated: active log points to tmp_path
    and real logs/audit_log.jsonl is not modified.
    """
    active_log = security.logger.get_log_file()
    assert str(tmp_path) in str(active_log)

    real_log = ROOT_DIR / "logs" / "audit_log.jsonl"
    if real_log.exists():
        real_size = real_log.stat().st_size
        # Writing to logger
        security.logger.log_decision(
            tool="read_temperature",
            args={},
            role="guest",
            risk="LOW",
            decision="ALLOW",
            reason="isolation check",
        )
        # Real log size must remain identical
        assert real_log.stat().st_size == real_size
