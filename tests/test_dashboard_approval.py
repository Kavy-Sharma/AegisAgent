"""
Phase 8 — Pytest Suite for Dashboard Approval Provider & IPC Workflow
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import time
import pytest

from security.approval import (
    ApprovalManager,
    ApprovalRequest,
    DashboardApprovalProvider,
)
from security.verify_log import verify_audit_log


def _make_request(session_id="test_sess", tool="unlock_door", risk="HIGH") -> ApprovalRequest:
    return ApprovalRequest(
        session_id=session_id,
        kind="tool_call",
        tool=tool,
        args={"door_id": "main_entrance", "auto_lock": True},
        risk=risk,
        reasons=["High-risk door unlock action requires operator confirmation"],
    )


# 1. Approve via decision file -> approved
def test_approve_via_decision_file(tmp_path):
    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)
    req = _make_request()

    def write_decision():
        time.sleep(0.1)
        dec_file = tmp_path / "decisions" / f"{req.request_id}.json"
        data = {
            "approved": True,
            "request_hash": req.request_hash,
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }
        dec_file.write_text(json.dumps(data), encoding="utf-8")

    t = threading.Thread(target=write_decision)
    t.start()

    res = provider.request_approval(req)
    t.join()

    assert res.approved is True
    assert res.decided_by == "dashboard_operator"
    assert res.timed_out is False
    # Verify cleanup
    assert not (tmp_path / "pending" / f"{req.request_id}.json").exists()
    assert not (tmp_path / "decisions" / f"{req.request_id}.json").exists()


# 2. Deny via decision file -> denied
def test_deny_via_decision_file(tmp_path):
    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)
    req = _make_request()

    def write_decision():
        time.sleep(0.1)
        dec_file = tmp_path / "decisions" / f"{req.request_id}.json"
        data = {
            "approved": False,
            "request_hash": req.request_hash,
            "decided_at": datetime.now(timezone.utc).isoformat(),
            "reason": "Denied by operator: unauthorized timeframe",
        }
        dec_file.write_text(json.dumps(data), encoding="utf-8")

    t = threading.Thread(target=write_decision)
    t.start()

    res = provider.request_approval(req)
    t.join()

    assert res.approved is False
    assert res.decided_by == "dashboard_operator"
    assert "Denied by operator" in res.reason
    assert res.timed_out is False
    # Verify cleanup
    assert not (tmp_path / "pending" / f"{req.request_id}.json").exists()
    assert not (tmp_path / "decisions" / f"{req.request_id}.json").exists()


# 3. No file -> timeout deny (use a 1s timeout)
def test_no_file_timeout_denies(tmp_path):
    provider = DashboardApprovalProvider(timeout_seconds=1.0, poll_interval=0.05, base_dir=tmp_path)
    req = _make_request()

    res = provider.request_approval(req)

    assert res.approved is False
    assert res.timed_out is True
    assert res.decided_by == "timeout"
    assert "timed out" in res.reason.lower()
    # Verify pending file cleaned up
    assert not (tmp_path / "pending" / f"{req.request_id}.json").exists()


# 4. Wrong request_hash in decision file -> deny with "hash mismatch"
def test_wrong_request_hash_in_decision_file_denies(tmp_path):
    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)
    req = _make_request()

    def write_decision():
        time.sleep(0.1)
        dec_file = tmp_path / "decisions" / f"{req.request_id}.json"
        data = {
            "approved": True,
            "request_hash": "tampered_wrong_hash_00000000000000000000000000000000",
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }
        dec_file.write_text(json.dumps(data), encoding="utf-8")

    t = threading.Thread(target=write_decision)
    t.start()

    res = provider.request_approval(req)
    t.join()

    assert res.approved is False
    assert res.reason == "hash mismatch"
    assert res.decided_by == "dashboard_operator"
    # Verify cleanup
    assert not (tmp_path / "pending" / f"{req.request_id}.json").exists()
    assert not (tmp_path / "decisions" / f"{req.request_id}.json").exists()


# 5. Malformed JSON -> deny
def test_malformed_json_in_decision_file_denies(tmp_path):
    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)
    req = _make_request()

    def write_decision():
        time.sleep(0.1)
        dec_file = tmp_path / "decisions" / f"{req.request_id}.json"
        dec_file.write_text("{broken json syntax: true, [", encoding="utf-8")

    t = threading.Thread(target=write_decision)
    t.start()

    res = provider.request_approval(req)
    t.join()

    assert res.approved is False
    assert res.decided_by == "system"
    assert "Malformed decision file" in res.reason
    # Verify cleanup
    assert not (tmp_path / "pending" / f"{req.request_id}.json").exists()
    assert not (tmp_path / "decisions" / f"{req.request_id}.json").exists()


# 6. Decision for a different request_id is ignored
def test_decision_for_different_request_id_is_ignored(tmp_path):
    provider = DashboardApprovalProvider(timeout_seconds=1.0, poll_interval=0.05, base_dir=tmp_path)
    req = _make_request()

    # Write a decision file for an unrelated request ID
    unrelated_file = tmp_path / "decisions" / "unrelated_different_id.json"
    unrelated_file.write_text(
        json.dumps({
            "approved": True,
            "request_hash": req.request_hash,
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }),
        encoding="utf-8",
    )

    res = provider.request_approval(req)

    # Should ignore unrelated file and time out
    assert res.approved is False
    assert res.timed_out is True
    assert res.decided_by == "timeout"


# 7. Pending file is written atomically and cleaned up
def test_pending_file_written_atomically_and_cleaned_up(tmp_path):
    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)
    req = _make_request()

    observed_pending_keys = set()
    observed_pending_exists = False

    def inspect_and_decide():
        nonlocal observed_pending_keys, observed_pending_exists
        pending_file = tmp_path / "pending" / f"{req.request_id}.json"
        for _ in range(20):
            if pending_file.exists():
                observed_pending_exists = True
                try:
                    data = json.loads(pending_file.read_text(encoding="utf-8"))
                    observed_pending_keys = set(data.keys())
                    break
                except Exception:
                    pass
            time.sleep(0.05)

        # Write decision to complete flow
        dec_file = tmp_path / "decisions" / f"{req.request_id}.json"
        data = {
            "approved": True,
            "request_hash": req.request_hash,
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }
        dec_file.write_text(json.dumps(data), encoding="utf-8")

    t = threading.Thread(target=inspect_and_decide)
    t.start()

    res = provider.request_approval(req)
    t.join()

    assert res.approved is True
    assert observed_pending_exists is True
    expected_keys = {
        "request_id",
        "kind",
        "tool",
        "args",
        "risk",
        "reasons",
        "request_hash",
        "created_at",
        "expires_at",
    }
    assert expected_keys.issubset(observed_pending_keys)
    # Both pending and decision files cleaned up
    assert not (tmp_path / "pending" / f"{req.request_id}.json").exists()
    assert not (tmp_path / "decisions" / f"{req.request_id}.json").exists()


# 8. Audit chain remains valid afterwards
def test_audit_chain_valid_after_dashboard_approval(tmp_path):
    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)
    manager = ApprovalManager(provider=provider)
    req = _make_request(session_id="audit_chain_test_sess")

    def write_decision():
        time.sleep(0.1)
        dec_file = tmp_path / "decisions" / f"{req.request_id}.json"
        data = {
            "approved": True,
            "request_hash": req.request_hash,
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }
        dec_file.write_text(json.dumps(data), encoding="utf-8")

    t = threading.Thread(target=write_decision)
    t.start()

    res = manager.request(req)
    t.join()

    assert res.approved is True
    assert verify_audit_log() is True
