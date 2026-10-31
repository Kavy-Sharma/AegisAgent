"""

Phase 8 -- Pytest Suite for Dashboard Approval Provider & IPC Workflow

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

import security.signing

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





def _write_decision(base_dir, request_id, request_hash, approved, reason=None, tamper_sig=False, wrong_hash=None, wrong_id=None, decided_by="dashboard_operator"):

    dec_file = base_dir / "decisions" / f"{request_id}.json"

    decided_at = datetime.now(timezone.utc).isoformat()

    actual_hash = wrong_hash if wrong_hash is not None else request_hash

    actual_id = wrong_id if wrong_id is not None else request_id

    

    sig_payload = {

        "approved": approved,

        "decided_at": decided_at,

        "decided_by": decided_by,

        "request_hash": actual_hash,

        "request_id": actual_id,

    }

    sig = "invalid_signature_hex" if tamper_sig else security.signing.sign(sig_payload)

    

    data = {

        "request_id": actual_id,

        "request_hash": actual_hash,

        "approved": approved,

        "decided_at": decided_at,

        "decided_by": decided_by,

        "signature": sig,

    }

    if reason:

        data["reason"] = reason

    dec_file.write_text(json.dumps(data), encoding="utf-8")





# 1. Approve via decision file -> approved

def test_approve_via_decision_file(tmp_path):

    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)

    req = _make_request()



    def write_decision():

        time.sleep(0.1)

        _write_decision(tmp_path, req.request_id, req.request_hash, approved=True)



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

        _write_decision(tmp_path, req.request_id, req.request_hash, approved=False, reason="Denied by operator: unauthorized timeframe")



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

        _write_decision(

            tmp_path,

            req.request_id,

            req.request_hash,

            approved=True,

            wrong_hash="tampered_wrong_hash_00000000000000000000000000000000",

        )



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





# 5. Bad signature in decision file -> deny with "bad signature"

def test_bad_signature_in_decision_file_denies(tmp_path):

    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)

    req = _make_request()



    def write_decision():

        time.sleep(0.1)

        _write_decision(tmp_path, req.request_id, req.request_hash, approved=True, tamper_sig=True)



    t = threading.Thread(target=write_decision)

    t.start()



    res = provider.request_approval(req)

    t.join()



    assert res.approved is False

    assert res.reason == "bad signature"

    assert res.decided_by == "dashboard_operator"

    # Verify cleanup

    assert not (tmp_path / "pending" / f"{req.request_id}.json").exists()

    assert not (tmp_path / "decisions" / f"{req.request_id}.json").exists()





# 6. Malformed JSON -> deny

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





# 7. Decision for a different request_id is ignored

def test_decision_for_different_request_id_is_ignored(tmp_path):

    provider = DashboardApprovalProvider(timeout_seconds=1.0, poll_interval=0.05, base_dir=tmp_path)

    req = _make_request()



    # Write a decision file for an unrelated request ID

    unrelated_file = tmp_path / "decisions" / "unrelated_different_id.json"

    sig_payload = {

        "approved": True,

        "decided_at": datetime.now(timezone.utc).isoformat(),

        "request_hash": req.request_hash,

        "request_id": "unrelated_different_id",

    }

    unrelated_file.write_text(

        json.dumps({

            "approved": True,

            "request_hash": req.request_hash,

            "request_id": "unrelated_different_id",

            "decided_at": sig_payload["decided_at"],

            "signature": security.signing.sign(sig_payload),

        }),

        encoding="utf-8",

    )



    res = provider.request_approval(req)



    # Should ignore unrelated file and time out

    assert res.approved is False

    assert res.timed_out is True

    assert res.decided_by == "timeout"





# 8. Pending file is written atomically and cleaned up

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

        _write_decision(tmp_path, req.request_id, req.request_hash, approved=True)



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





# 9. Audit chain remains valid afterwards

def test_audit_chain_valid_after_dashboard_approval(tmp_path):

    provider = DashboardApprovalProvider(timeout_seconds=2.0, poll_interval=0.05, base_dir=tmp_path)

    manager = ApprovalManager(provider=provider)

    req = _make_request(session_id="audit_chain_test_sess")



    def write_decision():

        time.sleep(0.1)

        _write_decision(tmp_path, req.request_id, req.request_hash, approved=True)



    t = threading.Thread(target=write_decision)

    t.start()



    res = manager.request(req)

    t.join()



    assert res.approved is True

    assert verify_audit_log() is True

