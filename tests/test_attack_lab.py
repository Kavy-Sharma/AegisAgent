"""
Tests for Attack Lab Backend Engine.

Verifies:
1. Each scenario produces unlocked door/alarm in unprotected run and expected stopped_at in protected run.
2. Real hardware bridge is never called.
3. Previous bridge is restored even when an error occurs.
4. Guest role gets 403 Forbidden on attack lab API routes.
5. Global policy dict remains untouched after lab runs.
6. Audit entries are tagged with source="attack_lab".
"""

import copy
import json
import os
from pathlib import Path
import pytest

import security.attack_lab as attack_lab
from security.attack_lab import SCENARIOS, run_protected, run_unprotected
import security.hardware
import security.logger
import security.policy_loader
from web.server import create_app


def test_attack_lab_scenarios_unprotected_vs_protected(tmp_path):
    """
    Verifies that for every scenario:
    - Unprotected simulation succeeds (door unlocked / alarm on).
    - Protected pipeline blocks at the expected defense stage and keeps virtual state safe.
    """
    for sc in SCENARIOS:
        sc_id = sc["id"]
        exp_stage = sc["expected_protected_stage"]

        # 1. Unprotected Run
        res_u = run_unprotected(sc, scratch_dir=tmp_path)
        assert res_u["result"] == "simulated, no guard"
        assert res_u["action_executed"] is True

        if sc_id in ("direct_override", "memo_subtle", "memo_obvious", "admin_unlock"):
            assert res_u["virtual_state"]["door"] == "unlocked", f"Scenario {sc_id} expected unlocked door"
        elif sc_id == "guest_alarm":
            assert res_u["virtual_state"]["alarm"] == "on", f"Scenario {sc_id} expected alarm on"

        # 2. Protected Run
        res_p = run_protected(sc, scratch_dir=tmp_path)
        assert res_p["stopped_at"] == exp_stage, f"Scenario {sc_id} expected stopped_at={exp_stage}, got {res_p['stopped_at']}"
        assert res_p["final"]["decision"] == "BLOCK"

        # Virtual state in protected run remains safe
        assert res_p["virtual_state"]["door"] == "locked"
        assert res_p["virtual_state"]["alarm"] == "off"


def test_attack_lab_real_bridge_never_called(tmp_path):
    """
    Verifies that real hardware bridge is never invoked during attack lab runs.
    """
    class RealHardwareSentinelBridge:
        def __init__(self):
            self.calls = 0

        def is_device_online(self):
            return True

        def publish(self, command):
            self.calls += 1
            raise AssertionError("Real hardware bridge was invoked by Attack Lab!")

    sentinel = RealHardwareSentinelBridge()
    security.hardware.set_bridge(sentinel)

    try:
        for sc in SCENARIOS:
            run_unprotected(sc, scratch_dir=tmp_path)
            run_protected(sc, scratch_dir=tmp_path)

        assert sentinel.calls == 0
        assert security.hardware._bridge_instance is sentinel
    finally:
        security.hardware.set_bridge(None)


def test_attack_lab_previous_bridge_restored_after_error(tmp_path, monkeypatch):
    """
    Verifies that previous bridge is always restored even if run_turn raises an exception.
    """
    sentinel = object()
    security.hardware.set_bridge(sentinel)

    # Inject an unexpected crash into run_turn
    def crash_run_turn(*args, **kwargs):
        raise RuntimeError("Simulated crash inside agent turn")

    monkeypatch.setattr(attack_lab, "run_turn", crash_run_turn)

    try:
        with pytest.raises(RuntimeError, match="Simulated crash"):
            run_protected(SCENARIOS[0], scratch_dir=tmp_path)

        # Bridge must be restored despite error
        assert security.hardware._bridge_instance is sentinel
    finally:
        security.hardware.set_bridge(None)


def test_attack_lab_policy_unchanged_after_run(tmp_path):
    """
    Verifies that the global POLICY dictionary is not mutated during lab execution.
    """
    snapshot = copy.deepcopy(security.policy_loader.POLICY)

    for sc in SCENARIOS:
        run_unprotected(sc, scratch_dir=tmp_path)
        run_protected(sc, scratch_dir=tmp_path)

    assert security.policy_loader.POLICY == snapshot


def test_attack_lab_audit_source_tagged(tmp_path):
    """
    Verifies audit log entries from lab runs contain 'source': 'attack_lab'.
    """
    sc = SCENARIOS[0]
    run_protected(sc, scratch_dir=tmp_path)

    log_file = security.logger.get_log_file()
    assert log_file.exists()

    lab_entries = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entry = json.loads(line)
                if entry.get("event") == "attack_lab_run":
                    lab_entries.append(entry)

    assert len(lab_entries) >= 1
    assert lab_entries[-1]["source"] == "attack_lab"
    assert lab_entries[-1]["scenario_id"] == sc["id"]


def test_attack_lab_api_guest_gets_403(tmp_path):
    """
    Verifies that non-admin (guest) users are forbidden from calling attack lab API endpoints.
    """
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        # 1. Without login -> 401 or redirect to login
        res = client.post("/api/attack_lab/run", json={"scenario_id": "direct_override"})
        assert res.status_code in (401, 403, 302)

        # 2. Logged in as guest -> 403 Forbidden
        with client.session_transaction() as sess:
            sess["username"] = "guest_user"
            sess["role"] = "guest"
            sess["real_role"] = "guest"
            sess["csrf_token"] = "test_csrf_token"

        res2 = client.post(
            "/api/attack_lab/run",
            json={"scenario_id": "direct_override"},
            headers={"X-CSRF-Token": "test_csrf_token"},
        )
        assert res2.status_code == 403

        res3 = client.get("/api/attack_lab/result/lab_123456789012")
        assert res3.status_code == 403


def test_attack_lab_api_admin_run_and_result(tmp_path, monkeypatch):
    """
    Verifies full admin flow:
    - Admin submits scenario run via POST /api/attack_lab/run
    - Signed request written to inbox
    - Worker processes attack_lab request
    - GET /api/attack_lab/result/<id> returns completed comparison
    """
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGIS_LOG_FILE", str(tmp_path / "audit_log.jsonl"))

    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"
            sess["csrf_token"] = "admin_csrf_123"

        res = client.post(
            "/api/attack_lab/run",
            json={"scenario_id": "direct_override"},
            headers={"X-CSRF-Token": "admin_csrf_123"},
        )
        assert res.status_code == 200
        req_id = res.get_json()["req_id"]
        assert req_id.startswith("lab_")

        # Initial poll is queued or running
        poll1 = client.get(f"/api/attack_lab/result/{req_id}")
        assert poll1.status_code == 200
        assert poll1.get_json()["status"] in ("queued", "running")

        # Verify inbox file exists and is valid
        inbox_file = tmp_path / "chat" / "inbox" / f"{req_id}.json"
        assert inbox_file.exists()
        with open(inbox_file, "r", encoding="utf-8") as f:
            req_payload = json.load(f)
        assert req_payload["kind"] == "attack_lab"
        assert req_payload["scenario_id"] == "direct_override"

        # Simulate worker processing
        from agent.worker import _process_attack_lab
        outbox_file = tmp_path / "chat" / "outbox" / f"{req_id}.jsonl"
        _process_attack_lab(req_payload, None, outbox_file)

        # Final poll is completed with full comparative results
        poll2 = client.get(f"/api/attack_lab/result/{req_id}")
        assert poll2.status_code == 200
        data = poll2.get_json()
        assert data["status"] == "completed"
        res_entry = data["result"]
        assert res_entry["unprotected"]["action_executed"] is True
        assert res_entry["unprotected"]["virtual_state"]["door"] == "unlocked"
        assert res_entry["protected"]["stopped_at"] == "detection"
        assert res_entry["protected"]["virtual_state"]["door"] == "locked"
        assert res_entry["source"] == "attack_lab"


def test_attack_lab_admin_not_quarantined_and_sentinel_unalerted(tmp_path, monkeypatch):
    """
    Run all 5 lab scenarios as admin through run_protected using tmp_path data dirs.
    Afterwards assert:
    (a) the admin user is NOT quarantined (quarantine.json for tmp dir has no entry for admin)
    (b) the sentinel real bridge received zero publish() calls INCLUDING alert_blocked
    (c) the audit chain still verifies after the runs
    """
    import time
    from security.quarantine import is_quarantined, _get_quarantine_file
    from security.verify_log import verify_audit_log

    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))

    class SentinelRealBridge:
        def __init__(self):
            self.calls = []

        def is_device_online(self):
            return True

        def publish(self, command):
            self.calls.append(command)
            return security.hardware.HardwareCommandResult(ok=True)

    sentinel = SentinelRealBridge()
    security.hardware.set_bridge(sentinel)

    try:
        for sc in SCENARIOS:
            admin_sc = dict(sc)
            admin_sc["role"] = "admin"
            admin_sc["username"] = "admin"
            run_protected(admin_sc, scratch_dir=tmp_path)

        # Allow any background alert thread a moment to finish
        time.sleep(0.1)

        # (a) admin user is NOT quarantined
        assert not is_quarantined("admin"), "admin user was quarantined by lab run!"
        q_file = _get_quarantine_file()
        if q_file.exists():
            with open(q_file, "r", encoding="utf-8") as f:
                q_data = json.load(f)
            assert "admin" not in q_data.get("quarantined", [])
            assert "admin" not in q_data.get("counts", {})

        # (b) sentinel bridge received zero publish() calls including alert_blocked
        assert len(sentinel.calls) == 0, f"Sentinel bridge received {len(sentinel.calls)} calls: {sentinel.calls}"

        # (c) audit chain still verifies after the runs
        log_file = security.logger.get_log_file()
        assert log_file.exists()
        assert verify_audit_log(str(log_file)) is True
    finally:
        security.hardware.set_bridge(None)


def test_attack_lab_preserves_real_user_rate_limit_and_threats(tmp_path):
    """
    Verifies that lab runs do not wipe real-user entries in the rate limiter
    or security.gateway._SESSION_THREATS.
    """
    import security.rate_limiter
    import security.gateway

    # 1. Put fake real-user entry in the rate limiter and in _SESSION_THREATS
    fake_rate_key = ("real_user_alice", "turn_light_on")
    fake_rate_timestamps = [1000.0, 1005.0]
    security.rate_limiter.CALL_TIMESTAMPS[fake_rate_key] = list(fake_rate_timestamps)

    if not hasattr(security.gateway, "_SESSION_THREATS"):
        security.gateway._SESSION_THREATS = {}
    fake_threat_entry = {"threat_score": 0.85, "tainted": True}
    security.gateway._SESSION_THREATS["real_sess_alice"] = dict(fake_threat_entry)

    try:
        # 2. Run all 5 scenarios
        for sc in SCENARIOS:
            run_protected(sc, scratch_dir=tmp_path)

        # 3. Assert those real entries are unchanged afterwards
        assert fake_rate_key in security.rate_limiter.CALL_TIMESTAMPS
        assert security.rate_limiter.CALL_TIMESTAMPS[fake_rate_key] == fake_rate_timestamps
        assert "real_sess_alice" in security.gateway._SESSION_THREATS
        assert security.gateway._SESSION_THREATS["real_sess_alice"] == fake_threat_entry
    finally:
        dict.pop(security.rate_limiter.CALL_TIMESTAMPS, fake_rate_key, None)
        if hasattr(security.gateway, "_SESSION_THREATS") and isinstance(security.gateway._SESSION_THREATS, dict):
            security.gateway._SESSION_THREATS.pop("real_sess_alice", None)


def test_attack_lab_office_scenarios_including_param_guard(tmp_path):
    """
    Verifies that all office scenarios (including param_guard path traversal and SQL injection)
    run through unprotected vs protected accurately:
    - Unprotected shows the harm (table dropped / secret file read).
    - Protected stops at the expected layer (param_guard) with decision BLOCK and leaves sandbox safe.
    """
    from security.attack_lab import OFFICE_SCENARIOS
    from agent.environments.office import OfficeSandbox
    import agent.agent

    agent.agent.load_environment("office")
    try:
        for sc in OFFICE_SCENARIOS:
            sc_id = sc["id"]
            exp_stage = sc["expected_protected_stage"]

            OfficeSandbox.reset()
            res_u = run_unprotected(sc, scratch_dir=tmp_path)
            assert res_u["action_executed"] is True
            assert res_u["adapter"] == "office_sandbox"

            if sc_id == "office_sql_injection":
                assert res_u["unprotected_outcome"] == "Table dropped in sandbox"
                assert res_u["virtual_state"]["sql_rows_count"] == 0
            elif sc_id == "office_path_traversal":
                assert res_u["unprotected_outcome"] == "Secret file read"

            OfficeSandbox.reset()
            res_p = run_protected(sc, scratch_dir=tmp_path)
            assert res_p["final"]["decision"] == "BLOCK"
            assert res_p["stopped_at"] == exp_stage, f"Expected {exp_stage}, got {res_p['stopped_at']}"
            assert res_p["stopped_layer"] == exp_stage

            if sc_id == "office_sql_injection":
                # In protected run, database remains intact (not dropped)
                assert res_p["virtual_state"]["sql_rows_count"] == 3
    finally:
        agent.agent.load_environment("smart_home")


def test_office_sandbox_resets_between_unprotected_runs(tmp_path):
    """
    Verifies that running office_sql_injection unprotected drops the database in the sandbox,
    but a subsequent unprotected scenario run automatically resets the database back to 3 rows.
    """
    from security.attack_lab import OFFICE_SCENARIOS, run_unprotected
    from agent.environments.office import OfficeSandbox
    import agent.agent

    agent.agent.load_environment("office")
    try:
        sc_sql = next(s for s in OFFICE_SCENARIOS if s["id"] == "office_sql_injection")
        sc_file = next(s for s in OFFICE_SCENARIOS if s["id"] == "office_poisoned_file")

        # First run: drops table, sql_rows_count goes to 0
        res1 = run_unprotected(sc_sql, scratch_dir=tmp_path)
        assert res1["virtual_state"]["sql_rows_count"] == 0
        assert len(OfficeSandbox.database) == 0

        # Second run without explicit manual reset: automatically resets to fresh initial state (3 rows)
        res2 = run_unprotected(sc_file, scratch_dir=tmp_path)
        assert res2["virtual_state"]["sql_rows_count"] == 3
        assert len(OfficeSandbox.database) == 3
    finally:
        agent.agent.load_environment("smart_home")




