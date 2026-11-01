"""
Comprehensive Test Suite for Audit Log Page and Cryptographic Ledger Infrastructure.

Verifies:
1. Reverse streaming tail reader matches forward filter on small blocks crossing boundaries.
2. Filters & Search (Decision, Actor/Role, Source, Search query, Date ranges).
3. CSV Spreadsheet Formula Injection Protection for =, +, -, @, tab, CR (CWE-1236).
4. Copy-only Tamper Demo isolation: SHA-256 of real log file identical before/after all 5 actions.
5. Strict Admin-only RBAC protection: All admin endpoints return 403 for guest and user roles.
6. CSRF Protection: Mutating POST endpoints return 403 when CSRF token is missing or invalid.
7. Anchor export and verification: Validates intact log and catches truncation/head tampering.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import pytest

import security.attack_lab
import security.logger
from security.logger import log_event
from security.verify_log import check_audit_log_status, create_anchor, export_anchor_line
from web.api_audit import (
    classify_audit_decision,
    escape_csv_cell,
    format_plain_summary,
    read_entries_reverse,
)
from web.server import create_app


def _create_mock_chain(log_path: Path, count: int = 50) -> list[dict]:
    """Helper that generates a cryptographically valid hash chain in log_path."""
    prev_hash = "0" * 64
    entries = []
    lines = []

    decisions = ["ALLOW", "BLOCK", "REVIEW", "ERROR"]
    roles = ["admin", "guest", "agent", "supervisor"]
    sources = ["real", "attack_lab", "virtual"]

    base_time = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)

    for i in range(count):
        entry_time = base_time + timedelta(seconds=i * 10)
        dec = decisions[i % len(decisions)]
        role = roles[i % len(roles)]
        src = sources[i % len(sources)]

        record = {
            "timestamp": entry_time.isoformat(),
            "event": f"action_{i}",
            "tool": "unlock_door" if i % 2 == 0 else "read_memo",
            "decision": dec,
            "role": role,
            "source": src,
            "reason": f"Audit test record #{i}",
            "args": {"line_num": i},
        }

        # Calculate SHA-256 chain link
        payload = json.dumps(record, sort_keys=True) + prev_hash
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        record["prev_hash"] = prev_hash
        record["entry_hash"] = entry_hash

        prev_hash = entry_hash
        entries.append(record)
        lines.append(json.dumps(record))

    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return entries


# =========================================================================
# 1. Reverse Streaming Tail Reader vs Forward Filter with Tiny Block Size
# =========================================================================

def test_reverse_reader_matches_forward_filter_chunk_boundaries(tmp_path):
    """
    Verifies that reverse reader chunking with a tiny block size (64 bytes)
    where lines span across multiple chunk boundaries gives 100% identical results
    to an authoritative naive forward filter.
    """
    log_file = tmp_path / "tiny_chunk_audit.jsonl"
    total_count = 25
    _create_mock_chain(log_file, count=total_count)

    # Ground truth forward filter: read all, filter for decision == BLOCK, reverse
    all_raw = [json.loads(l) for l in log_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    expected_forward = [e for e in all_raw if str(e.get("decision")).upper() in ("BLOCK", "BLOCKED")][::-1]

    # Reverse reader with tiny 64-byte blocks forcing frequent multi-chunk line splits
    reverse_results, total_matching, total_lines = read_entries_reverse(
        log_file=log_file,
        limit=50,
        offset=0,
        decision_filter="BLOCKED",
        block_size=64,
    )

    assert total_lines == total_count
    assert total_matching == len(expected_forward)
    assert len(reverse_results) == len(expected_forward)

    for i in range(len(expected_forward)):
        assert reverse_results[i]["entry_hash"] == expected_forward[i]["entry_hash"]
        assert reverse_results[i]["prev_hash"] == expected_forward[i]["prev_hash"]
        assert reverse_results[i]["reason"] == expected_forward[i]["reason"]


def test_reverse_streaming_big_file(tmp_path):
    """
    Verifies reverse pagination on 1,200 entries without loading whole file.
    """
    log_file = tmp_path / "big_audit.jsonl"
    total_count = 1200
    mock_entries = _create_mock_chain(log_file, count=total_count)

    # Page 1 (limit 25, offset 0)
    items, total_matching, total_lines = read_entries_reverse(log_file, limit=25, offset=0)
    assert total_matching == total_count
    assert total_lines == total_count
    assert len(items) == 25
    assert items[0]["entry_hash"] == mock_entries[-1]["entry_hash"]
    assert items[24]["entry_hash"] == mock_entries[-25]["entry_hash"]

    # Page 2 (limit 25, offset 25)
    items_p2, _, _ = read_entries_reverse(log_file, limit=25, offset=25)
    assert len(items_p2) == 25
    assert items_p2[0]["entry_hash"] == mock_entries[-26]["entry_hash"]


# =========================================================================
# 2. Filters & Plain-English Summaries
# =========================================================================

def test_filters_and_summaries(tmp_path):
    """Verifies decision, role, source, and search filters."""
    log_file = tmp_path / "filter_audit.jsonl"
    _create_mock_chain(log_file, count=60)

    # Decision filter: BLOCKED
    items, total, _ = read_entries_reverse(log_file, limit=100, decision_filter="BLOCKED")
    assert total > 0
    for it in items:
        assert str(it["decision"]).upper() in ("BLOCK", "BLOCKED")

    # Role filter: guest
    items, total, _ = read_entries_reverse(log_file, limit=100, role_filter="guest")
    assert total > 0
    for it in items:
        assert it["role"] == "guest"

    # Source filter: attack_lab
    items, total, _ = read_entries_reverse(log_file, limit=100, source_filter="attack_lab")
    assert total > 0
    for it in items:
        assert it["source"] == "attack_lab"

    # Search filter: record #42
    items, total, _ = read_entries_reverse(log_file, limit=10, search_query="#42")
    assert total == 1
    assert "42" in items[0]["reason"]

    # Verify template plain summary
    sample = {
        "event": "tool_call",
        "tool": "unlock_door",
        "decision": "BLOCK",
        "role": "guest",
        "reason": "Policy mismatch: user only asked to read",
    }
    summary = format_plain_summary(sample)
    assert "Blocked: User only asked to read, but payload attempted 'unlock_door'." in summary


# =========================================================================
# 3. CSV Formula Injection Defense for =, +, -, @, Tab, CR (CWE-1236)
# =========================================================================

def test_csv_formula_injection_defense():
    """
    Prevents formulas like =SUM(), +123, -cmd, @calc, tab, CR from executing in Excel/Calc.
    """
    # 1. Equals sign
    assert escape_csv_cell("=1+1") == "'=1+1"
    assert escape_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"

    # 2. Plus sign
    assert escape_csv_cell("+12345") == "'+12345"

    # 3. Minus sign
    assert escape_csv_cell("-2+3*4") == "'-2+3*4"

    # 4. At symbol
    assert escape_csv_cell("@SUM(A1:B10)") == "'@SUM(A1:B10)"

    # 5. Tab character
    assert escape_csv_cell("\tmalicious_tab_payload") == "'\tmalicious_tab_payload"

    # 6. Carriage return character
    assert escape_csv_cell("\rmalicious_cr_payload") == "'\rmalicious_cr_payload"

    # Benign text is unaffected
    assert escape_csv_cell("Safe audit log entry") == "Safe audit log entry"
    assert escape_csv_cell("2026-11-01 12:00:00") == "2026-11-01 12:00:00"
    assert escape_csv_cell(None) == ""


# =========================================================================
# 4. Tamper Demo: Copy-Only Sandbox Isolation (SHA-256 for all 5 actions)
# =========================================================================

def test_tamper_demo_never_touches_real_log(tmp_path, monkeypatch):
    """
    CRITICAL SECURITY INVARIANT:
    For EACH of the 5 tamper actions (edit_line, delete_line, truncate, rewrite, reset),
    the SHA-256 of the real log file MUST be identical before and after.
    """
    real_log = tmp_path / "real_audit.jsonl"
    _create_mock_chain(real_log, count=10)

    monkeypatch.setenv("AEGIS_LOG_FILE", str(real_log))
    security.logger.set_log_file(real_log)

    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"
            sess["csrf_token"] = "valid_csrf_token"

        actions = ["edit_line", "delete_line", "truncate", "rewrite", "reset"]
        for act in actions:
            # Calculate SHA-256 of real log BEFORE action
            sha_before = hashlib.sha256(real_log.read_bytes()).hexdigest()
            mtime_before = real_log.stat().st_mtime_ns

            res = client.post(
                "/api/audit/tamper_demo",
                json={"action": act},
                headers={"X-CSRF-Token": "valid_csrf_token"},
            )
            assert res.status_code == 200, f"Action {act} failed with {res.data}"
            data = res.get_json()
            assert data["status"] == "success"
            assert "chain_blocks" in data
            assert len(data["chain_blocks"]) > 0

            # Calculate SHA-256 of real log AFTER action
            sha_after = hashlib.sha256(real_log.read_bytes()).hexdigest()
            mtime_after = real_log.stat().st_mtime_ns

            # MUST be byte-for-byte cryptographically identical
            assert sha_before == sha_after, f"Real log hash changed during action '{act}'!"
            assert mtime_before == mtime_after, f"Real log mtime changed during action '{act}'!"


# =========================================================================
# 5. RBAC: All Admin Endpoints Return 403 for Guest and User Roles
# =========================================================================

def test_admin_only_rbac_all_endpoints(tmp_path, monkeypatch):
    """
    Verifies that all 5 admin endpoints return 403 for both guest and user roles.
    Endpoints:
    1. GET /audit
    2. GET /api/audit/entries
    3. GET /api/audit/export/csv
    4. GET /api/audit/anchor/export
    5. POST /api/audit/tamper_demo
    (and POST /api/audit/anchor/check)
    """
    real_log = tmp_path / "rbac_audit.jsonl"
    _create_mock_chain(real_log, count=5)
    monkeypatch.setenv("AEGIS_LOG_FILE", str(real_log))
    security.logger.set_log_file(real_log)

    app = create_app()
    app.config["TESTING"] = True

    non_admin_roles = ["guest", "user"]

    with app.test_client() as client:
        for r in non_admin_roles:
            with client.session_transaction() as sess:
                sess["username"] = f"test_{r}"
                sess["role"] = r
                sess["real_role"] = r
                sess["csrf_token"] = f"csrf_{r}"

            # 1. Page
            assert client.get("/audit").status_code == 403
            # 2. Entries
            assert client.get("/api/audit/entries").status_code == 403
            # 3. Export CSV
            assert client.get("/api/audit/export/csv").status_code == 403
            # 4. Export Anchor
            assert client.get("/api/audit/anchor/export").status_code == 403
            # 5. Tamper Demo
            assert client.post(
                "/api/audit/tamper_demo",
                json={"action": "edit_line"},
                headers={"X-CSRF-Token": f"csrf_{r}"},
            ).status_code == 403
            # 6. Anchor Check
            assert client.post(
                "/api/audit/anchor/check",
                json={"anchor_text": "{}"},
                headers={"X-CSRF-Token": f"csrf_{r}"},
            ).status_code == 403

        # Authenticate as Admin -> all succeed (200)
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"
            sess["csrf_token"] = "csrf_admin"

        assert client.get("/audit").status_code == 200
        assert client.get("/api/audit/entries").status_code == 200
        assert client.get("/api/audit/export/csv").status_code == 200
        assert client.get("/api/audit/anchor/export").status_code == 200


# =========================================================================
# 6. CSRF Defense: Mutating POST Endpoints Return 403 Without CSRF Token
# =========================================================================

def test_post_endpoints_require_csrf_token(tmp_path, monkeypatch):
    """
    Verifies that mutating POST endpoints (/api/audit/tamper_demo and /api/audit/anchor/check)
    return 403 Forbidden when CSRF token is omitted or invalid, even for an admin.
    """
    real_log = tmp_path / "csrf_audit.jsonl"
    _create_mock_chain(real_log, count=6)
    monkeypatch.setenv("AEGIS_LOG_FILE", str(real_log))
    security.logger.set_log_file(real_log)

    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"
            sess["csrf_token"] = "secret_valid_token"

        # 1. Tamper demo without CSRF header -> 403
        res = client.post("/api/audit/tamper_demo", json={"action": "edit_line"})
        assert res.status_code == 403
        assert "CSRF" in res.get_json().get("error", "")

        # 2. Anchor check without CSRF header -> 403
        res2 = client.post("/api/audit/anchor/check", json={"anchor_text": "{}"})
        assert res2.status_code == 403
        assert "CSRF" in res2.get_json().get("error", "")

        # 3. With invalid CSRF token -> 403
        res3 = client.post(
            "/api/audit/tamper_demo",
            json={"action": "edit_line"},
            headers={"X-CSRF-Token": "wrong_token"},
        )
        assert res3.status_code == 403

        # 4. With valid CSRF token -> 200
        res4 = client.post(
            "/api/audit/tamper_demo",
            json={"action": "reset"},
            headers={"X-CSRF-Token": "secret_valid_token"},
        )
        assert res4.status_code == 200


# =========================================================================
# 7. Anchor Export, Verification, and Truncation Detection
# =========================================================================

def test_anchor_export_and_check(tmp_path, monkeypatch):
    """
    Verifies anchor export, intact validation, forged head hash detection,
    and log truncation detection.
    """
    real_log = tmp_path / "anchor_audit.jsonl"
    _create_mock_chain(real_log, count=8)
    monkeypatch.setenv("AEGIS_LOG_FILE", str(real_log))
    security.logger.set_log_file(real_log)

    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["csrf_token"] = "csrf_test_anchor"

        # 1. Export Anchor
        res = client.get("/api/audit/anchor/export")
        assert res.status_code == 200
        anchor_data = res.get_json()
        assert anchor_data["count"] == 8
        assert "head_hash" in anchor_data
        assert "warning" in anchor_data
        assert "OFF THIS COMPUTER" in anchor_data["warning"]

        # 2. Check Valid Anchor against untouched log
        res_check = client.post(
            "/api/audit/anchor/check",
            json={"anchor_text": json.dumps(anchor_data)},
            headers={"X-CSRF-Token": "csrf_test_anchor"},
        )
        assert res_check.status_code == 200
        check_result = res_check.get_json()
        assert check_result["status"] == "success"
        assert check_result["verified"] is True

        # 3. Check Mismatched Anchor (Head Hash forged)
        bad_anchor = dict(anchor_data)
        bad_anchor["head_hash"] = "f" * 64
        res_bad = client.post(
            "/api/audit/anchor/check",
            json={"anchor_text": json.dumps(bad_anchor)},
            headers={"X-CSRF-Token": "csrf_test_anchor"},
        )
        assert res_bad.status_code == 200
        bad_result = res_bad.get_json()
        assert bad_result["status"] == "tampered"
        assert bad_result["verified"] is False

        # 4. Truncate Log (delete last entry from file)
        lines = [l for l in real_log.read_text(encoding="utf-8").splitlines() if l.strip()]
        truncated_lines = lines[:-1]  # 7 entries now
        real_log.write_text("\n".join(truncated_lines) + "\n", encoding="utf-8")

        # Now test active log against the original 8-count anchor
        res_trunc = client.post(
            "/api/audit/anchor/check",
            json={"anchor_text": json.dumps(anchor_data)},
            headers={"X-CSRF-Token": "csrf_test_anchor"},
        )
        assert res_trunc.status_code == 200
        trunc_result = res_trunc.get_json()
        assert trunc_result["status"] == "tampered"
        assert trunc_result["verified"] is False
        assert "COUNT" in trunc_result["message"]
        assert "Expected 8, got 7" in trunc_result["message"]


# =========================================================================
# 8. Tamper Demo Block Statuses (Reset All Green, Edit/Delete Correct Index)
# =========================================================================

def test_tamper_demo_block_statuses_reset_edit_delete(tmp_path, monkeypatch):
    """
    Verifies that:
    - 'reset' produces 100% valid blocks (all green, chain_intact=True).
    - 'edit_line' marks target_idx+1 (block #4) as 'broken' and subsequent as 'orphaned'.
    - 'delete_line' marks target_idx+1 (block #4) as 'broken' and subsequent as 'orphaned'.
    """
    real_log = tmp_path / "blocks_audit.jsonl"
    _create_mock_chain(real_log, count=8)
    monkeypatch.setenv("AEGIS_LOG_FILE", str(real_log))
    security.logger.set_log_file(real_log)

    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["csrf_token"] = "valid_csrf_token"

        # 1. Action: Reset
        res_reset = client.post(
            "/api/audit/tamper_demo",
            json={"action": "reset"},
            headers={"X-CSRF-Token": "valid_csrf_token"},
        )
        assert res_reset.status_code == 200
        data_reset = res_reset.get_json()
        assert data_reset["chain_ok"] is True
        assert data_reset["broken_index"] is None
        assert data_reset["anchor_ok"] is True
        blocks_reset = data_reset["chain_blocks"]
        assert len(blocks_reset) == 6
        assert all(b["status"] == "valid" for b in blocks_reset), f"Expected all green, got {[b['status'] for b in blocks_reset]}"

        # 2. Action: Edit Line (target_idx is 3 -> block #4)
        res_edit = client.post(
            "/api/audit/tamper_demo",
            json={"action": "edit_line"},
            headers={"X-CSRF-Token": "valid_csrf_token"},
        )
        assert res_edit.status_code == 200
        data_edit = res_edit.get_json()
        assert data_edit["chain_ok"] is False
        assert data_edit["broken_index"] == 4
        # Middle edit: chain breaks, but anchor MATCHES because count and newest head hash are unchanged
        assert data_edit["anchor_ok"] is True
        blocks_edit = data_edit["chain_blocks"]
        assert blocks_edit[0]["status"] == "valid"
        assert blocks_edit[1]["status"] == "valid"
        assert blocks_edit[2]["status"] == "valid"
        assert blocks_edit[3]["status"] == "broken", f"Block 4 expected 'broken', got {blocks_edit[3]['status']}"
        assert blocks_edit[4]["status"] == "after_break"
        assert blocks_edit[5]["status"] == "after_break"

        # 3. Action: Delete Line (target_idx is 3 -> block #4)
        res_del = client.post(
            "/api/audit/tamper_demo",
            json={"action": "delete_line"},
            headers={"X-CSRF-Token": "valid_csrf_token"},
        )
        assert res_del.status_code == 200
        data_del = res_del.get_json()
        assert data_del["chain_ok"] is False
        assert data_del["broken_index"] == 4
        assert data_del["anchor_ok"] is False
        blocks_del = data_del["chain_blocks"]
        assert blocks_del[0]["status"] == "valid"
        assert blocks_del[1]["status"] == "valid"
        assert blocks_del[2]["status"] == "valid"
        assert blocks_del[3]["status"] == "broken", f"Block 4 expected 'broken', got {blocks_del[3]['status']}"
        assert blocks_del[4]["status"] == "after_break"

        # 4. Action: Truncate (Chain OK, Anchor Mismatch)
        res_trunc = client.post(
            "/api/audit/tamper_demo",
            json={"action": "truncate"},
            headers={"X-CSRF-Token": "valid_csrf_token"},
        )
        assert res_trunc.status_code == 200
        data_trunc = res_trunc.get_json()
        assert data_trunc["chain_ok"] is True
        assert data_trunc["broken_index"] is None
        assert data_trunc["anchor_ok"] is False
        blocks_trunc = data_trunc["chain_blocks"]
        assert all(b["status"] == "valid" for b in blocks_trunc)

        # 5. Action: Rewrite (Chain OK, Anchor Mismatch)
        res_rewrite = client.post(
            "/api/audit/tamper_demo",
            json={"action": "rewrite"},
            headers={"X-CSRF-Token": "valid_csrf_token"},
        )
        assert res_rewrite.status_code == 200
        data_rewrite = res_rewrite.get_json()
        assert data_rewrite["chain_ok"] is True
        assert data_rewrite["broken_index"] is None
        assert data_rewrite["anchor_ok"] is False
        blocks_rewrite = data_rewrite["chain_blocks"]
        assert all(b["status"] == "valid" for b in blocks_rewrite)

        # 6. Truth Table Matrix for all 5 actions
        expected_table = {
            "reset":       {"chain_ok": True,  "anchor_ok": True},
            "edit_line":   {"chain_ok": False, "anchor_ok": True},
            "delete_line": {"chain_ok": False, "anchor_ok": False},
            "truncate":    {"chain_ok": True,  "anchor_ok": False},
            "rewrite":     {"chain_ok": True,  "anchor_ok": False},
        }

        for act, exp in expected_table.items():
            r = client.post(
                "/api/audit/tamper_demo",
                json={"action": act},
                headers={"X-CSRF-Token": "valid_csrf_token"},
            )
            assert r.status_code == 200
            d = r.get_json()
            assert d["chain_ok"] is exp["chain_ok"], f"Action {act}: expected chain_ok={exp['chain_ok']}, got {d['chain_ok']}"
            assert d["anchor_ok"] is exp["anchor_ok"], f"Action {act}: expected anchor_ok={exp['anchor_ok']}, got {d['anchor_ok']}"


# =========================================================================
# 9. Decision Badges: Informational Events Must Not Show Error
# =========================================================================

def test_decision_badge_classification_no_false_error():
    """
    Verifies that informational events (login success, role switch, intent scope, turn summary)
    map to INFO, and only genuine failures/blocks map to ERROR/BLOCKED.
    """
    # 1. Informational lifecycle events
    assert classify_audit_decision({"event": "login_success", "username": "admin"}) == "INFO"
    assert classify_audit_decision({"event": "role_change", "old_role": "guest", "new_role": "admin"}) == "INFO"
    assert classify_audit_decision({"event": "intent_scope", "scope": ["unlock_door"]}) == "INFO"
    assert classify_audit_decision({"event": "turn_summary", "decision": ""}) == "INFO"
    assert classify_audit_decision({"event": "turn_summary"}) == "INFO"

    # 2. Genuine errors and security failures
    assert classify_audit_decision({"event": "login_failure", "username": "attacker"}) == "ERROR"
    assert classify_audit_decision({"event": "execution_error", "error": "Crash"}) == "ERROR"
    assert classify_audit_decision({"event": "hardware_command", "command": "unlock", "ok": False}) == "ERROR"

    # 3. Policy decisions
    assert classify_audit_decision({"event": "tool_call", "decision": "ALLOW"}) == "ALLOWED"
    assert classify_audit_decision({"event": "tool_call", "decision": "BLOCK"}) == "BLOCKED"
    assert classify_audit_decision({"event": "approval_request", "decision": "REVIEW"}) == "WAITING"


# =========================================================================
# 10. Tamper Demo: Corrupted JSON Line Returns Clean 400 (Not 500)
# =========================================================================

def test_tamper_demo_corrupted_json_returns_clean_400(tmp_path, monkeypatch):
    """
    Verifies that if a line in the log contains corrupted non-JSON data,
    the tamper demo returns HTTP 400 Bad Request with a clean error message, not 500.
    """
    corrupt_log = tmp_path / "corrupt_audit.jsonl"
    corrupt_log.write_text("{\"valid\": 1}\nCORRUPTED_NON_JSON_LINE\n{\"valid\": 2}\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_LOG_FILE", str(corrupt_log))
    security.logger.set_log_file(corrupt_log)

    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["csrf_token"] = "valid_csrf_token"

        res = client.post(
            "/api/audit/tamper_demo",
            json={"action": "reset"},
            headers={"X-CSRF-Token": "valid_csrf_token"},
        )
        assert res.status_code == 400
        data = res.get_json()
        assert data["status"] == "error"
        assert "invalid JSON" in data["message"]


# =========================================================================
# 11. Attack Lab Source Tag: Every Entry Carries source=attack_lab
# =========================================================================

def test_attack_lab_all_entries_carry_attack_lab_source(tmp_path, monkeypatch):
    """
    Verifies that during an attack lab simulation run, EVERY audit entry written
    carries source='attack_lab', without breaking the cryptographic hash chain.
    """
    lab_log = tmp_path / "attack_lab_audit.jsonl"
    monkeypatch.setenv("AEGIS_LOG_FILE", str(lab_log))
    security.logger.set_log_file(lab_log)

    sc = security.attack_lab.SCENARIOS[0]  # direct_override
    res = security.attack_lab.run_protected(sc, scratch_dir=tmp_path)
    assert res["stopped_at"] == "detection"

    lines = [json.loads(l) for l in lab_log.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) >= 4, f"Expected at least 4 entries, got {len(lines)}"

    # Assert EVERY line has source == "attack_lab"
    for idx, entry in enumerate(lines, 1):
        assert entry.get("source") == "attack_lab", f"Line {idx} ({entry.get('event')}) has source={entry.get('source')}"

    # Assert hash chain is 100% valid
    is_intact, verify_msg = check_audit_log_status(lab_log)
    assert is_intact is True, f"Hash chain broken: {verify_msg}"


# =========================================================================
# 12. Attack Lab Isolation: Normal Request After Lab Run NOT Tagged attack_lab
# =========================================================================

def test_post_lab_run_isolation_not_tagged_attack_lab(tmp_path, monkeypatch):
    """
    Verifies that a normal request handled right after an attack lab run
    is NOT tagged 'attack_lab' (source reverts cleanly to 'real').
    """
    isolation_log = tmp_path / "isolation_audit.jsonl"
    monkeypatch.setenv("AEGIS_LOG_FILE", str(isolation_log))
    security.logger.set_log_file(isolation_log)

    # 1. Run lab simulation
    sc = security.attack_lab.SCENARIOS[0]
    security.attack_lab.run_protected(sc, scratch_dir=tmp_path)

    # 2. Immediately log normal activity outside the lab context
    security.logger.log_event("user_status_check", {"user": "admin", "source": "real"})

    lines = [json.loads(l) for l in isolation_log.read_text(encoding="utf-8").splitlines() if l.strip()]
    last_entry = lines[-1]

    assert last_entry.get("event") == "user_status_check"
    assert last_entry.get("source") != "attack_lab"
    assert last_entry.get("source") == "real"


# =========================================================================
# 13. Rendered /audit HTML & Assets Contain No Overclaims
# =========================================================================

def test_rendered_audit_page_no_overclaims(tmp_path, monkeypatch):
    """
    Verifies that the rendered /audit HTML page, loaded scripts, and README
    contain none of the forbidden overclaim words:
    immutable, merkle, tamper-proof, guarantee, or 'instantly'.
    """
    test_log = tmp_path / "overclaim_test.jsonl"
    _create_mock_chain(test_log, count=5)
    monkeypatch.setenv("AEGIS_LOG_FILE", str(test_log))
    security.logger.set_log_file(test_log)

    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["csrf_token"] = "valid_csrf"

        res = client.get("/audit")
        assert res.status_code == 200
        html = res.data.decode("utf-8")

    forbidden = ["immutable", "merkle", "tamper-proof", "guarantee", "instantly"]
    for word in forbidden:
        assert word not in html.lower(), f"Forbidden word '{word}' found in rendered /audit HTML!"

    # Verify README.md has no 'guarantee'
    readme_text = Path("README.md").read_text(encoding="utf-8").lower()
    assert "guarantee" not in readme_text, "Found 'guarantee' in README.md!"


# =========================================================================
# 14. Server-Side Categorization: Entries Include 'category'
# =========================================================================

def test_entries_contain_category_from_server(tmp_path, monkeypatch):
    """
    Verifies that the server populates 'category' on each entry so the frontend
    does not need to duplicate categorization logic.
    """
    test_log = tmp_path / "category_test.jsonl"
    _create_mock_chain(test_log, count=5)
    monkeypatch.setenv("AEGIS_LOG_FILE", str(test_log))
    security.logger.set_log_file(test_log)

    items, _, _ = read_entries_reverse(test_log, limit=10, offset=0)
    assert len(items) == 5
    for item in items:
        assert "category" in item
        assert item["category"] in ("ALLOWED", "BLOCKED", "WAITING", "ERROR", "INFO")
