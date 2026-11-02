import json
import hashlib
from pathlib import Path
import pytest
from security.verify_log import (
    create_anchor,
    export_anchor_line,
    check_anchor_line,
    check_audit_log_status,
    verify_external_anchor,
)


def _append_entry(log_file: Path, data: dict, prev_hash: str) -> str:
    serialized = json.dumps(data, sort_keys=True)
    payload = serialized + prev_hash
    entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    entry = dict(data)
    entry["prev_hash"] = prev_hash
    entry["entry_hash"] = entry_hash
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry_hash


def _build_log(log_file: Path, num_entries: int = 3) -> str:
    prev_hash = "0" * 64
    for i in range(1, num_entries + 1):
        prev_hash = _append_entry(log_file, {"turn": i, "event": f"event_{i}"}, prev_hash)
    return prev_hash


def test_anchor_then_append_two_entries_verified(tmp_path):
    """(1) Anchor created at 3 entries, then 2 new entries appended -> both anchor and full chain verified."""
    log_file = tmp_path / "audit.jsonl"
    anchor_file = tmp_path / "audit.anchor.json"

    # 1. Build initial 3 entries
    h3 = _build_log(log_file, num_entries=3)
    create_anchor(log_file, anchor_file)
    anchor_line = export_anchor_line(log_file)

    # 2. Append 2 valid chained entries
    h4 = _append_entry(log_file, {"turn": 4, "event": "event_4"}, h3)
    _append_entry(log_file, {"turn": 5, "event": "event_5"}, h4)

    # Verify both anchor file and anchor line
    ok_status, msg_status = check_audit_log_status(log_file, anchor_file=anchor_file)
    assert ok_status is True, f"Full chain + anchor verification failed: {msg_status}"

    ok_line, msg_line = check_anchor_line(anchor_line, log_file)
    assert ok_line is True, f"Anchor line check failed: {msg_line}"
    assert "Historical anchor verified at entry 3 (2 newer entries appended since anchor)" in msg_line


def test_tamper_entry_hash_at_or_before_anchor_fails(tmp_path):
    """(2) Change an entry_hash at or before anchor index -> caught by verify_log."""
    log_file = tmp_path / "audit.jsonl"
    anchor_file = tmp_path / "audit.anchor.json"

    h3 = _build_log(log_file, num_entries=3)
    create_anchor(log_file, anchor_file)
    anchor_line = export_anchor_line(log_file)

    # Append 2 entries
    h4 = _append_entry(log_file, {"turn": 4, "event": "event_4"}, h3)
    _append_entry(log_file, {"turn": 5, "event": "event_5"}, h4)

    # Tamper with line 2
    lines = log_file.read_text(encoding="utf-8").splitlines()
    entry2 = json.loads(lines[1])
    entry2["entry_hash"] = "f" * 64
    lines[1] = json.dumps(entry2)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok_status, msg_status = check_audit_log_status(log_file, anchor_file=anchor_file)
    assert ok_status is False
    assert "LOG TAMPERED AT LINE 2" in msg_status


def test_delete_lines_so_count_less_than_anchor_fails(tmp_path):
    """(3) Delete lines so actual count < anchor count -> fails with count mismatch/truncation."""
    log_file = tmp_path / "audit.jsonl"
    anchor_file = tmp_path / "audit.anchor.json"

    _build_log(log_file, num_entries=4)
    create_anchor(log_file, anchor_file)
    anchor_line = export_anchor_line(log_file)

    # Truncate to 2 lines (< 4)
    lines = log_file.read_text(encoding="utf-8").splitlines()[:2]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok_status, msg_status = check_audit_log_status(log_file, anchor_file=anchor_file)
    assert ok_status is False
    assert "COUNT" in msg_status or "truncation" in msg_status.lower()

    ok_line, msg_line = check_anchor_line(anchor_line, log_file)
    assert ok_line is False
    assert "ANCHOR MISMATCH (COUNT)" in msg_line


def test_wrong_head_hash_fails(tmp_path):
    """(4) Anchor with wrong head hash -> fails head_hash mismatch."""
    log_file = tmp_path / "audit.jsonl"
    anchor_file = tmp_path / "audit.anchor.json"

    _build_log(log_file, num_entries=3)
    create_anchor(log_file, anchor_file)

    # Tamper with the anchor file to have wrong head hash
    anchor_data = json.loads(anchor_file.read_text(encoding="utf-8"))
    anchor_data["head_hash"] = "e" * 64
    anchor_file.write_text(json.dumps(anchor_data), encoding="utf-8")

    ok_status, msg_status = check_audit_log_status(log_file, anchor_file=anchor_file)
    assert ok_status is False
    assert "HEAD_HASH" in msg_status or "rewrite" in msg_status.lower()

    # Also test check_anchor_line with wrong head hash
    bad_anchor_line = "ANCHOR:count=3:head_hash=" + ("e" * 64)
    ok_line, msg_line = check_anchor_line(bad_anchor_line, log_file)
    assert ok_line is False
    assert "ANCHOR MISMATCH (HEAD_HASH)" in msg_line

