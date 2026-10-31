import json
import hashlib
from pathlib import Path
import pytest
import security.logger
from security.verify_log import (
    check_audit_log_status,
    create_anchor,
    verify_external_anchor,
)


@pytest.fixture
def sample_log(tmp_path):
    """Creates a valid 5-entry audit log for testing."""
    log_file = tmp_path / "test_audit.jsonl"
    prev_hash = "0" * 64
    for i in range(1, 6):
        entry_data = {
            "event": f"test_event_{i}",
            "turn": i,
            "user": "test_user",
        }
        serialized = json.dumps(entry_data, sort_keys=True)
        payload = serialized + prev_hash
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        entry = dict(entry_data)
        entry["prev_hash"] = prev_hash
        entry["entry_hash"] = entry_hash
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        prev_hash = entry_hash
    return log_file


def test_tamper_edit_middle_line_detected(sample_log, tmp_path):
    """Scenario 1: Edit payload of line 3 -> caught by entry_hash mismatch."""
    tampered = tmp_path / "tampered_edit.jsonl"
    lines = sample_log.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    entry["user"] = "attacker"
    lines[2] = json.dumps(entry)
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = check_audit_log_status(tampered)
    assert not ok
    assert "LOG TAMPERED AT LINE 3" in msg


def test_tamper_delete_middle_line_detected(sample_log, tmp_path):
    """Scenario 2: Delete line 3 -> caught by prev_hash mismatch on line 3 (formerly line 4)."""
    tampered = tmp_path / "tampered_delete.jsonl"
    lines = sample_log.read_text(encoding="utf-8").splitlines()
    del lines[2]
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = check_audit_log_status(tampered)
    assert not ok
    assert "prev_hash mismatch" in msg


def test_tamper_reorder_lines_detected(sample_log, tmp_path):
    """Scenario 3: Swap lines 2 and 3 -> caught by hash mismatch."""
    tampered = tmp_path / "tampered_reorder.jsonl"
    lines = sample_log.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = check_audit_log_status(tampered)
    assert not ok
    assert "LOG TAMPERED" in msg


def test_tamper_truncation_detected_by_external_anchor(sample_log, tmp_path):
    """Scenario 4: Truncate last 2 lines. Without anchor chain is valid; with anchor it fails."""
    anchor_file = tmp_path / "test_audit.anchor.json"
    create_anchor(sample_log, anchor_file)

    tampered = tmp_path / "tampered_trunc.jsonl"
    lines = sample_log.read_text(encoding="utf-8").splitlines()
    lines = lines[:3]  # keep first 3 of 5
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Without anchor, internal chain of 1..3 is intact
    ok_no_anchor, _ = check_audit_log_status(tampered)
    assert ok_no_anchor is True, "Internal chain alone should not detect truncation of suffix"

    # With anchor, truncation is detected
    ok_anchor, anchor_msg = check_audit_log_status(tampered, anchor_file=anchor_file)
    assert ok_anchor is False
    assert "COUNT" in anchor_msg or "truncation" in anchor_msg.lower()


def test_tamper_rewrite_and_recompute_detected_by_anchor(sample_log, tmp_path):
    """Scenario 5: Modify line 2 and recompute all downstream hashes. Anchor detects head mismatch."""
    anchor_file = tmp_path / "test_audit.anchor.json"
    create_anchor(sample_log, anchor_file)

    tampered = tmp_path / "tampered_rewrite.jsonl"
    lines = sample_log.read_text(encoding="utf-8").splitlines()
    entries = [json.loads(l) for l in lines]
    entries[1]["user"] = "attacker"

    # Recompute hashes from line 2 to 5
    prev_hash = entries[0]["entry_hash"]
    for i in range(1, len(entries)):
        entries[i]["prev_hash"] = prev_hash
        data_clean = {k: v for k, v in entries[i].items() if k not in ("prev_hash", "entry_hash")}
        payload = json.dumps(data_clean, sort_keys=True) + prev_hash
        entries[i]["entry_hash"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        prev_hash = entries[i]["entry_hash"]

    tampered.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

    # Without anchor, internal chain was legitimately recomputed
    ok_no_anchor, _ = check_audit_log_status(tampered)
    assert ok_no_anchor is True

    # With anchor, head_hash mismatch is detected
    ok_anchor, anchor_msg = check_audit_log_status(tampered, anchor_file=anchor_file)
    assert ok_anchor is False
    assert "HEAD_HASH" in anchor_msg or "rewrite" in anchor_msg.lower()

