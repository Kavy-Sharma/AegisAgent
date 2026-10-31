"""
Tamper Demo on a COPY of the audit log.
Tests 5 distinct tampering scenarios:
1. Edit payload of middle line
2. Delete middle line
3. Delete last N lines (truncation)
4. Reorder lines (swap adjacent lines)
5. Rewrite past line and recompute forward hashes
Demonstrates failure modes with and without external anchor.
"""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from security.verify_log import (
    check_audit_log_status,
    create_anchor,
    verify_external_anchor,
)
import security.logger


def run_demo():
    print("=" * 70)
    print("PHASE B - AUDIT LOG CRYPTOGRAPHIC TAMPER DEMONSTRATION")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        orig_log = security.logger.get_log_file()

        # If original log doesn't exist or has < 5 lines, create synthetic sample
        test_log = tmp_path / "audit_copy.jsonl"
        prev_hash = "0" * 64
        print(f"[*] Generating 10 sample audit events in {test_log.name}...")
        for i in range(1, 11):
            entry_data = {
                "event": f"audit_sample_event_{i}",
                "turn": i,
                "actor": "admin" if i % 2 == 0 else "operator",
                "action": "turn_light_on" if i % 2 == 0 else "read_temperature",
            }
            serialized = json.dumps(entry_data, sort_keys=True)
            payload = serialized + prev_hash
            entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            entry = dict(entry_data)
            entry["prev_hash"] = prev_hash
            entry["entry_hash"] = entry_hash
            with open(test_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            prev_hash = entry_hash

        # Establish External Anchor
        anchor_file = tmp_path / "audit_copy.anchor.json"
        anchor_data = create_anchor(test_log, anchor_file)
        print(f"[*] Created external anchor: count={anchor_data['count']}, head_hash={anchor_data['head_hash'][:16]}...\n")

        # Baseline verification
        ok, msg = check_audit_log_status(test_log, anchor_file=anchor_file)
        print(f"[Baseline] Untampered log verification: {'PASS' if ok else 'FAIL'} ({msg})\n")

        # Attack 1: Edit payload of middle line (Line 5)
        print("--- Scenario 1: Edit Payload in Middle Line (Line 5) ---")
        tamper_1 = tmp_path / "tamper_edit.jsonl"
        lines = test_log.read_text(encoding="utf-8").splitlines()
        e5 = json.loads(lines[4])
        e5["actor"] = "malicious_hacker"
        lines[4] = json.dumps(e5)
        tamper_1.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, msg = check_audit_log_status(tamper_1)
        print(f"  Internal Chain Result: {'DETECTED' if not ok else 'MISSED'}")
        print(f"  Status: {msg}\n")

        # Attack 2: Delete middle line (Line 5)
        print("--- Scenario 2: Delete Middle Line (Line 5) ---")
        tamper_2 = tmp_path / "tamper_delete_middle.jsonl"
        lines = test_log.read_text(encoding="utf-8").splitlines()
        del lines[4]
        tamper_2.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, msg = check_audit_log_status(tamper_2)
        print(f"  Internal Chain Result: {'DETECTED' if not ok else 'MISSED'}")
        print(f"  Status: {msg}\n")

        # Attack 3: Reorder lines (Swap line 4 and 5)
        print("--- Scenario 3: Reorder Adjacent Lines (Swap Lines 4 and 5) ---")
        tamper_3 = tmp_path / "tamper_reorder.jsonl"
        lines = test_log.read_text(encoding="utf-8").splitlines()
        lines[3], lines[4] = lines[4], lines[3]
        tamper_3.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, msg = check_audit_log_status(tamper_3)
        print(f"  Internal Chain Result: {'DETECTED' if not ok else 'MISSED'}")
        print(f"  Status: {msg}\n")

        # Attack 4: Delete last N lines (Truncation - drop lines 8, 9, 10)
        print("--- Scenario 4: Truncate Last 3 Lines (Delete Suffix) ---")
        tamper_4 = tmp_path / "tamper_truncate.jsonl"
        lines = test_log.read_text(encoding="utf-8").splitlines()
        lines = lines[:7]
        tamper_4.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok_no_anchor, msg_no = check_audit_log_status(tamper_4)
        print(f"  Internal Chain (Without Anchor): {'DETECTED' if not ok_no_anchor else 'MISSED (Chain valid)'}")
        print(f"  Status: {msg_no}")
        ok_anchor, msg_anchor = check_audit_log_status(tamper_4, anchor_file=anchor_file)
        print(f"  With External Anchor: {'DETECTED' if not ok_anchor else 'MISSED'}")
        print(f"  Status: {msg_anchor}\n")

        # Attack 5: Rewrite Line 3 and Recompute All Subsequent Hashes
        print("--- Scenario 5: Rewrite Line 3 and Recompute Downstream Hashes ---")
        tamper_5 = tmp_path / "tamper_rewrite.jsonl"
        lines = test_log.read_text(encoding="utf-8").splitlines()
        entries = [json.loads(l) for l in lines]
        entries[2]["actor"] = "covert_operator"
        # Recompute downstream
        curr_prev = entries[1]["entry_hash"]
        for j in range(2, len(entries)):
            entries[j]["prev_hash"] = curr_prev
            clean = {k: v for k, v in entries[j].items() if k not in ("prev_hash", "entry_hash")}
            curr_hash = hashlib.sha256((json.dumps(clean, sort_keys=True) + curr_prev).encode("utf-8")).hexdigest()
            entries[j]["entry_hash"] = curr_hash
            curr_prev = curr_hash
        tamper_5.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
        ok_no_anchor, msg_no = check_audit_log_status(tamper_5)
        print(f"  Internal Chain (Without Anchor): {'DETECTED' if not ok_no_anchor else 'MISSED (Chain recomputed validly)'}")
        print(f"  Status: {msg_no}")
        ok_anchor, msg_anchor = check_audit_log_status(tamper_5, anchor_file=anchor_file)
        print(f"  With External Anchor: {'DETECTED' if not ok_anchor else 'MISSED'}")
        print(f"  Status: {msg_anchor}\n")

    print("=" * 70)
    print("TAMPER DEMO COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()

