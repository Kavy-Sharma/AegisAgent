"""
Phase 4 — Audit Log Verifier

WHAT THIS FILE DOES:
Reads logs/audit_log.jsonl line-by-line, recomputing SHA-256 hashes and verifying
the cryptographic chain of custody. Prints "LOG INTACT" or identifies tampered lines.
"""

import hashlib
import json
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "audit_log.jsonl"


def verify_audit_log() -> bool:
    """Verifies audit log integrity by validating cryptographic hash chain."""
    if not LOG_FILE.exists():
        print("LOG FILE NOT FOUND")
        return False

    content = LOG_FILE.read_text(encoding="utf-8").strip()
    if not content:
        print("LOG INTACT")
        return True

    lines = content.splitlines()
    expected_prev_hash = "0" * 64

    for line_num, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            print(f"LOG TAMPERED AT LINE {line_num}: Invalid JSON syntax")
            return False

        stored_prev_hash = entry.get("prev_hash")
        stored_entry_hash = entry.get("entry_hash")

        if stored_prev_hash != expected_prev_hash:
            print(
                f"LOG TAMPERED AT LINE {line_num}: prev_hash mismatch. "
                f"Expected '{expected_prev_hash}', got '{stored_prev_hash}'"
            )
            return False

        entry_without_hash_fields = {
            "args": entry.get("args"),
            "decision": entry.get("decision"),
            "reason": entry.get("reason"),
            "risk": entry.get("risk"),
            "role": entry.get("role"),
            "timestamp": entry.get("timestamp"),
            "tool": entry.get("tool"),
        }

        serialized_data = json.dumps(entry_without_hash_fields, sort_keys=True)
        payload = serialized_data + stored_prev_hash
        computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        if computed_hash != stored_entry_hash:
            print(
                f"LOG TAMPERED AT LINE {line_num}: entry_hash mismatch. "
                f"Computed '{computed_hash}', got '{stored_entry_hash}'"
            )
            return False

        expected_prev_hash = stored_entry_hash

    print("LOG INTACT")
    return True


if __name__ == "__main__":
    verify_audit_log()
