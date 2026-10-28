"""
Phase 4 & Phase 8A -- Audit Log Verifier

WHAT THIS FILE DOES:
Reads logs/audit_log.jsonl (or specified log file) line-by-line, recomputing SHA-256
hashes and verifying the cryptographic chain of custody.
Prints "LOG INTACT" or identifies tampered lines.
"""

import hashlib
import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import security.logger


def check_audit_log_status(log_file: Path | str | None = None) -> tuple[bool, str]:
    """Verifies audit log integrity and returns (is_intact, status_message)."""
    if log_file is None:
        log_file = security.logger.get_log_file()
    else:
        log_file = Path(log_file)

    if not log_file.exists():
        return False, "LOG FILE NOT FOUND"

    content = log_file.read_text(encoding="utf-8").strip()
    if not content:
        return True, "LOG INTACT"

    lines = content.splitlines()
    expected_prev_hash = "0" * 64

    for line_num, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, f"LOG TAMPERED AT LINE {line_num}: Invalid JSON syntax"

        stored_prev_hash = entry.get("prev_hash")
        stored_entry_hash = entry.get("entry_hash")

        if stored_prev_hash != expected_prev_hash:
            return False, (
                f"LOG TAMPERED AT LINE {line_num}: prev_hash mismatch. "
                f"Expected '{expected_prev_hash}', got '{stored_prev_hash}'"
            )

        entry_without_hash_fields = {k: v for k, v in entry.items() if k not in ("prev_hash", "entry_hash")}

        serialized_data = json.dumps(entry_without_hash_fields, sort_keys=True)
        payload = serialized_data + stored_prev_hash
        computed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        if computed_hash != stored_entry_hash:
            return False, (
                f"LOG TAMPERED AT LINE {line_num}: entry_hash mismatch. "
                f"Computed '{computed_hash}', got '{stored_entry_hash}'"
            )

        expected_prev_hash = stored_entry_hash

    return True, "LOG INTACT"


def verify_audit_log(log_file: Path | str | None = None) -> bool:
    """Verifies audit log integrity by validating cryptographic hash chain."""
    ok, msg = check_audit_log_status(log_file)
    print(msg)
    return ok


def __getattr__(name):
    if name == "LOG_FILE":
        return security.logger.get_log_file()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    verify_audit_log()
