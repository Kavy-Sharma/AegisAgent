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


def create_anchor(log_file: Path | str | None = None, anchor_file: Path | str | None = None) -> dict:
    """Computes and writes an external anchor {count, head_hash} for the given log file."""
    if log_file is None:
        log_file = security.logger.get_log_file()
    else:
        log_file = Path(log_file)

    if anchor_file is None:
        anchor_file = log_file.parent / f"{log_file.stem}.anchor.json"
    else:
        anchor_file = Path(anchor_file)

    anchor_file.parent.mkdir(parents=True, exist_ok=True)

    if not log_file.exists():
        anchor_data = {"count": 0, "head_hash": "0" * 64}
    else:
        with security.logger._file_lock(log_file):
            content = log_file.read_text(encoding="utf-8").strip()
        if not content:
            anchor_data = {"count": 0, "head_hash": "0" * 64}
        else:
            lines = [l for l in content.splitlines() if l.strip()]
            count = len(lines)
            last_entry = json.loads(lines[-1])
            head_hash = last_entry.get("entry_hash", "0" * 64)
            anchor_data = {"count": count, "head_hash": head_hash}

    anchor_file.write_text(json.dumps(anchor_data, indent=2) + "\n", encoding="utf-8")
    return anchor_data


def verify_external_anchor(log_file: Path | str | None = None, anchor_file: Path | str | None = None) -> tuple[bool, str]:
    """Verifies that the log file matches the external anchor count and head_hash."""
    if log_file is None:
        log_file = security.logger.get_log_file()
    else:
        log_file = Path(log_file)

    if anchor_file is None:
        anchor_file = log_file.parent / f"{log_file.stem}.anchor.json"
    else:
        anchor_file = Path(anchor_file)

    if not anchor_file.exists():
        return False, "ANCHOR FILE NOT FOUND"

    try:
        anchor_data = json.loads(anchor_file.read_text(encoding="utf-8"))
    except Exception:
        return False, "INVALID ANCHOR JSON"

    expected_count = anchor_data.get("count", 0)
    expected_head_hash = anchor_data.get("head_hash")

    if not log_file.exists():
        actual_count = 0
        actual_head_hash = "0" * 64
    else:
        with security.logger._file_lock(log_file):
            content = log_file.read_text(encoding="utf-8").strip()
        lines = [l for l in content.splitlines() if l.strip()]
        actual_count = len(lines)
        if actual_count > 0:
            try:
                actual_head_hash = json.loads(lines[-1]).get("entry_hash")
            except Exception:
                return False, "CORRUPT LAST LOG LINE"
        else:
            actual_head_hash = "0" * 64

    if actual_count != expected_count:
        return False, f"ANCHOR MISMATCH (COUNT): Expected {expected_count} entries, found {actual_count} (truncation or missing entries detected)"

    if actual_head_hash != expected_head_hash:
        return False, f"ANCHOR MISMATCH (HEAD_HASH): Expected head hash '{expected_head_hash}', got '{actual_head_hash}' (rewrite or history modification detected)"

    return True, "ANCHOR VERIFIED"


def check_audit_log_status(log_file: Path | str | None = None, anchor_file: Path | str | None = None) -> tuple[bool, str]:
    """Verifies audit log integrity and returns (is_intact, status_message)."""
    if log_file is None:
        log_file = security.logger.get_log_file()
    else:
        log_file = Path(log_file)

    if not log_file.exists():
        return False, "LOG FILE NOT FOUND"

    with security.logger._file_lock(log_file):
        content = log_file.read_text(encoding="utf-8").strip()
    if not content:
        if anchor_file is not None:
            anchor_ok, anchor_msg = verify_external_anchor(log_file, anchor_file)
            if not anchor_ok:
                return False, f"LOG TAMPERED: {anchor_msg}"
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

    if anchor_file is not None:
        anchor_ok, anchor_msg = verify_external_anchor(log_file, anchor_file)
        if not anchor_ok:
            return False, f"LOG TAMPERED: {anchor_msg}"

    return True, "LOG INTACT"


def verify_audit_log(log_file: Path | str | None = None, anchor_file: Path | str | None = None) -> bool:
    """Verifies audit log integrity by validating cryptographic hash chain."""
    ok, msg = check_audit_log_status(log_file, anchor_file=anchor_file)
    print(msg)
    return ok


def __getattr__(name):
    if name == "LOG_FILE":
        return security.logger.get_log_file()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    verify_audit_log()
