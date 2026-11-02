"""
Phase 4 & Phase 8A -- Audit Log Verifier

WHAT THIS FILE DOES:
Reads logs/audit_log.jsonl (or specified log file) line-by-line, recomputing SHA-256
hashes and verifying the cryptographic chain of custody.
Prints "LOG INTACT" or identifies tampered lines.
Supports external anchoring and verification to detect truncation and history rewrite.
"""

import argparse
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

    if actual_count < expected_count:
        return False, f"ANCHOR MISMATCH (COUNT): Expected {expected_count} entries, found {actual_count} (truncation or missing entries detected)"

    anchor_entry_hash = "0" * 64
    if expected_count > 0 and len(lines) >= expected_count:
        try:
            anchor_entry = json.loads(lines[expected_count - 1])
            anchor_entry_hash = anchor_entry.get("entry_hash", "0" * 64)
        except Exception:
            anchor_entry_hash = "0" * 64

    if anchor_entry_hash != expected_head_hash:
        return False, f"ANCHOR MISMATCH (HEAD_HASH): Expected head hash '{expected_head_hash}', got '{anchor_entry_hash}' (rewrite or history modification detected)"

    return True, "ANCHOR VERIFIED"


def export_anchor_line(log_file: Path | str | None = None) -> str:
    """Returns a single-line external anchor string to copy elsewhere."""
    p = Path(log_file) if log_file else security.logger.get_log_file()
    anchor = create_anchor(p)
    return f"ANCHOR:count={anchor['count']}:head_hash={anchor['head_hash']}"


def check_anchor_line(line: str, log_file: Path | str | None = None) -> tuple[bool, str]:
    """Verifies that the audit log matches a pasted one-line anchor string."""
    p = Path(log_file) if log_file else security.logger.get_log_file()
    ok_chain, msg_chain = check_audit_log_status(p)
    if not ok_chain:
        return False, f"CHAIN INTEGRITY FAILED: {msg_chain}"

    clean = line.strip()
    if clean.startswith("ANCHOR:"):
        clean = clean[len("ANCHOR:"):].strip()

    expected_count = None
    expected_head = None

    if clean.startswith("{"):
        try:
            data = json.loads(clean)
            expected_count = int(data.get("count"))
            expected_head = data.get("head_hash")
        except Exception:
            pass
    else:
        parts = clean.split(":")
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                k = k.strip()
                v = v.strip()
                if k == "count":
                    try:
                        expected_count = int(v)
                    except ValueError:
                        pass
                elif k == "head_hash":
                    expected_head = v

    if expected_count is None or expected_head is None:
        return False, f"INVALID ANCHOR FORMAT: could not parse count and head_hash from '{line}'"

    if not p.exists():
        actual_count = 0
        actual_head = "0" * 64
        lines = []
    else:
        with security.logger._file_lock(p):
            lines = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
        actual_count = len(lines)
        actual_head = json.loads(lines[-1]).get("entry_hash") if actual_count > 0 else "0" * 64

    if actual_count < expected_count:
        return False, f"ANCHOR MISMATCH (COUNT): Expected {expected_count}, got {actual_count}"

    # Verify that the entry hash at the anchor snapshot index matches the expected head hash
    anchor_entry_hash = "0" * 64
    if expected_count > 0 and len(lines) >= expected_count:
        try:
            anchor_entry = json.loads(lines[expected_count - 1])
            anchor_entry_hash = anchor_entry.get("entry_hash", "0" * 64)
        except Exception:
            anchor_entry_hash = "0" * 64

    if anchor_entry_hash != expected_head:
        return False, f"ANCHOR MISMATCH (HEAD_HASH): Expected '{expected_head}', got '{anchor_entry_hash}'"

    if actual_count == expected_count:
        return True, f"ANCHOR VERIFIED: Log matches external anchor (count: {actual_count}, head_hash: {actual_head})"
    else:
        appended_entries = actual_count - expected_count
        return True, f"ANCHOR VERIFIED: Historical anchor verified at entry {expected_count} ({appended_entries} newer entries appended since anchor)"


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
    p = Path(log_file) if log_file else security.logger.get_log_file()
    count = 0
    head_hash = "0" * 64
    if p.exists():
        with security.logger._file_lock(p):
            content = p.read_text(encoding="utf-8").strip()
        lines = [l for l in content.splitlines() if l.strip()]
        count = len(lines)
        if count > 0:
            try:
                head_hash = json.loads(lines[-1]).get("entry_hash", "0" * 64)
            except Exception:
                head_hash = "CORRUPT"

    ok, msg = check_audit_log_status(log_file, anchor_file=anchor_file)
    print(f"{msg} (count: {count}, head_hash: {head_hash})")
    return ok


def __getattr__(name):
    if name == "LOG_FILE":
        return security.logger.get_log_file()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cryptographic Audit Log Verifier")
    parser.add_argument("--export-anchor", action="store_true", help="Print a one-line anchor to copy elsewhere")
    parser.add_argument("--check-anchor", type=str, default=None, help="Verify audit log against a pasted anchor string")
    parser.add_argument("--log-file", type=str, default=None, help="Path to audit log file")
    args = parser.parse_args()

    if args.export_anchor:
        print(export_anchor_line(args.log_file))
    elif args.check_anchor:
        ok, msg = check_anchor_line(args.check_anchor, args.log_file)
        print(msg)
        sys.exit(0 if ok else 1)
    else:
        ok = verify_audit_log(args.log_file)
        sys.exit(0 if ok else 1)
