"""
Phase 4 — Tamper-Evident Audit Logger

WHAT THIS FILE DOES:
Appends decision logs to logs/audit_log.jsonl using a SHA-256 hash chain.
Each log line includes a cryptographic hash of its contents plus the previous line's hash.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

# Path to audit_log.jsonl
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_FILE = LOG_DIR / "audit_log.jsonl"


def _get_last_entry_hash() -> str:
    """Returns the entry_hash of the last line in audit_log.jsonl, or '0'*64 if empty/missing."""
    if not LOG_FILE.exists():
        return "0" * 64

    lines = LOG_FILE.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        return "0" * 64

    try:
        last_entry = json.loads(lines[-1])
        return last_entry.get("entry_hash", "0" * 64)
    except Exception:
        return "0" * 64


def log_decision(
    tool: str,
    args: dict,
    role: str,
    risk: str | None,
    decision: str,
    reason: str,
) -> dict:
    """
    Constructs a tamper-evident audit log entry and appends it to logs/audit_log.jsonl.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).isoformat()
    prev_hash = _get_last_entry_hash()

    entry_without_hash_fields = {
        "args": args,
        "decision": decision,
        "reason": reason,
        "risk": risk,
        "role": role,
        "timestamp": timestamp_str,
        "tool": tool,
    }

    serialized_data = json.dumps(entry_without_hash_fields, sort_keys=True)
    payload = serialized_data + prev_hash
    entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    log_entry = {
        "timestamp": timestamp_str,
        "tool": tool,
        "args": args,
        "role": role,
        "risk": risk,
        "decision": decision,
        "reason": reason,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
    }

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

    return log_entry


def log_injection_check(
    session_id: str,
    source: str,
    decision: str,
    score: float,
    rule_ids: list[str],
    text: str,
) -> dict:
    """
    Constructs a tamper-evident audit log entry for prompt injection check.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).isoformat()
    prev_hash = _get_last_entry_hash()

    entry_without_hash_fields = {
        "decision": decision,
        "event": "injection_check",
        "rule_ids": rule_ids,
        "score": score,
        "session_id": session_id,
        "source": source,
        "text": text[:200],
        "timestamp": timestamp_str,
    }

    serialized_data = json.dumps(entry_without_hash_fields, sort_keys=True)
    payload = serialized_data + prev_hash
    entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    log_entry = dict(entry_without_hash_fields)
    log_entry["prev_hash"] = prev_hash
    log_entry["entry_hash"] = entry_hash

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

    return log_entry


def log_engine_error(
    session_id: str,
    source: str,
    error: str,
    text: str,
) -> dict:
    """
    Constructs a tamper-evident audit log entry for detection engine error.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.now(timezone.utc).isoformat()
    prev_hash = _get_last_entry_hash()

    entry_without_hash_fields = {
        "error": error,
        "event": "engine_error",
        "session_id": session_id,
        "source": source,
        "text": text[:200],
        "timestamp": timestamp_str,
    }

    serialized_data = json.dumps(entry_without_hash_fields, sort_keys=True)
    payload = serialized_data + prev_hash
    entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    log_entry = dict(entry_without_hash_fields)
    log_entry["prev_hash"] = prev_hash
    log_entry["entry_hash"] = entry_hash

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

    return log_entry

