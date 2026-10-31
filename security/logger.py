"""
Phase 4 & Phase 8A -- Tamper-Evident Audit Logger

WHAT THIS FILE DOES:
Appends decision and security logs to logs/audit_log.jsonl using a SHA-256 hash chain.
Each log line includes a cryptographic hash of its contents plus the previous line's hash.
Supports cross-process file locking (Windows msvcrt, POSIX fcntl), configurable log path,
and log rotation/archival.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

_custom_log_file: Path | None = None


def get_log_file() -> Path:
    """Returns the active audit log file path (custom, env-var, or default)."""
    if _custom_log_file is not None:
        return _custom_log_file
    env_path = os.environ.get("AEGIS_LOG_FILE")
    if env_path:
        return Path(env_path)
    return Path(__file__).resolve().parent.parent / "logs" / "audit_log.jsonl"


def set_log_file(path: Path | str | None):
    """Overrides the active audit log file path (useful for testing and isolation)."""
    global _custom_log_file
    if path is None:
        _custom_log_file = None
    else:
        _custom_log_file = Path(path)


def __getattr__(name):
    if name == "LOG_FILE":
        return get_log_file()
    if name == "LOG_DIR":
        return get_log_file().parent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@contextmanager
def _file_lock(log_path: Path, timeout: float = 10.0):
    """
    Cross-process file lock using msvcrt on Windows and fcntl on POSIX.
    Locks a companion .lock file to avoid conflicting with readers of the log file.
    """
    lock_path = log_path.with_name(log_path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    
    start_time = time.time()
    f = open(lock_path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            while True:
                try:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except (OSError, PermissionError, IOError):
                    if time.time() - start_time > timeout:
                        raise TimeoutError(f"Could not acquire file lock on {lock_path} within {timeout}s")
                    time.sleep(0.01)
            try:
                yield
            finally:
                try:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
        else:
            import fcntl
            while True:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except (OSError, IOError, BlockingIOError):
                    if time.time() - start_time > timeout:
                        raise TimeoutError(f"Could not acquire file lock on {lock_path} within {timeout}s")
                    time.sleep(0.01)
            try:
                yield
            finally:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
    finally:
        try:
            f.close()
        except Exception:
            pass


def _read_last_line_from_end(log_file: Path) -> str | None:
    """Reads only the last line from the file end without loading the whole file into memory."""
    try:
        file_size = log_file.stat().st_size
    except OSError:
        return None

    if file_size == 0:
        return None

    buffer_size = 4096
    with open(log_file, "rb") as f:
        pos = file_size
        remainder = b""
        while pos > 0:
            read_size = min(buffer_size, pos)
            pos -= read_size
            f.seek(pos)
            chunk = f.read(read_size) + remainder
            lines = chunk.splitlines()
            if len(lines) > 1:
                for line in reversed(lines):
                    s = line.strip()
                    if s:
                        return s.decode("utf-8", errors="replace")
                remainder = b""
            else:
                remainder = chunk
        if remainder.strip():
            return remainder.strip().decode("utf-8", errors="replace")
    return None


def _get_last_entry_hash(log_file: Path | None = None) -> str:
    """
    Returns the entry_hash of the last line in the log file, or '0'*64 if empty/missing.
    Reads only the last line from the file end. If the last line is corrupt, raises RuntimeError
    and writes an audit corruption record rather than silently restarting at genesis.
    """
    if log_file is None:
        log_file = get_log_file()

    if not log_file.exists():
        return "0" * 64

    last_line = _read_last_line_from_end(log_file)
    if not last_line:
        return "0" * 64

    try:
        last_entry = json.loads(last_line)
        if not isinstance(last_entry, dict) or "entry_hash" not in last_entry:
            raise ValueError("Entry missing 'entry_hash' field or not a valid JSON object")
        return last_entry["entry_hash"]
    except Exception as err:
        try:
            corruption_log = log_file.with_name("audit_corruption.log")
            with open(corruption_log, "a", encoding="utf-8") as cf:
                cf.write(
                    f"[{datetime.now(timezone.utc).isoformat()}] Audit log corrupt at {log_file}: {err}. Last line: {last_line}\n"
                )
        except Exception:
            pass
        raise RuntimeError(f"Corrupt audit log detected in {log_file}: {err}") from err


def _append_entry(entry_data: dict) -> dict:
    """
    Appends an entry to the hash chain under a cross-process lock.
    Safely executes: read last hash -> append line -> flush (+ fsync).
    """
    log_file = get_log_file()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    with _file_lock(log_file):
        prev_hash = _get_last_entry_hash(log_file)
        
        # Build entry without hash fields
        entry_without_hash = {k: v for k, v in entry_data.items() if k not in ("prev_hash", "entry_hash")}
        serialized_data = json.dumps(entry_without_hash, sort_keys=True)
        payload = serialized_data + prev_hash
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        log_entry = dict(entry_without_hash)
        log_entry["prev_hash"] = prev_hash
        log_entry["entry_hash"] = entry_hash

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass

        return log_entry


def archive_and_reset(reason: str) -> dict:
    """
    Moves current log to logs/archive/<UTC timestamp>.jsonl and starts a new
    chain whose first entry records the archived file name and its final hash.
    """
    log_file = get_log_file()
    log_dir = log_file.parent
    archive_dir = log_dir / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)

    with _file_lock(log_file):
        try:
            final_hash = _get_last_entry_hash(log_file)
        except Exception:
            final_hash = "CORRUPT"
        now_utc = datetime.now(timezone.utc)
        ts_str = now_utc.strftime("%Y-%m-%dT%H-%M-%SZ")
        archive_name = f"{ts_str}.jsonl"
        archive_path = archive_dir / archive_name
        if archive_path.exists():
            archive_name = f"{ts_str}_{now_utc.microsecond:06d}.jsonl"
            archive_path = archive_dir / archive_name

        if log_file.exists():
            shutil.move(str(log_file), str(archive_path))
        else:
            archive_name = "none"

        # Start a new chain
        first_entry_data = {
            "archived_file": archive_name,
            "event": "log_archive_reset",
            "final_hash": final_hash,
            "reason": reason,
            "timestamp": now_utc.isoformat(),
        }

        prev_hash = "0" * 64
        serialized_data = json.dumps(first_entry_data, sort_keys=True)
        payload = serialized_data + prev_hash
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        first_entry = dict(first_entry_data)
        first_entry["prev_hash"] = prev_hash
        first_entry["entry_hash"] = entry_hash

        with open(log_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(first_entry) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass

        return first_entry


def log_decision(
    tool: str,
    args: dict,
    role: str,
    risk: str | None,
    decision: str,
    reason: str,
) -> dict:
    """Constructs a tamper-evident audit log entry and appends it to logs/audit_log.jsonl."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "args": args,
        "decision": decision,
        "reason": reason,
        "risk": risk,
        "role": role,
        "timestamp": timestamp_str,
        "tool": tool,
    }
    return _append_entry(entry)


def log_injection_check(
    session_id: str,
    source: str,
    decision: str,
    score: float,
    rule_ids: list[str],
    text: str,
) -> dict:
    """Constructs a tamper-evident audit log entry for prompt injection check."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "decision": decision,
        "event": "injection_check",
        "rule_ids": rule_ids,
        "score": score,
        "session_id": session_id,
        "source": source,
        "text": text[:200],
        "timestamp": timestamp_str,
    }
    return _append_entry(entry)


def log_engine_error(
    session_id: str,
    source: str,
    error: str,
    text: str,
) -> dict:
    """Constructs a tamper-evident audit log entry for detection engine error."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "error": error,
        "event": "engine_error",
        "session_id": session_id,
        "source": source,
        "text": text[:200],
        "timestamp": timestamp_str,
    }
    return _append_entry(entry)


def log_approval_request(req) -> dict:
    """Constructs a tamper-evident audit log entry for an approval request."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "args": req.args,
        "event": "approval_request",
        "kind": req.kind,
        "reasons": req.reasons,
        "request_hash": req.request_hash,
        "request_id": req.request_id,
        "risk": req.risk,
        "session_id": req.session_id,
        "timestamp": timestamp_str,
        "tool": req.tool,
    }
    return _append_entry(entry)


def log_approval_decision(req, result) -> dict:
    """Constructs a tamper-evident audit log entry for an approval decision."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "approved": result.approved,
        "decided_by": result.decided_by,
        "event": "approval_decision",
        "reason": result.reason,
        "request_hash": req.request_hash,
        "request_id": req.request_id,
        "risk": getattr(req, "risk", None),
        "session_id": req.session_id,
        "timed_out": result.timed_out,
        "timestamp": timestamp_str,
        "tool": getattr(req, "tool", None),
    }
    return _append_entry(entry)


def log_approval_error(req, error_str: str) -> dict:
    """Constructs a tamper-evident audit log entry for an approval error."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "error": error_str,
        "event": "approval_error",
        "request_hash": req.request_hash,
        "request_id": req.request_id,
        "session_id": req.session_id,
        "timestamp": timestamp_str,
    }
    return _append_entry(entry)


def log_role_change(old_role: str, new_role: str) -> dict:
    """Constructs a tamper-evident audit log entry for a role change."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "event": "role_change",
        "new_role": new_role,
        "old_role": old_role,
        "timestamp": timestamp_str,
    }
    return _append_entry(entry)


def log_hardware_command(command: str, ok: bool, error: str | None) -> dict:
    """Constructs a tamper-evident audit log entry for a hardware command."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "command": command,
        "error": error,
        "event": "hardware_command",
        "ok": ok,
        "timestamp": timestamp_str,
    }
    return _append_entry(entry)


def log_event(event: str, data: dict | None = None, **kwargs) -> dict:
    """
    Constructs a tamper-evident audit log entry for any system or security event.
    (e.g., login_success, login_failure, logout, user_created, worker_rejected).
    """
    entry = {"event": event}
    if data:
        entry.update(data)
    if kwargs:
        entry.update(kwargs)
    if "timestamp" not in entry:
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    return _append_entry(entry)


def log_intent_scope(request_id: str, session_id: str, scope: list[str]) -> dict:
    """Constructs a tamper-evident audit log entry for intent scope."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "event": "intent_scope",
        "request_id": request_id,
        "scope": scope or [],
        "session_id": session_id,
        "timestamp": timestamp_str,
    }
    return _append_entry(entry)


def log_turn_summary(
    request_id: str,
    session_id: str,
    decision: str,
    tool: str | None,
    rule_ids: list[str],
    latency_ms: float,
    scope: list[str] | None = None,
    tainted: bool = False,
) -> dict:
    """Constructs a tamper-evident audit log entry for a turn summary."""
    timestamp_str = datetime.now(timezone.utc).isoformat()
    entry = {
        "decision": decision,
        "event": "turn_summary",
        "latency_ms": latency_ms,
        "request_id": request_id,
        "rule_ids": rule_ids or [],
        "scope": scope if scope is not None else [],
        "session_id": session_id,
        "tainted": tainted,
        "timestamp": timestamp_str,
        "tool": tool,
    }
    return _append_entry(entry)

