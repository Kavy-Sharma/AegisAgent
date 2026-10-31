"""
Phase 9B & Hardened Containment Lockdown:
Tracks prompt injection attempts keyed strictly by USERNAME.
Keying by username ensures that logging out and logging back in DOES NOT reset quarantine.
If 3 injection attempts occur by a user, the account is placed into Containment Lockdown (HTTP 423).
Quarantine state is atomically persisted to data/quarantine.json so that restarts do not clear lockdown.
Admins with real_role == 'admin' can release quarantine via authorized admin override.
"""

import json
import os
from pathlib import Path
import secrets
import threading
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent

_LOCK = threading.RLock()


def _get_quarantine_file() -> Path:
    data_dir = Path(os.environ.get("AEGIS_DATA_DIR", ROOT_DIR / "data"))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "quarantine.json"


def _normalize_key(user_or_sess: str) -> str:
    return (user_or_sess or "").strip().lower()


def _load_quarantine_data() -> tuple[dict[str, int], set[str]]:
    """Loads (counts, quarantined_set) from data/quarantine.json under lock."""
    q_file = _get_quarantine_file()
    if not q_file.exists():
        return {}, set()
    try:
        with open(q_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            counts = {str(k): int(v) for k, v in data.get("counts", {}).items()}
            quarantined = set(str(u) for u in data.get("quarantined", []))
            return counts, quarantined
    except Exception:
        return {}, set()


def _save_quarantine_data(counts: dict[str, int], quarantined: set[str]) -> None:
    """Atomically persists quarantine data to disk using temporary file replacement."""
    q_file = _get_quarantine_file()
    payload = {
        "counts": counts,
        "quarantined": sorted(list(quarantined)),
    }
    tmp_file = q_file.with_name(f"quarantine.tmp.{secrets.token_hex(4)}")
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp_file, q_file)
    except Exception:
        try:
            if tmp_file.exists():
                tmp_file.unlink()
        except Exception:
            pass


def record_injection_attempt(username: str) -> int:
    """Increments the injection attempt counter for a user. Quarantines at 3."""
    key = _normalize_key(username)
    if not key:
        return 0
    with _LOCK:
        counts, quarantined = _load_quarantine_data()
        count = counts.get(key, 0) + 1
        counts[key] = count
        if count >= 3:
            quarantined.add(key)
        _save_quarantine_data(counts, quarantined)
        return count


def is_quarantined(username: str) -> bool:
    """Returns True if the username is currently in Containment Lockdown."""
    key = _normalize_key(username)
    if not key:
        return False
    with _LOCK:
        _, quarantined = _load_quarantine_data()
        return key in quarantined


def release_quarantine(username: str) -> bool:
    """Releases the user from Quarantine mode and resets its attempt counter."""
    key = _normalize_key(username)
    if not key:
        return False
    with _LOCK:
        counts, quarantined = _load_quarantine_data()
        quarantined.discard(key)
        counts[key] = 0
        _save_quarantine_data(counts, quarantined)
        return True


def reset_all_quarantines() -> None:
    """Resets all quarantine states across all users."""
    with _LOCK:
        _save_quarantine_data({}, set())


def get_quarantine_info(username: str) -> dict[str, Any]:
    """Returns current quarantine status and injection count for a user."""
    key = _normalize_key(username)
    with _LOCK:
        counts, quarantined = _load_quarantine_data()
        return {
            "username": key,
            "quarantined": key in quarantined,
            "injection_attempts": counts.get(key, 0),
            "threshold": 3,
        }
