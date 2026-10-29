"""
Phase 9B -- Session Quarantine & Demo-Friendly Release
Tracks prompt injection attempts per session. If 3 injection attempts occur in a session,
the session is placed in QUARANTINE mode to protect connected IoT hardware.
Admins can instantly release quarantine via UI without waiting.
"""

from typing import Any

# Maps session_id -> count of injection attempts
_INJECTION_COUNTS: dict[str, int] = {}
# Set of currently quarantined session IDs
_QUARANTINED_SESSIONS: set[str] = set()


def record_injection_attempt(session_id: str) -> int:
    """Increments the injection attempt counter for a session. Quarantines at 3."""
    count = _INJECTION_COUNTS.get(session_id, 0) + 1
    _INJECTION_COUNTS[session_id] = count
    if count >= 3:
        _QUARANTINED_SESSIONS.add(session_id)
    return count


def is_quarantined(session_id: str) -> bool:
    """Returns True if the session is currently in Quarantine mode."""
    return session_id in _QUARANTINED_SESSIONS


def release_quarantine(session_id: str) -> bool:
    """Releases the session from Quarantine mode and resets its attempt counter."""
    _QUARANTINED_SESSIONS.discard(session_id)
    _INJECTION_COUNTS[session_id] = 0
    return True


def reset_all_quarantines() -> None:
    """Resets all quarantine states across all sessions."""
    _QUARANTINED_SESSIONS.clear()
    _INJECTION_COUNTS.clear()


def get_quarantine_info(session_id: str) -> dict[str, Any]:
    """Returns current quarantine status and injection count for a session."""
    return {
        "session_id": session_id,
        "quarantined": session_id in _QUARANTINED_SESSIONS,
        "injection_attempts": _INJECTION_COUNTS.get(session_id, 0),
        "threshold": 3,
    }

