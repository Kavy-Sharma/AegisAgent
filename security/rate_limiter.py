"""
Phase 4 -- In-Memory Rate Limiter (Hardened VULN-09)

WHAT THIS FILE DOES:
Tracks tool execution call timestamps in memory and enforces sliding window rate limits.
Keyed strictly by (username, tool_name) to prevent cross-user DoS.
Protected with threading.Lock for thread safety.
"""

import threading
import time
from security.policy_loader import get_rate_limit

_LOCK = threading.Lock()


class RateLimitDict(dict):
    """Dictionary supporting (username, tool_name) tuples with legacy string fallback."""
    def __getitem__(self, key):
        if isinstance(key, tuple):
            if key not in self:
                super().__setitem__(key, [])
            return super().__getitem__(key)
        # Legacy fallback by tool_name alone
        if super().__contains__(key):
            return super().__getitem__(key)
        for (u, t), val in self.items():
            if t == key:
                return val
        default_k = ("guest", key)
        if default_k not in self:
            super().__setitem__(default_k, [])
        return super().__getitem__(default_k)

    def get(self, key, default=None):
        if isinstance(key, tuple):
            return super().get(key, default if default is not None else [])
        if super().__contains__(key):
            return super().get(key, default)
        for (u, t), val in self.items():
            if t == key:
                return val
        return default if default is not None else []

    def __contains__(self, key):
        if isinstance(key, tuple):
            return super().__contains__(key)
        if super().__contains__(key):
            return True
        return any(isinstance(k, tuple) and len(k) > 1 and k[1] == key for k in self.keys())


# Maps (username, tool_name) -> list of float timestamps
CALL_TIMESTAMPS: RateLimitDict = RateLimitDict()


def _get_key(username: str | None, tool_name: str) -> tuple[str, str]:
    u = (username or "").strip() or "guest"
    return (u, tool_name)


def _prune_old_timestamps(key: tuple[str, str], now: float, window_seconds: int):
    """Removes timestamps older than window_seconds for the given key."""
    if key not in CALL_TIMESTAMPS:
        CALL_TIMESTAMPS[key] = []
        return
    cutoff = now - window_seconds
    CALL_TIMESTAMPS[key] = [t for t in CALL_TIMESTAMPS[key] if t >= cutoff]


def check_rate_limit(tool_name: str, username: str | None = None) -> bool:
    """
    Checks if executing tool_name for username stays within rate limits.
    Returns True if allowed, False if exceeded.
    """
    with _LOCK:
        max_calls, window_seconds = get_rate_limit()
        now = time.time()
        key = _get_key(username, tool_name)
        _prune_old_timestamps(key, now, window_seconds)
        return len(CALL_TIMESTAMPS[key]) < max_calls


def record_call(tool_name: str, username: str | None = None):
    """
    Records a tool execution timestamp for (username, tool_name).
    """
    with _LOCK:
        max_calls, window_seconds = get_rate_limit()
        now = time.time()
        key = _get_key(username, tool_name)
        _prune_old_timestamps(key, now, window_seconds)
        CALL_TIMESTAMPS[key].append(now)
