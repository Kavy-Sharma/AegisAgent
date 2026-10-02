"""
Phase 4 — In-Memory Rate Limiter

WHAT THIS FILE DOES:
Tracks tool execution call timestamps in memory and enforces sliding window rate limits.
"""

import time
from security.policy_loader import get_rate_limit

# Maps tool_name -> list of float timestamps
CALL_TIMESTAMPS: dict[str, list[float]] = {}


def _prune_old_timestamps(tool_name: str, now: float, window_seconds: int):
    """Removes timestamps older than window_seconds for the given tool."""
    if tool_name not in CALL_TIMESTAMPS:
        CALL_TIMESTAMPS[tool_name] = []
        return
    cutoff = now - window_seconds
    CALL_TIMESTAMPS[tool_name] = [t for t in CALL_TIMESTAMPS[tool_name] if t >= cutoff]


def check_rate_limit(tool_name: str) -> bool:
    """
    Checks if executing tool_name would stay within rate limits.
    Returns True if allowed, False if the rate limit would be exceeded.
    """
    max_calls, window_seconds = get_rate_limit()
    now = time.time()
    _prune_old_timestamps(tool_name, now, window_seconds)
    return len(CALL_TIMESTAMPS[tool_name]) < max_calls


def record_call(tool_name: str):
    """
    Records a tool execution timestamp after prune cleanup.
    """
    max_calls, window_seconds = get_rate_limit()
    now = time.time()
    _prune_old_timestamps(tool_name, now, window_seconds)
    CALL_TIMESTAMPS[tool_name].append(now)
