import concurrent.futures
import threading
import pytest
import security.rate_limiter
from security.rate_limiter import check_rate_limit, record_call


@pytest.fixture(autouse=True)
def clean_rate_limiter():
    security.rate_limiter.CALL_TIMESTAMPS.clear()


def test_rate_limiter_keyed_by_username_and_tool():
    """VULN-09: One user exhausting rate limit must NOT block a different user."""
    tool = "turn_light_on"

    # Alice exhausts her rate limit (5 calls)
    for _ in range(5):
        assert check_rate_limit(tool, username="alice") is True
        record_call(tool, username="alice")

    # Alice's 6th call is blocked
    assert check_rate_limit(tool, username="alice") is False

    # Bob's 1st call must be ALLOWED (not blocked by Alice's activity)
    assert check_rate_limit(tool, username="bob") is True, "Bob was blocked by Alice's calls (keyed by tool only, not username)!"


def test_rate_limiter_thread_safety():
    """VULN-09: Rate limiter uses threading.Lock to prevent race conditions during concurrent access."""
    assert hasattr(security.rate_limiter, "_LOCK"), "Rate limiter missing threading.Lock"
    assert isinstance(security.rate_limiter._LOCK, type(threading.Lock())), "_LOCK is not a Lock instance"

    tool = "read_temperature"
    # Run 50 concurrent checks across threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(check_rate_limit, tool, username=f"user_{i%5}") for i in range(50)]
        results = [f.result() for f in futures]
    assert all(isinstance(r, bool) for r in results)
