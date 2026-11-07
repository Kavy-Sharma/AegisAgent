"""
Pytest configuration and test isolation fixtures for AegisAgent.
"""

from pathlib import Path
import tempfile
import pytest
import security.hardware
import security.logger
import security.quarantine
import security.rate_limiter

_SESSION_TMP_DIR = Path(tempfile.mkdtemp(prefix="aegis_session_fallback_"))
_SESSION_LOG_FILE = _SESSION_TMP_DIR / "audit_log.jsonl"
_SESSION_LOG_FILE.touch()
security.logger.set_log_file(_SESSION_LOG_FILE)


def pytest_sessionfinish(session, exitstatus):
    """Restore logger to None at the very end of pytest."""
    security.logger.set_log_file(None)


@pytest.fixture(autouse=True)
def isolate_test_environment(tmp_path, monkeypatch):
    """
    Points the logger, approvals dir and data dir to tmp_path for EVERY test.
    Guarantees that real logs (logs/audit_log.jsonl) and real data files are untouched.
    """
    test_log = tmp_path / "logs" / "audit_log.jsonl"
    test_log.parent.mkdir(parents=True, exist_ok=True)
    test_log.touch()
    test_anchor = tmp_path / "logs" / "audit_log.anchor.json"

    test_data = tmp_path / "data"
    test_approvals = test_data / "approvals"
    (test_approvals / "pending").mkdir(parents=True, exist_ok=True)
    (test_approvals / "decisions").mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("AEGIS_LOG_FILE", str(test_log))
    monkeypatch.setenv("AEGIS_ANCHOR_FILE", str(test_anchor))
    monkeypatch.setenv("AEGIS_DATA_DIR", str(test_data))
    monkeypatch.setenv("AEGIS_APPROVALS_DIR", str(test_approvals))

    security.logger.set_log_file(test_log)
    fake_bridge = security.hardware.FakeBridge()
    security.hardware.set_bridge(fake_bridge)
    security.quarantine.release_quarantine("admin")
    security.rate_limiter.CALL_TIMESTAMPS.clear()

    yield tmp_path

    security.logger.set_log_file(_SESSION_LOG_FILE)
    security.hardware.set_bridge(None)
    security.quarantine.release_quarantine("admin")
    security.rate_limiter.CALL_TIMESTAMPS.clear()
