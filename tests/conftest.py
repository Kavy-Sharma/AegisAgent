"""
Pytest configuration and test isolation fixtures for AegisAgent.
"""

from pathlib import Path
import pytest
import security.logger


@pytest.fixture(autouse=True)
def isolate_test_environment(tmp_path, monkeypatch):
    """
    Points the logger, approvals dir and data dir to tmp_path for EVERY test.
    Guarantees that real logs (logs/audit_log.jsonl) and real data files are untouched.
    """
    test_log = tmp_path / "logs" / "audit_log.jsonl"
    test_log.parent.mkdir(parents=True, exist_ok=True)
    test_log.touch()

    test_data = tmp_path / "data"
    test_approvals = test_data / "approvals"
    (test_approvals / "pending").mkdir(parents=True, exist_ok=True)
    (test_approvals / "decisions").mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("AEGIS_LOG_FILE", str(test_log))
    monkeypatch.setenv("AEGIS_DATA_DIR", str(test_data))
    monkeypatch.setenv("AEGIS_APPROVALS_DIR", str(test_approvals))

    security.logger.set_log_file(test_log)

    yield tmp_path

    security.logger.set_log_file(None)
