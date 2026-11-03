"""
tests/test_param_guard.py - Unit & Pipeline Tests for Parameter Safety Guard
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import agent.agent
from agent.agent import run_turn
from agent.environments.office import OfficeSandbox
from security.approval import ApprovalResult
import security.gateway
import security.param_guard
from security.param_guard import (
    check_params,
    check_path_safe,
    check_sql_readonly,
    check_url_allowlist,
    validate_rule_type,
)
import security.registry


# =========================================================================
# 1. UNIT TESTS: path_safe (8+ reject cases, accept cases)
# =========================================================================

def test_path_safe_reject_cases():
    """Verifies that path_safe rejects traversal, absolute paths, drive letters, backslashes, nulls, long strings."""
    rejects = [
        "../etc/passwd",
        "/etc/passwd",
        "C:\\x",
        "C:/x",
        "\\etc\\passwd",
        "dir/../../secret.txt",
        "memo\x00.txt",
        "a\\b\\c.txt",
        "a" * 121,
        "..",
        12345,  # non-string
    ]
    for r in rejects:
        ok, reason = check_path_safe(r)
        assert not ok, f"Expected reject for path: {r!r}"
        assert reason != "", f"Expected failure reason for path: {r!r}"


def test_path_safe_accept_cases():
    """Verifies that path_safe accepts valid relative filesystem paths."""
    accepts = [
        "memo.txt",
        "report.txt",
        "documents/summary.txt",
        "q3_results_2026.csv",
    ]
    for a in accepts:
        ok, reason = check_path_safe(a)
        assert ok, f"Expected accept for path: {a!r}, got reason: {reason}"
        assert reason == ""


# =========================================================================
# 2. UNIT TESTS: url_allowlist (8+ reject cases, accept cases)
# =========================================================================

def test_url_allowlist_reject_cases():
    """Verifies url_allowlist rejects insecure schemes, IP literals, unallowed hosts, credentials, ports."""
    opts = {"allowed_hosts": ["status.internal", "docs.company.com"]}
    rejects = [
        "http://status.internal",  # insecure scheme
        "https://127.0.0.1/",  # IPv4 literal
        "https://192.168.1.50/",  # IPv4 literal
        "https://[::1]/",  # IPv6 literal
        "https://evil.com/",  # unallowed host
        "https://status.internal.evil.com/",  # subdomain spoofing
        "https://user:p@status.internal/",  # embedded credentials
        "https://localhost/",  # localhost
        "https://status.internal:8080/",  # non-443 port
        "https://status.internal:80/",  # non-443 port
        "ftp://status.internal/file",  # non-https scheme
        12345,  # non-string
    ]
    for r in rejects:
        ok, reason = check_url_allowlist(r, opts)
        assert not ok, f"Expected reject for url: {r!r}"
        assert reason != "", f"Expected failure reason for url: {r!r}"


def test_url_allowlist_accept_cases():
    """Verifies url_allowlist accepts valid HTTPS URLs matching allowed hosts/subdomains."""
    opts = {"allowed_hosts": ["status.internal", "docs.company.com"]}
    accepts = [
        "https://status.internal/",
        "https://status.internal/health",
        "https://status.internal:443/health",
        "https://docs.company.com/handbook",
        "https://api.docs.company.com/v1/news",
    ]
    for a in accepts:
        ok, reason = check_url_allowlist(a, opts)
        assert ok, f"Expected accept for url: {a!r}, got reason: {reason}"
        assert reason == ""


# =========================================================================
# 3. UNIT TESTS: sql_readonly (8+ reject cases, accept cases)
# =========================================================================

def test_sql_readonly_reject_cases():
    """Verifies sql_readonly rejects non-SELECT, multi-statement, comments, destructive keywords, long queries."""
    rejects = [
        "SELECT 1; DROP TABLE users",  # semicolon multi-statement + DROP
        "select * from users -- x",  # line comment
        "DELETE FROM users",  # DELETE
        "SELECT 1 /* x */",  # block comment
        "UPDATE users SET name='x'",  # UPDATE
        "INSERT INTO users VALUES (1)",  # INSERT
        "ALTER TABLE users ADD c INT",  # ALTER
        "TRUNCATE TABLE users",  # TRUNCATE
        "CREATE TABLE x (id INT)",  # CREATE
        "ATTACH DATABASE 'x' AS db",  # ATTACH
        "PRAGMA integrity_check",  # PRAGMA
        "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'",  # GRANT
        "SELECT * FROM users; SELECT 2",  # multiple statements
        "SELECT " + ("a" * 501),  # length > 500
        12345,  # non-string
    ]
    for r in rejects:
        ok, reason = check_sql_readonly(r)
        assert not ok, f"Expected reject for SQL: {r!r}"
        assert reason != "", f"Expected failure reason for SQL: {r!r}"


def test_sql_readonly_accept_cases():
    """Verifies sql_readonly accepts single SELECT queries without comments or forbidden words."""
    accepts = [
        "SELECT name FROM users",
        "select id, name, dept from database where id = 1",
        "SELECT * FROM users;",
        "SELECT 1",
        "SELECT count(*) FROM records WHERE status = 'active'",
    ]
    for a in accepts:
        ok, reason = check_sql_readonly(a)
        assert ok, f"Expected accept for SQL: {a!r}, got reason: {reason}"
        assert reason == ""


# =========================================================================
# 4. UNKNOWN RULE TYPE TEST
# =========================================================================

def test_unknown_rule_type_raises_error():
    """Verifies that an unknown rule type in policy fails closed with ValueError."""
    with pytest.raises(ValueError, match="Unknown param guard rule type: 'arbitrary_eval'"):
        validate_rule_type("arbitrary_eval")

    with pytest.raises(ValueError, match="Unknown param guard rule type: 'magic_bypass'"):
        check_params("test_tool", {"arg": "val"}, {"arg": {"type": "magic_bypass"}})


# =========================================================================
# 5. PIPELINE TESTS: Office Environment via run_turn
# =========================================================================

@pytest.fixture(autouse=True)
def setup_office_env():
    """Ensures office environment is loaded for pipeline tests and restored after."""
    agent.agent.load_environment("office")
    OfficeSandbox.reset()
    yield
    agent.agent.load_environment("smart_home")


def test_pipeline_read_file_path_traversal_blocked():
    """read_file with ../x is blocked at param_guard and the file is not read."""
    mock_resp = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "read_file",
                        "arguments": {"path": "../secret.txt"},
                    }
                }
            ],
        }
    }
    emitted = []

    def capture_emit(stage, status, detail):
        emitted.append((stage, status, detail))

    with patch("ollama.chat", return_value=mock_resp):
        res = run_turn(
            text="Read the file ../secret.txt",
            role="admin",
            session_id="test_param_traversal",
            emit=capture_emit,
        )

    assert res.decision == "BLOCK"
    assert res.stopped_at == "param_guard"
    assert "directory traversal" in res.error

    # Verify param_guard stage emitted block
    stages_blocked = [s for s, st, d in emitted if st == "block"]
    assert "param_guard" in stages_blocked

    # Verify downstream stages were skipped
    stages_skipped = [s for s, st, d in emitted if st == "skip"]
    for downstream in ("rate_limit", "approval", "hardware", "output_scan"):
        assert downstream in stages_skipped


def test_pipeline_http_get_evil_url_blocked():
    """http_get with evil URL is blocked at param_guard, OfficeSandbox untouched."""
    mock_resp = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "http_get",
                        "arguments": {"url": "https://attacker.evil.com/payload"},
                    }
                }
            ],
        }
    }
    with patch("ollama.chat", return_value=mock_resp):
        res = run_turn(
            text="Fetch https://attacker.evil.com/payload",
            role="admin",
            session_id="test_param_url",
        )

    assert res.decision == "BLOCK"
    assert res.stopped_at == "param_guard"
    assert "not in policy allowed_hosts" in res.error


def test_pipeline_run_sql_drop_blocked_before_approval():
    """run_sql DROP as admin is blocked at param_guard before approval; approval manager never called."""
    destructive_query = "DROP TABLE users;"
    mock_resp = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "run_sql",
                        "arguments": {"query": destructive_query},
                    }
                }
            ],
        }
    }

    mock_approval = MagicMock()
    with patch.object(security.gateway.get_approval_manager(), "request", mock_approval):
        with patch("ollama.chat", return_value=mock_resp):
            res = run_turn(
                text=f"Please execute query {destructive_query}",
                role="admin",
                session_id="test_param_sql_drop",
            )

    assert res.decision == "BLOCK"
    assert res.stopped_at == "param_guard"
    # Essential assertion: approval manager was NEVER invoked
    assert mock_approval.call_count == 0


def test_pipeline_run_sql_select_reaches_approval():
    """run_sql with benign SELECT as admin passes param_guard and reaches approval gate."""
    safe_query = "SELECT name, dept FROM users WHERE id = 1"
    mock_resp = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "run_sql",
                        "arguments": {"query": safe_query},
                    }
                }
            ],
        }
    }

    called_requests = []

    def mock_approval_handler(req):
        called_requests.append(req)
        return ApprovalResult(approved=True, decided_by="admin_op", reason="Approved SELECT query")

    with patch.object(security.gateway.get_approval_manager(), "request", side_effect=mock_approval_handler):
        with patch("ollama.chat", return_value=mock_resp):
            res = run_turn(
                text=f"Please execute {safe_query}",
                role="admin",
                session_id="test_param_sql_select",
            )

    assert res.decision == "ALLOW"
    assert res.tool_called == "run_sql"
    assert len(called_requests) == 1
    assert called_requests[0].tool == "run_sql"
    assert called_requests[0].args.get("query") == safe_query


def test_smart_home_tools_pass_param_guard_silently():
    """Smart-home mode has no parameter rules defined; tools pass param_guard cleanly."""
    agent.agent.load_environment("smart_home")
    rules = security.registry.param_rules("turn_light_on")
    assert rules == {}

    ok, reason = check_params("turn_light_on", {}, rules)
    assert ok is True
    assert reason == ""

