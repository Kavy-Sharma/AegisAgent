import pytest
from unittest.mock import patch
from web.guards import verify_host_header, HOST_REGEX
from security.approval import ApprovalManager, ConsoleApprovalProvider, DashboardApprovalProvider
import security.policy_loader
from web.server import create_app


def test_host_header_fullmatch_rejects_subdomain_and_suffix():
    """VULN-06: Host check must use fullmatch to reject hosts like 127.0.0.1.attacker.com."""
    assert HOST_REGEX.fullmatch("127.0.0.1") is not None
    assert HOST_REGEX.fullmatch("localhost") is not None
    assert HOST_REGEX.fullmatch("127.0.0.1:8501") is not None
    assert HOST_REGEX.fullmatch("localhost:8501") is not None

    # Host starting with 127.0.0.1 or localhost but with trailing attacker suffix
    assert HOST_REGEX.fullmatch("127.0.0.1.evil.com") is None
    assert HOST_REGEX.fullmatch("localhost.attacker.io") is None
    assert HOST_REGEX.fullmatch("127.0.0.1:8501/bad") is None


def test_single_approval_timeout_from_policy():
    """VULN-12: ApprovalManager and providers must all read timeout_seconds from policy as single source of truth."""
    with patch.dict(security.policy_loader.POLICY.get("approval", {}), {"timeout_seconds": 45.0}):
        manager = ApprovalManager()
        assert manager.timeout_seconds == 45.0, f"Expected 45.0 from policy, got {manager.timeout_seconds}"

        console_p = ConsoleApprovalProvider()
        assert console_p.timeout_seconds == 45.0, f"Expected 45.0 from policy, got {console_p.timeout_seconds}"

        dash_p = DashboardApprovalProvider()
        assert dash_p.timeout_seconds == 45.0, f"Expected 45.0 from policy, got {dash_p.timeout_seconds}"


def test_no_hardcoded_com11_in_overview():
    """VULN-13: /api/overview must never display hardcoded COM11 when device port is unassigned."""
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    # Mock health returning device with no port
    mock_health = {
        "device": {"status": "offline", "port": None, "last_seen": None},
        "worker": {"alive": True},
        "ollama": {"status": "ready"},
        "audit": {"status": "intact"}
    }

    with patch("security.health.get_system_health", return_value=mock_health):
        with app.test_client() as c:
            with c.session_transaction() as sess:
                sess["logged_in"] = True
                sess["username"] = "admin"
                sess["role"] = "admin"
                sess["real_role"] = "admin"

            res = c.get("/api/overview")
            assert res.status_code == 200
            data_str = str(res.get_json())
            assert "COM11" not in data_str, f"Found hardcoded 'COM11' in overview response: {data_str}"

