import json
from pathlib import Path
import pytest
from web.server import create_app
from web.api import _get_data_dir
import security.logger


@pytest.fixture
def app():
    application = create_app()
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


def test_guest_overview_recent_alerts_filtered(app):
    """Guest role on /api/overview must have recent_alerts filtered (empty for guests)."""
    # Log an admin security alert to the audit log
    security.logger.log_event("injection_check", {
        "decision": "BLOCK",
        "rule_ids": ["INJ-001"],
        "reason": "Instruction override detected",
        "username": "admin",
    })

    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "guest_user"
            sess["role"] = "guest"
            sess["real_role"] = "guest"

        res = c.get("/api/overview")
        assert res.status_code == 200
        data = res.get_json()
        assert "recent_alerts" in data
        # Guest must not see system-wide admin security alerts
        assert len(data["recent_alerts"]) == 0, f"Expected filtered alerts for guest, got {data['recent_alerts']}"


def test_outbox_poll_idor_rejected_for_non_owner(app):
    """VULN-IDOR: Outbox poll for another user's request must return 403 Forbidden."""
    outbox_dir = _get_data_dir() / "chat" / "outbox"
    outbox_dir.mkdir(parents=True, exist_ok=True)
    req_file = outbox_dir / "req_alice_secret.jsonl"

    with open(req_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"owner": "alice", "request_id": "req_alice_secret"}) + "\n")
        f.write(json.dumps({"stage": "llm", "status": "pass", "detail": {"secret": "alice_confidential_prompt"}}) + "\n")
        f.write(json.dumps({"final": True, "reply": "Confidential reply for Alice", "decision": "ALLOW"}) + "\n")

    # Bob (guest) attempts to poll Alice's request
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "bob"
            sess["role"] = "guest"
            sess["real_role"] = "guest"

        res = c.get("/api/console/poll/req_alice_secret")
        assert res.status_code == 403, f"Expected 403 Forbidden for IDOR attempt, got {res.status_code}"
        assert "Forbidden" in res.get_json().get("error", "")


def test_outbox_poll_allowed_for_owner(app):
    """Owner of the request is allowed to poll their own outbox."""
    outbox_dir = _get_data_dir() / "chat" / "outbox"
    outbox_dir.mkdir(parents=True, exist_ok=True)
    req_file = outbox_dir / "req_alice_own.jsonl"

    with open(req_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"owner": "alice", "request_id": "req_alice_own"}) + "\n")
        f.write(json.dumps({"final": True, "reply": "Hello Alice", "decision": "ALLOW"}) + "\n")

    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "alice"
            sess["role"] = "guest"
            sess["real_role"] = "guest"

        res = c.get("/api/console/poll/req_alice_own")
        assert res.status_code == 200
        data = res.get_json()
        assert data.get("final", {}).get("reply") == "Hello Alice"


def test_outbox_poll_allowed_for_admin_real_role(app):
    """Admin with real_role == 'admin' is allowed to poll any outbox."""
    outbox_dir = _get_data_dir() / "chat" / "outbox"
    outbox_dir.mkdir(parents=True, exist_ok=True)
    req_file = outbox_dir / "req_bob_data.jsonl"

    with open(req_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"owner": "bob", "request_id": "req_bob_data"}) + "\n")
        f.write(json.dumps({"final": True, "reply": "Hello Bob", "decision": "ALLOW"}) + "\n")

    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"

        res = c.get("/api/console/poll/req_bob_data")
        assert res.status_code == 200
        data = res.get_json()
        assert data.get("final", {}).get("reply") == "Hello Bob"
