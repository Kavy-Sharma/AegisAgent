import re
from unittest.mock import patch
from flask import abort
import pytest
from web.server import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["real_role"] = "admin"
            sess["csrf_token"] = "test_csrf"
        yield c


def test_no_exception_text_leaked_in_console_send_failure(client):
    """VULN-07: Internal exceptions during console send must not leak str(e) to client."""
    secret_exception_text = "INTERNAL_DB_PASSWORD_LEAK_IN_EXCEPTION_XYZ999"
    with patch("os.replace", side_effect=RuntimeError(secret_exception_text)):
        res = client.post("/api/console/send", json={"text": "hello"}, headers={"X-CSRF-Token": "test_csrf"})
        assert res.status_code == 500
        data = res.get_json()
        assert secret_exception_text not in str(data), f"Leaked exception details in response: {data}"
        assert "error_id" in data


def test_no_exception_text_leaked_in_bad_request_handler():
    """VULN-07: 400 Bad Request handler must not leak str(e) into JSON responses."""
    app = create_app()

    @app.route("/api/test_trigger_400")
    def trigger():
        abort(400, "Internal sensitive error message with secret tokens")

    with app.test_client() as c:
        res = c.get("/api/test_trigger_400")
        assert res.status_code == 400
        data = res.get_json()
        assert isinstance(data, dict)
        assert "secret tokens" not in str(data)
        assert "error_id" in data
