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


def test_max_content_length_configured():
    """VULN-04: app.config['MAX_CONTENT_LENGTH'] must be set to 1MB (1,048,576 bytes)."""
    app = create_app()
    assert app.config.get("MAX_CONTENT_LENGTH") == 1 * 1024 * 1024


def test_payload_over_1mb_rejected_with_413_json(client):
    """VULN-04: Request payload exceeding 1MB returns HTTP 413 with JSON error."""
    large_payload = {"text": "A" * (1024 * 1024 + 100)}
    res = client.post("/api/console/send", json=large_payload, headers={"X-CSRF-Token": "test_csrf"})
    assert res.status_code == 413, f"Expected 413 for payload >1MB, got {res.status_code}"
    data = res.get_json()
    assert isinstance(data, dict)
    assert "Payload too large" in data.get("error", "")
    assert data.get("max_bytes") == 1048576

