import pytest
from web.server import create_app
import security.auth


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


CSRF_HEADERS = {"X-CSRF-Token": "test_csrf"}


@pytest.mark.parametrize("payload", [
    12345,
    ["x"],
    "a raw string",
    {"text": 12345},
    {"text": ["nested", "list"]},
    {"text": None},
])
def test_console_send_rejects_non_dict_and_invalid_types_with_400(client, payload):
    """VULN-02: Non-dict bodies and invalid field types must return 400 JSON, never 500."""
    res = client.post("/api/console/send", json=payload, headers=CSRF_HEADERS)
    assert res.status_code == 400, f"Expected 400 for payload {payload}, got {res.status_code}"
    data = res.get_json()
    assert isinstance(data, dict)
    assert "error" in data


@pytest.mark.parametrize("payload", [
    12345,
    ["x"],
    {"command": 999},
    {"command": ["bad"]},
])
def test_hardware_actuate_rejects_invalid_types_with_400(client, payload):
    """VULN-02: Hardware actuate rejects non-dict and invalid command types with 400."""
    res = client.post("/api/hardware/actuate", json=payload, headers=CSRF_HEADERS)
    assert res.status_code == 400, f"Expected 400 for payload {payload}, got {res.status_code}"
    data = res.get_json()
    assert isinstance(data, dict)
    assert "error" in data


@pytest.mark.parametrize("payload", [
    12345,
    ["x"],
    {"request_id": 12345, "approved": True},
    {"request_id": "req_123", "approved": "yes"},
])
def test_approvals_decide_rejects_invalid_types_with_400(client, payload):
    """VULN-02: Approvals decide rejects non-dict and invalid types with 400."""
    res = client.post("/api/approvals/decide", json=payload, headers=CSRF_HEADERS)
    assert res.status_code == 400, f"Expected 400 for payload {payload}, got {res.status_code}"
    data = res.get_json()
    assert isinstance(data, dict)
    assert "error" in data


@pytest.mark.parametrize("payload", [
    12345,
    ["x"],
    {"role": 123},
    {"role": ["admin"]},
])
def test_switch_role_rejects_invalid_types_with_400(client, payload):
    """VULN-02: Switch role rejects non-dict and invalid types with 400."""
    res = client.post("/api/auth/switch_role", json=payload, headers=CSRF_HEADERS)
    assert res.status_code == 400, f"Expected 400 for payload {payload}, got {res.status_code}"
    data = res.get_json()
    assert isinstance(data, dict)
    assert "error" in data
