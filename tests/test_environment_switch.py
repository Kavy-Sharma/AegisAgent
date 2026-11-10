"""
Tests for Admin Environment Switching (POST /api/environment/switch) & Role UI Gating.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time
import security.logger
import security.registry
from web.server import create_app


def _setup_client(app, role: str, real_role: str | None = None, username: str = "tester"):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["username"] = username
        sess["role"] = role
        sess["real_role"] = real_role if real_role is not None else role
        sess["csrf_token"] = "test_csrf_tok"
        sess["last_activity"] = time.time()
    return client


def test_env_switch_rejects_unauthenticated_and_guest(tmp_path, monkeypatch):
    monkeypatch.setattr("web.api._get_data_dir", lambda: tmp_path)
    calls = []
    app = create_app()
    app.config["TESTING"] = True
    app.config["ENV_RESTART_HANDLER"] = lambda target, frm, who: calls.append((target, frm, who))

    # 1. Guest session
    guest_client = _setup_client(app, role="guest", username="guest1")
    res_g = guest_client.post(
        "/api/environment/switch",
        json={"env": "office"},
        headers={"X-CSRF-Token": "test_csrf_tok"},
    )
    assert res_g.status_code == 403
    assert calls == []

    # 2. Admin simulating guest role
    sim_guest_client = _setup_client(app, role="guest", real_role="admin", username="admin")
    res_sg = sim_guest_client.post(
        "/api/environment/switch",
        json={"env": "office"},
        headers={"X-CSRF-Token": "test_csrf_tok"},
    )
    assert res_sg.status_code == 403
    assert calls == []

    # 3. Spoofed real_role != admin
    spoof_client = _setup_client(app, role="admin", real_role="guest", username="guest2")
    res_sp = spoof_client.post(
        "/api/environment/switch",
        json={"env": "office"},
        headers={"X-CSRF-Token": "test_csrf_tok"},
    )
    assert res_sp.status_code == 403
    assert calls == []


def test_env_switch_rejects_missing_csrf_and_unknown_env(tmp_path, monkeypatch):
    monkeypatch.setattr("web.api._get_data_dir", lambda: tmp_path)
    calls = []
    app = create_app()
    app.config["TESTING"] = True
    app.config["ENV_RESTART_HANDLER"] = lambda target, frm, who: calls.append((target, frm, who))

    admin_client = _setup_client(app, role="admin", username="admin")

    # Missing CSRF rejected
    res_nocsrf = admin_client.post("/api/environment/switch", json={"env": "office"})
    assert res_nocsrf.status_code == 403
    assert calls == []

    # Unknown env rejected against registry's known names
    assert "mars" not in security.registry.list_environments()
    res_unk = admin_client.post(
        "/api/environment/switch",
        json={"env": "mars"},
        headers={"X-CSRF-Token": "test_csrf_tok"},
    )
    assert res_unk.status_code == 400
    assert "Unknown environment" in (res_unk.get_json() or {}).get("error", "")
    assert calls == []


def test_env_switch_refuses_when_approval_pending_or_request_running(tmp_path, monkeypatch):
    monkeypatch.setattr("web.api._get_data_dir", lambda: tmp_path)
    calls = []
    app = create_app()
    app.config["TESTING"] = True
    app.config["ENV_RESTART_HANDLER"] = lambda target, frm, who: calls.append((target, frm, who))
    admin_client = _setup_client(app, role="admin", username="admin")

    # 1. Pending approval blocks switch
    pending_dir = tmp_path / "approvals" / "pending"
    pending_dir.mkdir(parents=True)
    future_iso = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
    pending_file = pending_dir / "req_123.json"
    pending_file.write_text(json.dumps({"request_id": "req_123", "expires_at": future_iso}), encoding="utf-8")

    res_pend = admin_client.post(
        "/api/environment/switch",
        json={"env": "office"},
        headers={"X-CSRF-Token": "test_csrf_tok"},
    )
    assert res_pend.status_code == 409
    assert "approval is pending" in (res_pend.get_json() or {}).get("error", "").lower()
    assert calls == []

    pending_file.unlink()

    # 2. Active running request in inbox without final outbox blocks switch
    inbox_dir = tmp_path / "chat" / "inbox"
    inbox_dir.mkdir(parents=True)
    (inbox_dir / "req_active.json").write_text(json.dumps({"id": "req_active", "text": "hi"}), encoding="utf-8")

    res_run = admin_client.post(
        "/api/environment/switch",
        json={"env": "office"},
        headers={"X-CSRF-Token": "test_csrf_tok"},
    )
    assert res_run.status_code == 409
    assert "running" in (res_run.get_json() or {}).get("error", "").lower()
    assert calls == []


def test_env_switch_writes_audit_event_and_calls_injected_restart(tmp_path, monkeypatch):
    monkeypatch.setattr("web.api._get_data_dir", lambda: tmp_path)
    log_file = tmp_path / "audit.jsonl"
    monkeypatch.setattr(security.logger, "_custom_log_file", log_file)

    calls = []
    app = create_app()
    app.config["TESTING"] = True
    app.config["ENV_RESTART_HANDLER"] = lambda target, frm, who: calls.append((target, frm, who))
    admin_client = _setup_client(app, role="admin", username="alice_admin")

    res = admin_client.post(
        "/api/environment/switch",
        json={"env": "office"},
        headers={"X-CSRF-Token": "test_csrf_tok"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "restarting"
    assert body["restarting"] is True
    assert body["from"] == "smart_home"
    assert body["environment"] == "office"

    assert calls == [("office", "smart_home", "alice_admin")]

    entries = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    switch_events = [e for e in entries if e.get("event") == "env_switch"]
    assert len(switch_events) == 1
    ev = switch_events[0]
    assert ev["who"] == "alice_admin"
    assert ev["from"] == "smart_home"
    assert ev["to"] == "office"


def test_topbar_shows_switch_menu_only_for_admin():
    app = create_app()
    app.config["TESTING"] = True

    admin_client = _setup_client(app, role="admin", username="admin")
    html_admin = admin_client.get("/overview").get_data(as_text=True)
    assert 'id="env-dropdown"' in html_admin
    assert 'id="btn-env-switch"' in html_admin
    assert "Switch to Office" in html_admin

    guest_client = _setup_client(app, role="guest", username="guest")
    html_guest = guest_client.get("/overview").get_data(as_text=True)
    assert 'id="sim-chip"' in html_guest
    assert 'id="env-dropdown"' not in html_guest
    assert 'id="btn-env-switch"' not in html_guest
