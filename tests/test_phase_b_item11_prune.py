import json
import os
import time
from pathlib import Path
import pytest
from web.api import _get_data_dir


def test_prune_outbox_older_than_24h():
    """VULN-08: Files in outbox older than 24h must be pruned."""
    from agent.worker import prune_stale_files

    data_dir = _get_data_dir()
    outbox_dir = data_dir / "chat" / "outbox"
    outbox_dir.mkdir(parents=True, exist_ok=True)

    old_file = outbox_dir / "req_old_25h.jsonl"
    fresh_file = outbox_dir / "req_fresh.jsonl"

    old_file.write_text("old data", encoding="utf-8")
    fresh_file.write_text("fresh data", encoding="utf-8")

    # Set old_file mtime to 25 hours ago
    t_25h_ago = time.time() - (25 * 3600)
    os.utime(old_file, (t_25h_ago, t_25h_ago))

    prune_stale_files(data_dir)

    assert not old_file.exists(), "Old outbox file >24h was not pruned!"
    assert fresh_file.exists(), "Fresh outbox file was incorrectly pruned!"


def test_purge_stale_pending_and_decisions():
    """VULN-08: Expired pending approvals and decisions >24h must be purged."""
    from agent.worker import prune_stale_files

    data_dir = _get_data_dir()
    pending_dir = data_dir / "approvals" / "pending"
    decisions_dir = data_dir / "approvals" / "decisions"
    pending_dir.mkdir(parents=True, exist_ok=True)
    decisions_dir.mkdir(parents=True, exist_ok=True)

    # 1. Expired pending file
    expired_pending = pending_dir / "req_expired.json"
    expired_pending.write_text(json.dumps({
        "request_id": "req_expired",
        "expires_at": time.time() - 3600,  # expired 1 hr ago
    }), encoding="utf-8")

    # 2. Fresh pending file
    fresh_pending = pending_dir / "req_valid.json"
    fresh_pending.write_text(json.dumps({
        "request_id": "req_valid",
        "expires_at": time.time() + 3600,  # valid for 1 hr
    }), encoding="utf-8")

    # 3. Old decision file >24h
    old_decision = decisions_dir / "req_old_dec.json"
    old_decision.write_text(json.dumps({"request_id": "req_old_dec"}), encoding="utf-8")
    t_25h_ago = time.time() - (25 * 3600)
    os.utime(old_decision, (t_25h_ago, t_25h_ago))

    # 4. Fresh decision file
    fresh_decision = decisions_dir / "req_fresh_dec.json"
    fresh_decision.write_text(json.dumps({"request_id": "req_fresh_dec"}), encoding="utf-8")

    prune_stale_files(data_dir)

    assert not expired_pending.exists(), "Expired pending approval was not purged!"
    assert fresh_pending.exists(), "Fresh pending approval was incorrectly purged!"
    assert not old_decision.exists(), "Decision file >24h was not purged!"
    assert fresh_decision.exists(), "Fresh decision file was incorrectly purged!"

