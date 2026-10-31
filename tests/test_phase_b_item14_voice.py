import re
from pathlib import Path
import pytest
import security.policy_loader
from agent.agent import sanitize_spoken_text


def test_voice_policy_default_disabled():
    """VULN-14: voice.enabled must be false by default in policy.yaml."""
    cfg = security.policy_loader.POLICY.get("voice", {})
    assert cfg.get("enabled", False) is False, "voice.enabled is not False in policy.yaml!"


def test_no_hashes_or_ids_in_spoken_text():
    """VULN-14: Text generated for text-to-speech must not speak raw cryptographic hashes or request IDs."""
    test_raw = "Hardware failed with Error ID: 9f8a1b2c and hash a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90 for req_999888777"
    cleaned = sanitize_spoken_text(test_raw)
    assert "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90" not in cleaned
    assert "req_999888777" not in cleaned
    assert "9f8a1b2c" not in cleaned


def test_voice_polling_timeout_greater_than_policy_plus_10s():
    """VULN-14: Client-side voice polling timeout must be >= policy approval timeout + 10s."""
    js_file = Path(__file__).resolve().parent.parent / "web" / "static" / "js" / "voice_sphere.js"
    js_text = js_file.read_text(encoding="utf-8")

    match = re.search(r"Date\.now\(\)\s*-\s*startTime\s*>\s*(\d+)", js_text)
    assert match is not None, "Could not find voice polling timeout in voice_sphere.js"
    timeout_ms = int(match.group(1))
    timeout_sec = timeout_ms / 1000.0

    policy_approval_timeout = float(security.policy_loader.POLICY.get("approval", {}).get("timeout_seconds", 60.0))
    required_min = policy_approval_timeout + 10.0

    assert timeout_sec >= required_min, f"Voice polling timeout ({timeout_sec}s) is less than required ({required_min}s)"

