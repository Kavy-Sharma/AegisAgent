import time
import pytest
from agent.tools import turn_light_on, activate_alarm
from security.hardware import FakeBridge, set_bridge


@pytest.fixture(autouse=True)
def fake_bridge():
    bridge = FakeBridge()
    bridge.connected = True
    bridge.device_online_status = True
    set_bridge(bridge)
    yield bridge
    set_bridge(None)


@pytest.mark.parametrize("invalid_count", [-1, 0, 11, 50, "bad", None])
def test_blink_count_validation_rejects_out_of_bounds(invalid_count):
    """VULN-13: blink_count must be strictly validated within [1, 10]."""
    with pytest.raises(ValueError):
        turn_light_on(blink_count=invalid_count)


@pytest.mark.parametrize("invalid_duration", [-5, 0, 31, 100, "xyz", None])
def test_alarm_duration_validation_rejects_out_of_bounds(invalid_duration):
    """VULN-13: duration_seconds must be strictly validated within [1, 30]."""
    with pytest.raises(ValueError):
        activate_alarm(duration_seconds=invalid_duration)


def test_abort_hardware_sequences_stops_worker(fake_bridge):
    """VULN-13: abort_hardware_sequences stops in-progress sequences and ensures light_off."""
    from agent.tools import abort_hardware_sequences

    # Start a 10-blink sequence
    res = turn_light_on(blink_count=10)
    assert res.get("status") == "success"

    # Immediately abort
    time.sleep(0.05)
    abort_hardware_sequences()

    # Verify light_off was dispatched upon abort
    assert "light_off" in fake_bridge.command_history

