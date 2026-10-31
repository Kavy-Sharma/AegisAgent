"""
Tests for exact ACK matching in security/hardware.py (MQTT and Serial).

Requirements:
(a) exact "light_off_done" accepted
(b) with "EVENT: " prefix accepted
(c) "light" or "done" alone rejected
(d) "xx light_off_done yy" rejected
"""

import pytest
from security.hardware import _ack_ok, _serial_ack_ok, _normalize_ack


def test_ack_exact_accepted():
    """(a) exact 'light_off_done' accepted without prefixes or extra padding."""
    target = "light_off_done"

    # MQTT matching
    assert _ack_ok("light_off_done", target) is True

    # Serial line matching
    assert _serial_ack_ok("light_off_done\r\n", target) is True
    assert _serial_ack_ok("BOOT\nlight_off_done\nREADY", target) is True


def test_ack_with_event_prefix_accepted():
    """(b) with 'EVENT: ' prefix accepted for both payload and target."""
    target = "light_off_done"

    # MQTT with EVENT: prefix on payload
    assert _ack_ok("EVENT: light_off_done", target) is True
    assert _ack_ok("EVENT:light_off_done", target) is True

    # MQTT with EVENT: prefix on target
    assert _ack_ok("light_off_done", "EVENT: light_off_done") is True
    assert _ack_ok("EVENT: light_off_done", "EVENT: light_off_done") is True

    # Serial with EVENT: prefix in stream lines
    assert _serial_ack_ok("EVENT: light_off_done\r\n", target) is True
    assert _serial_ack_ok("EVENT:light_off_done\n", target) is True
    assert _serial_ack_ok("LOG: startup\r\nEVENT: light_off_done\r\nSTATUS: ok", target) is True


def test_ack_partial_words_rejected():
    """(c) 'light' or 'done' alone rejected (no substring false-positives)."""
    target = "light_off_done"

    # MQTT partial substrings
    assert _ack_ok("light", target) is False
    assert _ack_ok("done", target) is False
    assert _ack_ok("off", target) is False
    assert _ack_ok("light_off", target) is False

    # Serial partial substrings
    assert _serial_ack_ok("light\r\n", target) is False
    assert _serial_ack_ok("done\r\n", target) is False
    assert _serial_ack_ok("light\r\ndone\r\n", target) is False
    assert _serial_ack_ok("EVENT: light\r\n", target) is False


def test_ack_embedded_substring_rejected():
    """(d) 'xx light_off_done yy' rejected (no substring matching within lines)."""
    target = "light_off_done"

    # MQTT with embedded text
    assert _ack_ok("xx light_off_done yy", target) is False
    assert _ack_ok("xxlight_off_doneyy", target) is False
    assert _ack_ok("EVENT: xx light_off_done yy", target) is False

    # Serial with embedded text in lines
    assert _serial_ack_ok("xx light_off_done yy\r\n", target) is False
    assert _serial_ack_ok("line1\r\nxx light_off_done yy\r\nline2\r\n", target) is False
    assert _serial_ack_ok("EVENT: xx light_off_done yy\r\n", target) is False

