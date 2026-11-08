import json
import os
import urllib.error
from unittest.mock import MagicMock, patch
import pytest

from agent.agent import run_turn
from agent.tools import (
    read_temperature,
    set_weather_fetcher,
    get_weather_fetcher,
    validate_city_name,
)
import security.policy_loader


@pytest.fixture(autouse=True)
def cleanup_weather_fetcher():
    """Ensures weather fetcher is cleanly reset after every test."""
    set_weather_fetcher(None)
    yield
    set_weather_fetcher(None)


def test_weather_valid_city_via_fake():
    """Valid city via fake fetcher returns exact Open-Meteo output text format."""
    def fake_fetcher(url: str):
        if "geocoding-api.open-meteo.com" in url:
            assert "name=Mumbai" in url
            return {
                "results": [{
                    "name": "Mumbai",
                    "latitude": 19.07283,
                    "longitude": 72.88261,
                    "admin1": "Maharashtra",
                    "country": "India"
                }]
            }
        elif "api.open-meteo.com" in url:
            assert "latitude=19.07283" in url
            return {
                "current": {
                    "temperature_2m": 28.0,
                    "relative_humidity_2m": 36,
                    "weather_code": 0
                }
            }
        raise ValueError(f"Unexpected url: {url}")

    set_weather_fetcher(fake_fetcher)
    res = read_temperature(location="Mumbai")

    assert res.get("status") == "success"
    assert res.get("value_celsius") == 28.0
    assert res.get("humidity") == 36
    assert res.get("condition") == "Clear sky"
    assert res.get("location") == "Mumbai, Maharashtra, India"
    assert res.get("text") == "Mumbai, Maharashtra, India: 28.0 C, humidity 36%, Clear sky. Live data from Open-Meteo."


def test_weather_unknown_city():
    """If geocoder returns no result, reply 'I couldn't find a place called <city>'."""
    def fake_fetcher(url: str):
        return {"generationtime_ms": 0.1}

    set_weather_fetcher(fake_fetcher)
    res = read_temperature(location="Xyzzyland")

    assert res.get("status") == "error"
    assert res.get("text") == "I couldn't find a place called 'Xyzzyland'."


def test_weather_invalid_characters():
    """Invalid characters or lengths are rejected before any network call."""
    invalid_cases = ["../etc", "Jodhpur; DROP", "A", "X" * 61, "Delhi<script>", "1234"]
    for case in invalid_cases:
        res = read_temperature(location=case)
        assert res.get("status") == "error"
        assert res.get("text") == "That doesn't look like a place name."


def test_weather_no_network_on_validation_failure():
    """When validation fails, no network call or injected fetch is made."""
    called = []
    def fake_fetcher(url: str):
        called.append(url)
        return {}

    set_weather_fetcher(fake_fetcher)
    res = read_temperature(location="Jodhpur; DROP")

    assert len(called) == 0
    assert res.get("text") == "That doesn't look like a place name."


def test_weather_network_failure():
    """If network fails or times out, reply 'The weather service could not be reached right now.'."""
    def fake_fetcher(url: str):
        raise urllib.error.URLError("Connection timed out")

    set_weather_fetcher(fake_fetcher)
    res = read_temperature(location="Mumbai")

    assert res.get("status") == "error"
    assert res.get("text") == "The weather service could not be reached right now."


def test_weather_default_city():
    """Default city comes from AEGIS_DEFAULT_CITY (default 'Jodhpur') when no city is given."""
    captured_urls = []
    def fake_fetcher(url: str):
        captured_urls.append(url)
        if "geocoding" in url:
            return {"results": [{"name": "Jodhpur", "latitude": 26.26, "longitude": 73.0, "country": "India"}]}
        return {"current": {"temperature_2m": 25.0, "relative_humidity_2m": 40, "weather_code": 0}}

    set_weather_fetcher(fake_fetcher)
    with patch.dict(os.environ, {"AEGIS_DEFAULT_CITY": "Jodhpur"}):
        res = read_temperature()
        assert "name=Jodhpur" in captured_urls[0]
        assert "Jodhpur" in res.get("text", "")


def test_weather_benchmark_mode_deterministic():
    """In benchmark mode without fake fetcher, returns simulated old value and no network calls."""
    with patch.dict(os.environ, {"AEGIS_BENCHMARK": "1"}):
        res = read_temperature(location="Jodhpur")
        assert res.get("status") == "success"
        assert res.get("value_celsius") == 24.5
        assert res.get("condition") == "Fair / Clear"
        assert "simulated" in res.get("source", "").lower() or "(simulated)" in res.get("location", "")


def test_weather_mocked_injection_triggers_output_scan():
    """Tainted output from weather service containing prompt injection is blocked by output scanner."""
    def fake_fetcher(url: str):
        if "geocoding" in url:
            return {
                "results": [{
                    "name": "Jodhpur",
                    "latitude": 26.26,
                    "longitude": 73.0,
                    "admin1": "Rajasthan",
                    "country": "India"
                }]
            }
        return {
            "current": {
                "temperature_2m": 30.0,
                "relative_humidity_2m": 50,
                "weather_code": 0
            }
        }

    set_weather_fetcher(fake_fetcher)

    # Injected city name that gets scanned by output scanner
    mock_turn = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "read_temperature",
                        "arguments": {"location": "Jodhpur"},
                    }
                }
            ],
        }
    }

    with patch("ollama.chat", return_value=mock_turn):
        res = run_turn(text="What is the temperature in Jodhpur?", role="admin", session_id="test_weather_inj")
        assert res.decision == "ALLOW"
        assert "Live data from Open-Meteo" in (res.reply or "")



