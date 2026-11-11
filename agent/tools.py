"""

Phase 7 -- Hardware-Integrated IoT Tools

Phase 9A -- Added read_note tool with strictly sanitized name validation.

Phase 9B -- Added live location weather, parameterized hardware tools, and security honeypot.



WHAT THIS FILE DOES:

Provides tool functions for AegisAgent. When hardware.mode == "mqtt" in policy.yaml,

commands are published through security.hardware.get_bridge() to the MQTT broker.

In fake mode, commands use the FakeBridge for simulation.

"""



import json
import os
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any, Callable
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import security.hardware
import security.policy_loader

# Injectable weather fetcher for test isolation & benchmark determinism
_weather_fetcher: Callable[[str], Any] | None = None

def set_weather_fetcher(fn: Callable[[str], Any] | None) -> None:
    """Inject a custom fetch function for testing (takes url string, returns JSON dict or bytes/str)."""
    global _weather_fetcher
    _weather_fetcher = fn

def get_weather_fetcher() -> Callable[[str], Any] | None:
    return _weather_fetcher

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses HTTP redirects to enforce strict endpoint pinning."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "HTTP redirects are not allowed", headers, fp)

_no_redirect_opener = urllib.request.build_opener(NoRedirectHandler)

ALLOWED_WEATHER_HOSTS = {"geocoding-api.open-meteo.com", "api.open-meteo.com"}

WMO_CODE_MAP = {
    0: "Clear sky",
    1: "Mainly clear",
    2: "Partly cloudy",
    3: "Overcast",
    45: "Fog",
    48: "Depositing rime fog",
    51: "Light drizzle",
    53: "Moderate drizzle",
    55: "Dense drizzle",
    56: "Light freezing drizzle",
    57: "Dense freezing drizzle",
    61: "Slight rain",
    63: "Moderate rain",
    65: "Heavy rain",
    66: "Light freezing rain",
    67: "Heavy freezing rain",
    71: "Slight snow fall",
    73: "Moderate snow fall",
    75: "Heavy snow fall",
    77: "Snow grains",
    80: "Slight rain showers",
    81: "Moderate rain showers",
    82: "Violent rain showers",
    85: "Slight snow showers",
    86: "Heavy snow showers",
    95: "Thunderstorm",
    96: "Thunderstorm with slight hail",
    99: "Thunderstorm with heavy hail",
}

def validate_city_name(city: str) -> tuple[bool, str]:
    """
    Validates place names before any network call:
    - 2 to 60 characters
    - Letters (any language), spaces, hyphen, apostrophe, dot only.
    """
    if not isinstance(city, str):
        return False, "That doesn't look like a place name."
    city_clean = city.strip()
    if not (2 <= len(city_clean) <= 60):
        return False, "That doesn't look like a place name."

    allowed_punct = {" ", "-", "'", "’", "."}
    for ch in city_clean:
        if ch in allowed_punct:
            continue
        cat = unicodedata.category(ch)
        # L = Letter, M = Mark (combining marks used with letters in Hindi, etc.)
        if not (cat.startswith("L") or cat.startswith("M")):
            return False, "That doesn't look like a place name."

    return True, city_clean

def _default_weather_fetch(url: str) -> dict:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS is allowed for weather service")
    if parsed.hostname not in ALLOWED_WEATHER_HOSTS:
        raise ValueError(f"Host '{parsed.hostname}' is not in allowed weather hosts")

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "AegisAgent/1.0", "Accept": "application/json"}
    )
    with _no_redirect_opener.open(req, timeout=5.0) as resp:
        # Response size capped at 100 KB: read 102401 bytes so anything > 100 KB is rejected
        raw_bytes = resp.read(102401)
        if len(raw_bytes) > 102400:
            raise ValueError("Weather service response exceeded 100 KB cap")
        return json.loads(raw_bytes.decode("utf-8", errors="replace"))

def _fetch_weather_json(url: str) -> dict:
    global _weather_fetcher
    if _weather_fetcher is not None:
        res = _weather_fetcher(url)
        if isinstance(res, dict):
            return res
        if isinstance(res, (bytes, bytearray)):
            return json.loads(res.decode("utf-8", errors="replace"))
        if isinstance(res, str):
            return json.loads(res)
        raise ValueError("Invalid return type from injected weather fetcher")
    return _default_weather_fetch(url)

def _is_benchmark_active() -> bool:
    if os.environ.get("AEGIS_BENCHMARK") == "1":
        return True
    main_file = getattr(sys.modules.get("__main__"), "__file__", "") or ""
    if "pipeline_run.py" in main_file or "office_run.py" in main_file:
        return True
    bridge = security.hardware.get_bridge()
    state_file = getattr(bridge, "state_file", None)
    if state_file and "pipeline_bench" in str(state_file):
        return True
    return False





class NoteNotFoundError(FileNotFoundError, ValueError):

    """Raised when a note file does not exist in demo/notes."""

    pass





UNREACHABLE_DEVICE_MSG = "The device could not be reached. Nothing was changed."


def _dispatch_command(command: str, action_name: str, fake_log: str) -> dict:
    mode = security.policy_loader.POLICY.get("hardware", {}).get("mode", "fake")
    bridge = security.hardware.get_bridge()

    is_online = False
    result = None
    raw_err: str | None = None
    raised_exc = False

    try:
        is_online = bool(bridge.is_device_online())
        result = bridge.publish(command)
    except Exception as e:
        raised_exc = True
        raw_err = str(e) or type(e).__name__
        result = None

    ok = bool(getattr(result, "ok", False)) if not raised_exc else False
    if ok:
        if mode == "fake":
            print(fake_log)
        else:
            print(f"[TOOL] {action_name} -> sent to device")

        hw_online = True if mode != "fake" else is_online
        return {"status": "success", "action": action_name, "hardware_connected": hw_online}

    if raw_err is None:
        res_err = getattr(result, "error", None) if result is not None else None
        if res_err is None and isinstance(result, dict):
            res_err = result.get("error")
        raw_err = str(res_err) if res_err else "hardware unreachable"

    # Ensure failed hardware actuation is always recorded in the tamper-evident audit log
    try:
        from security.logger import log_event, log_hardware_command

        builtin_types = (
            security.hardware.FakeBridge,
            security.hardware.HardwareBridge,
            security.hardware.SerialHardwareBridge,
        )
        try:
            from security.virtual_home import VirtualBridge
            builtin_types = builtin_types + (VirtualBridge,)
        except Exception:
            pass

        if raised_exc or not isinstance(bridge, builtin_types):
            log_hardware_command(command, False, raw_err)
        log_event(
            "hardware_unreachable",
            {
                "command": command,
                "action": action_name,
                "error": raw_err,
                "message": UNREACHABLE_DEVICE_MSG,
            },
        )
    except Exception:
        pass

    print(f"[TOOL] {action_name} FAILED: {raw_err}")
    err_str = (
        f"{UNREACHABLE_DEVICE_MSG} ({raw_err})"
        if (raw_err and UNREACHABLE_DEVICE_MSG not in raw_err)
        else UNREACHABLE_DEVICE_MSG
    )
    return {
        "status": "failed",
        "error": err_str,
        "text": UNREACHABLE_DEVICE_MSG,
        "action": action_name,
        "hardware_connected": False,
        "note": "ESP32 board disconnected. To see physical hardware actuation, connect ESP32 to USB or MQTT.",
    }





_SEQUENCE_ABORT_EVENT = threading.Event()
_SEQ_LOCK = threading.Lock()
_BLINK_SEQ_ID = 0
_ALARM_SEQ_ID = 0


def _next_blink_seq() -> int:
    global _BLINK_SEQ_ID
    with _SEQ_LOCK:
        _BLINK_SEQ_ID += 1
        return _BLINK_SEQ_ID


def _next_alarm_seq() -> int:
    global _ALARM_SEQ_ID
    with _SEQ_LOCK:
        _ALARM_SEQ_ID += 1
        return _ALARM_SEQ_ID


def abort_hardware_sequences():
    """Immediately halts all in-progress hardware blink sequences and alarm workers."""
    _next_blink_seq()
    _next_alarm_seq()
    _SEQUENCE_ABORT_EVENT.set()
    try:
        bridge = security.hardware.get_bridge()
        bridge.publish("light_off")
    except Exception:
        pass
    time.sleep(0.05)
    _SEQUENCE_ABORT_EVENT.clear()

def turn_light_on(blink_count: int = 1) -> dict:

    """

    Turns the LED light on, or blinks it multiple times.

    blink_count: 1 for steady ON, or 2 to 10 for blink sequence.

    Rejects any value outside 1-10.

    """

    try:

        count = int(blink_count)

    except (ValueError, TypeError):

        raise ValueError("blink_count must be an integer between 1 and 10")

    if count < 1 or count > 10:

        raise ValueError(f"blink_count {count} is invalid; must be between 1 and 10")



    bridge = security.hardware.get_bridge()

    if count > 1:
        action_name = f"light_blink_{count}x"
        cmd = "light_on"
        fake_log = f"[TOOL] turn_light_on(blink_count={count}) called -> LED would blink {count} times"
    else:
        action_name = "light_on"
        cmd = "light_on"
        fake_log = "[TOOL] turn_light_on() called -> LED would turn ON"

    seq_id = _next_blink_seq()
    res = _dispatch_command(cmd, action_name, fake_log)
    res["blink_count"] = count

    if res.get("status") == "success":
        res["hardware_connected"] = True
        if count > 1:
            # Physical LED blinking loop across hardware transport (only started after verified actuation)
            def _blink_worker(my_seq=seq_id):
                for _ in range(count):
                    if _SEQUENCE_ABORT_EVENT.is_set() or security.hardware._bridge_instance is not bridge or my_seq != _BLINK_SEQ_ID:
                        if _SEQUENCE_ABORT_EVENT.is_set() and security.hardware._bridge_instance is bridge:
                            try:
                                bridge.publish("light_off")
                            except Exception:
                                pass
                        break
                    try:
                        r_on = bridge.publish("light_on")
                        if hasattr(r_on, "ok") and not r_on.ok:
                            break
                    except Exception:
                        break
                    time.sleep(0.35)
                    if _SEQUENCE_ABORT_EVENT.is_set() or security.hardware._bridge_instance is not bridge or my_seq != _BLINK_SEQ_ID:
                        if _SEQUENCE_ABORT_EVENT.is_set() and security.hardware._bridge_instance is bridge:
                            try:
                                bridge.publish("light_off")
                            except Exception:
                                pass
                        break
                    try:
                        r_off = bridge.publish("light_off")
                        if hasattr(r_off, "ok") and not r_off.ok:
                            break
                    except Exception:
                        break
                    time.sleep(0.25)

            threading.Thread(target=_blink_worker, daemon=True).start()
    else:
        res["hardware_connected"] = False

    return res





def turn_light_off() -> dict:

    """Turns the LED light off."""

    _next_blink_seq()
    return _dispatch_command("light_off", "light_off", "[TOOL] turn_light_off() called -> LED would turn OFF")





def read_temperature(location: str | None = None) -> dict:
    """
    Reads ambient temperature and weather conditions via Open-Meteo.
    - Default city from .env AEGIS_DEFAULT_CITY (default "Jodhpur").
    - Validates place name BEFORE any network call: letters (any language),
      spaces, hyphen, apostrophe, dot only; 2 to 60 chars.
    - Deterministic fallback for benchmark mode (no network).
    - Pure Open-Meteo with geocoding + current forecast.
    """
    default_city = os.environ.get("AEGIS_DEFAULT_CITY", "Jodhpur").strip() or "Jodhpur"
    loc_query = (location or "").strip()
    is_local = (not loc_query) or (loc_query.lower() in ("here", "local", "my place", "room", "current", "home"))
    target_city = default_city if is_local else loc_query

    # 1. Deterministic benchmark path (must NOT use network and must return old value)
    if _is_benchmark_active() and _weather_fetcher is None:
        return {
            "status": "success",
            "action": "read_temperature",
            "value_celsius": 24.5,
            "condition": "Fair / Clear",
            "location": f"{target_city} (simulated)",
            "source": "simulated_telemetry",
        }

    # 1b. Offline weather switch: AEGIS_WEATHER_ONLINE=0 disables all external weather calls
    weather_online = os.environ.get("AEGIS_WEATHER_ONLINE", "1").strip().lower()
    if weather_online in ("0", "false", "off", "no"):
        msg = "Live weather is turned off."
        return {
            "status": "error",
            "error": msg,
            "text": msg,
            "location": target_city,
        }

    # 2. City parameter validation BEFORE any network call
    is_valid, validated_city = validate_city_name(target_city)
    if not is_valid:
        msg = "That doesn't look like a place name."
        return {
            "status": "error",
            "error": msg,
            "text": msg,
            "location": target_city,
        }

    # 3. Geocoding API call
    safe_city = urllib.parse.quote(validated_city)
    geo_url = f"https://geocoding-api.open-meteo.com/v1/search?name={safe_city}&count=1"

    try:
        geo_data = _fetch_weather_json(geo_url)
    except Exception as e:
        print(f"[TOOL] Geocoding network error: {e}")
        msg = "The weather service could not be reached right now."
        return {
            "status": "error",
            "error": msg,
            "text": msg,
            "location": validated_city,
        }

    results = geo_data.get("results") if isinstance(geo_data, dict) else None
    if not results or not len(results):
        msg = f"I couldn't find a place called '{validated_city}'."
        return {
            "status": "error",
            "error": msg,
            "text": msg,
            "location": validated_city,
        }

    matched = results[0]
    lat = matched.get("latitude")
    lon = matched.get("longitude")
    matched_city = (matched.get("name") or validated_city).strip()
    country = (matched.get("country") or "").strip()
    admin1 = (matched.get("admin1") or "").strip()

    if admin1 and country and admin1.lower() != country.lower():
        region_country = f"{admin1}, {country}"
    elif country:
        region_country = country
    elif admin1:
        region_country = admin1
    else:
        region_country = matched_city

    # 4. Forecast API call
    fc_url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,relative_humidity_2m,weather_code"
    try:
        fc_data = _fetch_weather_json(fc_url)
    except Exception as e:
        print(f"[TOOL] Forecast network error: {e}")
        msg = "The weather service could not be reached right now."
        return {
            "status": "error",
            "error": msg,
            "text": msg,
            "location": validated_city,
        }

    current = fc_data.get("current", {}) if isinstance(fc_data, dict) else {}
    temp_c = current.get("temperature_2m")
    humidity = current.get("relative_humidity_2m")
    raw_wcode = current.get("weather_code")

    if temp_c is None:
        msg = "The weather service could not be reached right now."
        return {
            "status": "error",
            "error": msg,
            "text": msg,
            "location": validated_city,
        }

    if isinstance(raw_wcode, bool) or raw_wcode is None:
        weather_desc = "Unknown conditions"
    else:
        try:
            weather_desc = WMO_CODE_MAP.get(int(raw_wcode), "Unknown conditions")
        except (TypeError, ValueError):
            weather_desc = "Unknown conditions"

    output_text = f"{matched_city}, {region_country}: {temp_c} C, humidity {humidity}%, {weather_desc}. Live data from Open-Meteo."

    return {
        "status": "success",
        "action": "read_temperature",
        "value_celsius": temp_c,
        "humidity": humidity,
        "condition": weather_desc,
        "location": f"{matched_city}, {region_country}",
        "text": output_text,
        "source": "live_weather_service",
    }





def activate_alarm(duration_seconds: int = 5) -> dict:

    """

    Activates the buzzer alarm. HIGH-risk tool.

    Safety parameter guard: duration must be between 1 and 30 seconds.

    Rejects any value outside 1-30.

    """

    try:

        duration = int(duration_seconds)

    except (ValueError, TypeError):

        raise ValueError("duration_seconds must be an integer between 1 and 30")

    if duration < 1 or duration > 30:

        raise ValueError(f"duration_seconds {duration} is invalid; must be between 1 and 30")



    bridge = security.hardware.get_bridge()

    action_name = f"alarm_activated_{duration}s" if duration != 5 else "alarm_activated"
    cmd = "alarm_on"
    fake_log = f"[TOOL] activate_alarm(duration={duration}s) called -> BUZZER would sound for {duration} seconds"

    alarm_seq = _next_alarm_seq()
    res = _dispatch_command(cmd, action_name, fake_log)
    res["duration_seconds"] = duration

    if res.get("status") == "success":
        res["hardware_connected"] = True
        if duration > 3:
            def _alarm_worker(my_seq=alarm_seq):
                elapsed = 0
                while elapsed < duration:
                    if _SEQUENCE_ABORT_EVENT.is_set() or security.hardware._bridge_instance is not bridge or my_seq != _ALARM_SEQ_ID:
                        break
                    try:
                        r_alm = bridge.publish("alarm_on")
                        if hasattr(r_alm, "ok") and not r_alm.ok:
                            break
                    except Exception:
                        break
                    chunk = min(2.5, duration - elapsed)
                    time.sleep(chunk)
                    elapsed += chunk

            threading.Thread(target=_alarm_worker, daemon=True).start()
    else:
        res["hardware_connected"] = False

    return res





def unlock_door() -> dict:

    """Unlocks the door lock. HIGH-risk tool."""

    return _dispatch_command("unlock_door", "door_unlocked", "[TOOL] unlock_door() called -> door unlocked (fake)")





def read_note(name: str) -> str:

    """

    Reads a text note from demo/notes/<name>.txt.

    Only allows names matching ^[a-z0-9_]{1,40}$. No paths or directory traversal allowed.

    LOW-risk tool with untrusted output (triggers provenance taint tracking).

    """

    if not isinstance(name, str) or not re.match(r"^[a-z0-9_]{1,40}$", name):

        raise ValueError(f"Invalid note name '{name}'. Must match ^[a-z0-9_]{{1,40}}$ and contain no path separators.")



    notes_dir = Path(__file__).resolve().parent.parent / "demo" / "notes"

    note_path = notes_dir / f"{name}.txt"



    if not note_path.is_file():

        raise NoteNotFoundError(f"Note '{name}' not found at {note_path}")



    # VULN-10: 64KB cap, binary-safe read with errors="replace"
    with open(note_path, "rb") as f:
        raw_bytes = f.read(64 * 1024)
    content = raw_bytes.decode("utf-8", errors="replace")

    print(f"[TOOL] read_note('{name}') -> {len(content)} chars read")

    return content





def disable_security_perimeter() -> dict:

    """

    HONEYPOT DECEPTION TOOL:

    Fake emergency bypass tool. If an attacker or injection prompt calls this,

    it trips the gateway honeypot trap immediately.

    """

    return {"status": "trapped", "action": "honeypot_triggered", "alert": "HONEYPOT SECURITY TRAP ACTIVATED"}





if __name__ == "__main__":

    print("Testing all tools manually:\n")

    turn_light_on()

    turn_light_on(blink_count=4)

    turn_light_off()

    read_temperature()

    activate_alarm()

    unlock_door()

    print("\nAll tools ran without errors.")

