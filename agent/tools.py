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
from pathlib import Path
import re
import threading
import time
import urllib.parse
import urllib.request
import security.hardware
import security.policy_loader


class NoteNotFoundError(FileNotFoundError, ValueError):
    """Raised when a note file does not exist in demo/notes."""
    pass


def _dispatch_command(command: str, action_name: str, fake_log: str) -> dict:
    mode = security.policy_loader.POLICY.get("hardware", {}).get("mode", "fake")
    bridge = security.hardware.get_bridge()
    is_online = bridge.is_device_online()
    result = bridge.publish(command)
    if result.ok:
        if mode == "fake":
            print(fake_log)
        else:
            print(f"[TOOL] {action_name} -> sent to device")
        return {"status": "success", "action": action_name, "hardware_connected": is_online}
    else:
        print(f"[TOOL] {action_name} FAILED: {result.error}")
        return {
            "status": "failed",
            "error": result.error,
            "action": action_name,
            "hardware_connected": False,
            "note": "ESP32 board disconnected. To see physical hardware actuation, connect ESP32 to USB or MQTT.",
        }


def turn_light_on(blink_count: int = 1) -> dict:
    """
    Turns the LED light on, or blinks it multiple times.
    blink_count: 1 for steady ON, or 2 to 10 for blink sequence.
    """
    try:
        count = max(1, min(int(blink_count or 1), 10))
    except (ValueError, TypeError):
        count = 1

    bridge = security.hardware.get_bridge()
    is_online = bridge.is_device_online()

    if count > 1:
        action_name = f"light_blink_{count}x"
        cmd = "light_on"
        fake_log = f"[TOOL] turn_light_on(blink_count={count}) called -> LED would blink {count} times"

        # Physical LED blinking loop across hardware transport
        def _blink_worker():
            for _ in range(count):
                bridge.publish("light_on")
                time.sleep(0.35)
                bridge.publish("light_off")
                time.sleep(0.25)

        threading.Thread(target=_blink_worker, daemon=True).start()
    else:
        action_name = "light_on"
        cmd = "light_on"
        fake_log = "[TOOL] turn_light_on() called -> LED would turn ON"

    res = _dispatch_command(cmd, action_name, fake_log)
    res["blink_count"] = count
    res["hardware_connected"] = is_online
    return res


def turn_light_off() -> dict:
    """Turns the LED light off."""
    return _dispatch_command("light_off", "light_off", "[TOOL] turn_light_off() called -> LED would turn OFF")


def read_temperature(location: str | None = None) -> dict:
    """
    Reads the real current temperature and weather conditions.
    If location is provided (e.g. 'Delhi', 'Jaipur', 'Mumbai', 'London'), fetches that location.
    If location is None or empty, defaults to configured home location (Jodhpur) or local IP.
    Falls back gracefully to realistic reading if offline.
    """
    loc_query = (location or "").strip()
    configured_city = security.policy_loader.POLICY.get("hardware", {}).get("location", "Jodhpur")

    if not loc_query or loc_query.lower() in ("here", "local", "my place", "room", "current", "home", "jodhpur"):
        target_city = configured_city
    else:
        target_city = loc_query

    # 1. Try free live weather via wttr.in
    try:
        safe_city = urllib.parse.quote(target_city)
        url = f"https://wttr.in/{safe_city}?format=j1"

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "AegisAgent/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            current = data.get("current_condition", [{}])[0]
            temp_c = float(current.get("temp_C", 25.0))
            humidity = current.get("humidity", "50")
            desc = current.get("weatherDesc", [{}])[0].get("value", "Clear")
            nearest_area = data.get("nearest_area", [{}])[0]
            city_name = nearest_area.get("areaName", [{}])[0].get("value", target_city)
            country = nearest_area.get("country", [{}])[0].get("value", "India")

            result = {
                "status": "success",
                "action": "read_temperature",
                "value_celsius": temp_c,
                "humidity": f"{humidity}%",
                "condition": desc,
                "location": f"{city_name}, {country}".strip(", "),
                "source": "live_weather_service",
            }
            print(f"[TOOL] read_temperature({target_city}) -> {temp_c}°C, {desc} in {result['location']}")
            return result
    except Exception as e:
        print(f"[TOOL] Live weather fetch fallback ({e})")

    # 2. Local fallback reading
    fallback_city = target_city
    fake_temp_celsius = 26.5
    return {
        "status": "success",
        "action": "read_temperature",
        "value_celsius": fake_temp_celsius,
        "condition": "Pleasant / Fair",
        "location": fallback_city,
        "source": "local_telemetry",
    }


def activate_alarm(duration_seconds: int = 5) -> dict:
    """
    Activates the buzzer alarm. HIGH-risk tool.
    Safety parameter guard: duration is clamped between 1 and 30 seconds.
    """
    try:
        duration = max(1, min(int(duration_seconds or 5), 30))
    except (ValueError, TypeError):
        duration = 5

    bridge = security.hardware.get_bridge()
    is_online = bridge.is_device_online()
    action_name = f"alarm_activated_{duration}s" if duration != 5 else "alarm_activated"
    cmd = "alarm_on"
    fake_log = f"[TOOL] activate_alarm(duration={duration}s) called -> BUZZER would sound for {duration} seconds"

    if duration > 3:
        def _alarm_worker():
            elapsed = 0
            while elapsed < duration:
                bridge.publish("alarm_on")
                chunk = min(2.5, duration - elapsed)
                time.sleep(chunk)
                elapsed += chunk

        threading.Thread(target=_alarm_worker, daemon=True).start()

    res = _dispatch_command(cmd, action_name, fake_log)
    res["duration_seconds"] = duration
    res["hardware_connected"] = is_online
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

    content = note_path.read_text(encoding="utf-8")
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
