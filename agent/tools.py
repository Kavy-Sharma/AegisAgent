"""
Phase 7 — Hardware-Integrated IoT Tools

WHAT THIS FILE DOES:
Provides tool functions for AegisAgent. When hardware.mode == "mqtt" in policy.yaml,
commands are published through security.hardware.get_bridge() to the MQTT broker.
In fake mode, commands use the FakeBridge for simulation.
"""

import security.hardware
import security.policy_loader


def _dispatch_command(command: str, action_name: str, fake_log: str) -> dict:
    mode = security.policy_loader.POLICY.get("hardware", {}).get("mode", "fake")
    bridge = security.hardware.get_bridge()
    result = bridge.publish(command)
    if result.ok:
        if mode == "fake":
            print(fake_log)
        else:
            print(f"[TOOL] {action_name} -> sent to device")
        return {"status": "success", "action": action_name}
    else:
        print(f"[TOOL] {action_name} FAILED: {result.error}")
        return {"status": "failed", "error": result.error, "action": action_name}


def turn_light_on():
    """Turns the LED light on."""
    return _dispatch_command("light_on", "light_on", "[TOOL] turn_light_on() called -> LED would turn ON")


def turn_light_off():
    """Turns the LED light off."""
    return _dispatch_command("light_off", "light_off", "[TOOL] turn_light_off() called -> LED would turn OFF")


def read_temperature():
    """
    Reads the temperature sensor. No arguments needed.
    Note: read_temperature stays fake for now because sensor telemetry reading
    is handled in local mock mode without hardware ADC wiring.
    """
    fake_temp_celsius = 28.5
    print(f"[TOOL] read_temperature() called -> {fake_temp_celsius}°C (fake reading)")
    return {"status": "success", "action": "read_temperature", "value_celsius": fake_temp_celsius}


def activate_alarm():
    """Activates the buzzer alarm. HIGH-risk tool."""
    return _dispatch_command("alarm_on", "alarm_activated", "[TOOL] activate_alarm() called -> BUZZER would sound")


def unlock_door():
    """Unlocks the door lock. HIGH-risk tool."""
    return _dispatch_command("unlock_door", "door_unlocked", "[TOOL] unlock_door() called -> door unlocked (fake)")


if __name__ == "__main__":
    print("Testing all tools manually:\n")
    turn_light_on()
    turn_light_off()
    read_temperature()
    activate_alarm()
    unlock_door()
    print("\nAll tools ran without errors.")