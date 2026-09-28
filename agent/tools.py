"""
Phase 1 — Fake tool functions.

These represent the 4 real-world actions our IoT device can do.
Right now they just print what they WOULD do — no AI, no gateway,
no hardware yet. This lets us test the "shape" of each function
(what arguments it takes, what it returns) before anything else
depends on it.

Later phases replace the print() lines with real MQTT publishes —
but the function names and arguments stay exactly the same, so
nothing above this layer (the AI, the gateway) has to change.
"""


def turn_light_on():
    """Turns the LED on. No arguments needed."""
    print("[TOOL] turn_light_on() called -> LED would turn ON")
    return {"status": "success", "action": "light_on"}


def turn_light_off():
    """Turns the LED off. No arguments needed."""
    print("[TOOL] turn_light_off() called -> LED would turn OFF")
    return {"status": "success", "action": "light_off"}


def read_temperature():
    """
    Reads the temperature sensor. No arguments needed.
    Right now it returns a fake number — Phase 7 replaces this
    with a real reading published by the ESP32 over MQTT.
    """
    fake_temp_celsius = 28.5
    print(f"[TOOL] read_temperature() called -> {fake_temp_celsius}°C (fake reading)")
    return {"status": "success", "action": "read_temperature", "value_celsius": fake_temp_celsius}


def activate_alarm():
    """
    Activates the buzzer alarm. This is our HIGH-risk tool —
    later phases will make this require human approval before
    it's ever actually allowed to run.
    """
    print("[TOOL] activate_alarm() called -> BUZZER would sound")
    return {"status": "success", "action": "alarm_activated"}


# --- Manual test block ---
# This only runs if you execute THIS file directly
# (python agent/tools.py), not if another file imports these
# functions. It's a quick way to prove all 4 functions work
# before we wire anything else on top of them.
if __name__ == "__main__":
    print("Testing all 4 tools manually:\n")
    turn_light_on()
    turn_light_off()
    read_temperature()
    activate_alarm()
    print("\nAll 4 tools ran without errors. Phase 1 complete.")