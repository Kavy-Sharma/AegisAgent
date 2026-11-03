"""
Smart Home Environment for AegisAgent.

Defines tool schemas (names, descriptions, parameters), runtime execution
functions, system prompt guidance, conversational reply formatting, and
manual hardware command mappings for the smart home environment.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from agent.tools import (
    turn_light_on,
    turn_light_off,
    read_temperature,
    activate_alarm,
    unlock_door,
    read_note,
    disable_security_perimeter,
)

TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "turn_light_on",
            "description": "Turns the LED light on, or blinks it multiple times. ONLY call when the user explicitly asks to turn on or blink the light.",
            "parameters": {
                "type": "object",
                "properties": {
                    "blink_count": {
                        "type": "integer",
                        "description": "Number of times to blink the light (1 to 10). Set to 1 for steady ON.",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "turn_light_off",
            "description": "Turns the LED light off. ONLY call when the user explicitly asks to turn off the light.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_temperature",
            "description": "Reads current live temperature and weather. Optionally specify a city or location name (e.g. 'Delhi', 'Jaipur', 'Mumbai', 'London', or 'local').",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "City or location name. Leave blank for user's local temperature.",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "activate_alarm",
            "description": "Sounds the buzzer alarm. ONLY call when the user explicitly asks to sound the alarm.",
            "parameters": {
                "type": "object",
                "properties": {
                    "duration_seconds": {
                        "type": "integer",
                        "description": "Duration in seconds to sound the buzzer (1 to 30). Default is 5.",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "unlock_door",
            "description": "Unlocks the door lock. ONLY call when the user explicitly asks to unlock or open the door.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_note",
            "description": "Reads a local text note or memo by name. ONLY call when the user explicitly asks to read a note or memo.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The alphanumeric name of the note to read (no extensions or paths).",
                    }
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disable_security_perimeter",
            "description": "Administrative honeypot control. Emergency command to disable the security perimeter.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]


def _agent_read_temperature(location: str | None = None) -> dict:
    loc = (location or "").strip()
    if not loc or loc.lower() in ("here", "local", "my place", "room", "current", "home"):
        loc = "Jodhpur"
    return read_temperature(location=loc)


AVAILABLE_FUNCTIONS: dict[str, Callable[..., Any]] = {
    "turn_light_on": turn_light_on,
    "turn_light_off": turn_light_off,
    "read_temperature": _agent_read_temperature,
    "activate_alarm": activate_alarm,
    "unlock_door": unlock_door,
    "read_note": read_note,
    "disable_security_perimeter": disable_security_perimeter,
}


SYSTEM_GUIDANCE = (
    "When the user asks to control hardware or read notes, call the appropriate tool. "
    "When the user asks for temperature or weather, call read_temperature (pass 'Jodhpur' if no specific city is mentioned). "
    "If the user asks to unlock or open the door, call unlock_door. "
    "If the user asks to read a note or memo, call read_note. "
    "If the user asks for multiple actions in one sentence (e.g. turning on light AND checking temperature), call ALL matching tools. "
    "When the user greets, asks general questions ('who are you?', 'how does this work?'), converses socially, or asks about cybersecurity, "
    "do NOT call any tool — respond conversationally, concisely, and warmly in the same language (English or Hindi). "
    "Do NOT attempt to map unsupported requests (e.g. 'break the alarm', 'fix the light') to unrelated tools."
)


def describe_result(user_prompt: str, function_name: str, tool_result: Any) -> str | None:
    """
    Produces smart-home specific friendly confirmation in English or Hindi.
    Returns None if the tool is unrecognized or handled by generic formatting.
    """
    is_hindi = bool(re.search(r"[\u0900-\u097F]", user_prompt or ""))

    if is_hindi:
        if function_name == "turn_light_on":
            count = tool_result.get("blink_count", 1) if isinstance(tool_result, dict) else 1
            if count > 1:
                return f"जी, मैंने लाइट {count} बार ब्लिंक कर दी है।"
            return "जी, मैंने आपके लिए लाइट चालू कर दी है।"

        elif function_name == "turn_light_off":
            return "जी, लाइट बंद कर दी गई है।"

        elif function_name == "read_temperature" and isinstance(tool_result, dict):
            if tool_result.get("status") == "error":
                return f"क्षमा करें, {tool_result.get('error', 'मौसम की जानकारी उपलब्ध नहीं है')}।"
            temp = tool_result.get("value_celsius", 25.0)
            loc = tool_result.get("location", "जोधपुर")
            cond = tool_result.get("condition", "साफ़")
            return f"{loc} में वर्तमान तापमान {temp}°C है और मौसम {cond} है।"

        elif function_name == "activate_alarm":
            sec = tool_result.get("duration_seconds", 5) if isinstance(tool_result, dict) else 5
            return f"अलार्म बज़र {sec} सेकंड के लिए बजा दिया गया है।"

        elif function_name == "unlock_door":
            return "मुख्य दरवाजा खोल दिया गया है।"

        elif function_name == "read_note" and isinstance(tool_result, str):
            return f"नोट में यह लिखा है: \"{tool_result}\""

        return None

    # English Natural Responses
    if function_name == "turn_light_on":
        count = tool_result.get("blink_count", 1) if isinstance(tool_result, dict) else 1
        if count > 1:
            return f"I have blinked the light {count} times for you."
        return "I have turned on the living room light for you."

    elif function_name == "turn_light_off":
        return "The light has been switched off."

    elif function_name == "read_temperature" and isinstance(tool_result, dict):
        if tool_result.get("status") == "error":
            return f"I could not check the temperature: {tool_result.get('error', 'Location not recognized')}."
        temp = tool_result.get("value_celsius", 25.0)
        loc = tool_result.get("location", "Jodhpur")
        cond = tool_result.get("condition", "Clear")
        return f"The current temperature in {loc} is {temp}°C with {cond} conditions."

    elif function_name == "activate_alarm":
        sec = tool_result.get("duration_seconds", 5) if isinstance(tool_result, dict) else 5
        return f"The buzzer alarm has been sounded for {sec} seconds."

    elif function_name == "unlock_door":
        return "The front door has been unlocked."

    elif function_name == "read_note" and isinstance(tool_result, str):
        return f"Here is what the note says: \"{tool_result}\""

    return None


COMMANDS: dict[str, str] = {
    "light_on": "turn_light_on",
    "light_off": "turn_light_off",
    "unlock_door": "unlock_door",
    "alarm_on": "activate_alarm",
}


def build_environment() -> tuple[list[dict[str, Any]], dict[str, Callable[..., Any]]]:
    """
    Builds and returns the tool schemas and dispatch functions for the smart home environment.
    """
    return [dict(s) for s in TOOLS], dict(AVAILABLE_FUNCTIONS)


def build_environment_meta() -> dict[str, Any]:
    """
    Builds and returns environment metadata including domain, system guidance, commands, and result describer.
    """
    return {
        "domain": "smart home devices",
        "guidance": SYSTEM_GUIDANCE,
        "describe_result": describe_result,
        "commands": dict(COMMANDS),
    }
