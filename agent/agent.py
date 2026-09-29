"""
Phase 2 — Real AI agent, still fake tools underneath.

WHAT THIS FILE DOES:
1. Takes a plain-English sentence from the user (e.g. "turn on the light")
2. Sends it to the local Ollama model, along with a description of
   the 4 tools it's allowed to choose from
3. The model decides which tool (if any) fits the request, and with
   what arguments
4. We look up that tool name in our AVAILABLE_FUNCTIONS dictionary
   and actually call it

IMPORTANT SECURITY NOTE (say this in your viva):
This phase calls the tool DIRECTLY the moment the model asks for it.
That is intentionally insecure — there is no permission check, no
risk scoring, no injection detection yet. Phase 3 inserts the gateway
in between step 3 and step 4 above, so nothing here changes except
one line: instead of calling the function directly, we call
gateway.evaluate() first.
"""

import ollama
from agent.tools import turn_light_on, turn_light_off, read_temperature, activate_alarm

MODEL = "llama3.1"  # change this one line if you use a different Ollama model

# This is the "menu" of tools we tell the AI it's allowed to choose from.
# The AI never sees our actual Python code — only this description.
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "turn_light_on",
            "description": "Turns the LED light on.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "turn_light_off",
            "description": "Turns the LED light off.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_temperature",
            "description": "Reads the current temperature from the sensor.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "activate_alarm",
            "description": "Sounds the buzzer alarm. Only use this if the user clearly wants the alarm.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

# Maps the tool NAME (a string, what the AI sends back) to the
# actual Python FUNCTION (what we can call). This lookup table is
# the only bridge between "what the AI said" and "what code runs."
AVAILABLE_FUNCTIONS = {
    "turn_light_on": turn_light_on,
    "turn_light_off": turn_light_off,
    "read_temperature": read_temperature,
    "activate_alarm": activate_alarm,
}


def run_agent(user_text: str):
    """
    Sends user_text to the model, and if the model chooses a tool,
    calls it directly (Phase 2 has no gateway yet).
    """
    messages = [
    {
        "role": "system",
        "content": (
                "You are a home automation assistant with exactly 4 tools: "
                "turn_light_on, turn_light_off, read_temperature, activate_alarm. "
                "Only call a tool if the user is CLEARLY asking to control the "
                "light, sound the alarm, or check the temperature. "
                "For greetings, small talk, general knowledge questions, or "
                "anything unrelated to these 4 actions, do NOT call any tool — "
                "just reply normally in plain text."
            ),
        },
        {"role": "user", "content": user_text},
    ]

    response = ollama.chat(model=MODEL, messages=messages, tools=TOOLS)

    message = response["message"]

    tool_calls = message.get("tool_calls")

    if not tool_calls:
        # The model didn't think any tool fit this request
        print(f"[AGENT] No tool matched. Model said: {message.get('content')}")
        return

    for call in tool_calls:
        function_name = call["function"]["name"]
        function_args = call["function"].get("arguments", {}) or {}

        print(f"[AGENT] Model chose tool: {function_name}({function_args})")

        if function_name not in AVAILABLE_FUNCTIONS:
            # The model hallucinated a tool name that doesn't exist.
            # This DOES happen with small local models occasionally —
            # this check is your first line of defense against it.
            print(f"[AGENT] REJECTED — '{function_name}' is not a real tool.")
            continue

        # Phase 3 will insert: gateway.evaluate(function_name, function_args, user_text)
        # right here, BEFORE this next line runs.
        AVAILABLE_FUNCTIONS[function_name](**function_args)


if __name__ == "__main__":
    print("AegisAgent Phase 2 — type a request in plain English (or 'quit')\n")
    print("Try: 'turn on the light' / 'what's the temperature' / 'sound the alarm'\n")

    while True:
        user_text = input("You: ").strip()
        if user_text.lower() in ("quit", "exit"):
            break
        if not user_text:
            continue
        run_agent(user_text)