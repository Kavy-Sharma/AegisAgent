"""
Phase 4 — Security Policy Enforcement (Permissions, Risk & Rate Limiting).

WHAT THIS FILE DOES:
1. Takes a plain-English sentence from the user (e.g. "turn on the light")
2. Sends it to the local Ollama model, along with a description of
   the 4 tools it's allowed to choose from
3. The model decides which tool (if any) fits the request, and with
   what arguments
4. Passes the tool request through security.gateway.evaluate(..., role="guest")
5. If the gateway decision is ALLOW, looks up that tool name in
   AVAILABLE_FUNCTIONS dictionary and actually calls it
"""

import ollama
import security.gateway
import security.policy_loader
from agent.tools import turn_light_on, turn_light_off, read_temperature, activate_alarm

MODEL = "llama3.1"  # change this one line if you use a different Ollama model

# This is the "menu" of tools we tell the AI it's allowed to choose from.
# The AI never sees our actual Python code — only this description.
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "turn_light_on",
            "description": "Turns the LED light on. ONLY call when the user explicitly asks to turn on the light.",
            "parameters": {"type": "object", "properties": {}, "required": []},
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
            "description": "Reads the current temperature from the sensor. ONLY call when the user explicitly asks for temperature or weather reading.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "activate_alarm",
            "description": "Sounds the buzzer alarm. ONLY call when the user explicitly asks to sound the alarm.",
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

# Build a lookup of exactly which arguments each tool is allowed to receive,
# directly from the TOOLS schema above — so we never have to maintain this twice.
TOOL_SCHEMAS = {
    t["function"]["name"]: set(t["function"]["parameters"]["properties"].keys())
    for t in TOOLS
}


def run_agent(user_text: str, session_id: str = "default"):
    """
    Sends user_text to the model, evaluates prompt injection security checks,
    evaluates the tool decision through the security gateway, and executes the tool if allowed.
    """
    # 1. Prompt Injection Detection Check on user input
    verdict = security.gateway.inspect_user_message(session_id, user_text)
    detection_mode = security.policy_loader.POLICY.get("detection", {}).get("mode", "monitor")

    if verdict.decision == "BLOCK":
        top_reason = "Prompt injection detected"
        for res in verdict.results:
            if res.reasons:
                top_reason = res.reasons[0]
                break
        if detection_mode == "enforce":
            print(f"Request blocked by AegisAgent: {top_reason}")
            return
        else:
            print(f"[GATEWAY MONITOR] Injection detected (score {verdict.score:.2f}): {top_reason}")
    elif verdict.decision == "REVIEW":
        security.gateway.handle_review(session_id, verdict)

    messages = [
        {
            "role": "system",
            "content": (
                "You are a home automation assistant with 4 tools: "
                "turn_light_on, turn_light_off, read_temperature, activate_alarm. "
                "If the user asks for multiple actions in one sentence (e.g. turning on light AND checking temperature), "
                "call ALL matching tools. "
                "Do NOT call any tool for single-word prompts (e.g., 'yes', 'no', 'ok', 'sure') or ambiguous follow-ups. "
                "Do NOT attempt to map unsupported requests (e.g. 'break the alarm', 'fix the light') to unrelated tools. "
                "For ambiguous, single-word, or unsupported requests, do NOT call any tool — reply in plain text."
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

    scan_tool_outputs = security.policy_loader.POLICY.get("detection", {}).get("scan_tool_outputs", True)

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

        # Evaluate tool request through the security gateway
        # Hardcoding role="guest" for now; Phase 8's dashboard will introduce real admin login later
        evaluation = security.gateway.evaluate(function_name, function_args, user_text, role="guest")
        decision = evaluation.get("decision")
        reason = evaluation.get("reason")

        print(f"[GATEWAY] Decision: {decision} | Reason: {reason}")

        if decision == "ALLOW":
            expected_args = TOOL_SCHEMAS.get(function_name, set())
            unexpected = set(function_args.keys()) - expected_args
            if unexpected:
                print(
                    f"[AGENT] WARNING - model sent unexpected args {unexpected} for "
                    f"{function_name}, dropping them (tool expects: {expected_args or 'none'})"
                )
                function_args = {k: v for k, v in function_args.items() if k in expected_args}
            
            tool_result = AVAILABLE_FUNCTIONS[function_name](**function_args)

            # Scan tool output if enabled in policy
            if scan_tool_outputs:
                tool_verdict = security.gateway.inspect_tool_output(session_id, str(tool_result))
                if tool_verdict.decision == "BLOCK" and detection_mode == "enforce":
                    print("[GATEWAY] [tool output withheld by AegisAgent]")
                elif tool_verdict.decision == "REVIEW":
                    security.gateway.handle_review(session_id, tool_verdict)



if __name__ == "__main__":
    print("AegisAgent Phase 3 — type a request in plain English (or 'quit')\n")
    print("Try: 'turn on the light' / 'what's the temperature' / 'sound the alarm'\n")

    while True:
        user_text = input("You: ").strip()
        if user_text.lower() in ("quit", "exit"):
            break
        if not user_text:
            continue
        run_agent(user_text)