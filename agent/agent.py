"""
AegisAgent — Security Policy Enforcement Gateway & Home Automation Assistant.

WHAT THIS FILE DOES:
1. Takes a plain-English sentence from the user (e.g. "turn on the light", "unlock the door")
2. Checks user message for prompt injection via security.gateway
3. Sends sentence to local Ollama model with tool descriptions
4. Evaluates tool requests through security gateway (RBAC, Rate Limiting, Human Approval)
5. Executes allowed tools and scans tool outputs for safety
"""

import argparse
import sys
import ollama
import security.gateway
import security.logger
import security.policy_loader
from agent.tools import (
    turn_light_on,
    turn_light_off,
    read_temperature,
    activate_alarm,
    unlock_door,
)

MODEL = "llama3.1"  # change this one line if you use a different Ollama model

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
    {
        "type": "function",
        "function": {
            "name": "unlock_door",
            "description": "Unlocks the door lock. ONLY call when the user explicitly asks to unlock or open the door.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

AVAILABLE_FUNCTIONS = {
    "turn_light_on": turn_light_on,
    "turn_light_off": turn_light_off,
    "read_temperature": read_temperature,
    "activate_alarm": activate_alarm,
    "unlock_door": unlock_door,
}

TOOL_SCHEMAS = {
    t["function"]["name"]: set(t["function"]["parameters"]["properties"].keys())
    for t in TOOLS
}


def print_tools_table():
    tools_cfg = security.policy_loader.POLICY.get("tools", {})
    roles_cfg = security.policy_loader.POLICY.get("roles", {})

    print("\nAvailable Tools & Security Policies:")
    print(f"{'Tool Name':<20} | {'Risk Level':<10} | {'Allowed Roles':<20}")
    print("-" * 56)
    for tool_name, info in tools_cfg.items():
        risk = info.get("risk", "UNKNOWN")
        allowed = [r for r, r_info in roles_cfg.items() if tool_name in r_info.get("allowed_tools", [])]
        roles_str = ", ".join(allowed) if allowed else "none"
        print(f"{tool_name:<20} | {risk:<10} | {roles_str:<20}")
    print()


def get_default_role() -> str:
    roles_cfg = security.policy_loader.POLICY.get("roles", {})
    if not roles_cfg:
        return "guest"
    return min(roles_cfg.keys(), key=lambda r: len(roles_cfg[r].get("allowed_tools", [])))


def run_agent(user_text: str, session_id: str = "default", role: str = "guest"):
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
        allowed = security.gateway.handle_review(session_id, verdict, text=user_text)
        if not allowed:
            print("Request denied by human operator")
            return

    messages = [
        {
            "role": "system",
            "content": (
                "You are a home automation assistant with 5 tools: "
                "turn_light_on, turn_light_off, read_temperature, activate_alarm, unlock_door. "
                "If the user asks to unlock or open the door, call unlock_door. "
                "If the user asks for multiple actions in one sentence (e.g. turning on light AND checking temperature), "
                "call ALL matching tools. "
                "Do NOT call any tool for single-word prompts (e.g., 'yes', 'no', 'ok', 'sure') or ambiguous follow-ups. "
                "Do NOT attempt to map unsupported requests (e.g. 'break the alarm', 'fix the light') to unrelated tools. "
                "For ambiguous, single-word, or unsupported requests, do NOT call any tool — reply in plain text."
            ),
        },
        {"role": "user", "content": user_text},
    ]

    response = ollama.chat(model=MODEL, messages=messages, tools=TOOLS, keep_alive="30m")

    message = response["message"]

    tool_calls = message.get("tool_calls")

    if not tool_calls:
        print(f"[AGENT] No tool matched. Model said: {message.get('content')}")
        return

    scan_tool_outputs = security.policy_loader.POLICY.get("detection", {}).get("scan_tool_outputs", True)

    for call in tool_calls:
        function_name = call["function"]["name"]
        function_args = call["function"].get("arguments", {}) or {}

        print(f"[AGENT] Model chose tool: {function_name}({function_args})")

        if function_name not in AVAILABLE_FUNCTIONS:
            print(f"[AGENT] REJECTED — '{function_name}' is not a real tool.")
            continue

        evaluation = security.gateway.evaluate(function_name, function_args, user_text, role=role, session_id=session_id)
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

            if scan_tool_outputs:
                tool_verdict = security.gateway.inspect_tool_output(session_id, str(tool_result))
                if tool_verdict.decision == "BLOCK" and detection_mode == "enforce":
                    print("[GATEWAY] [tool output withheld by AegisAgent]")
                elif tool_verdict.decision == "REVIEW":
                    allowed_output = security.gateway.handle_review(session_id, tool_verdict, text=str(tool_result))
                    if not allowed_output:
                        print("[GATEWAY] [tool output withheld by AegisAgent]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisAgent Security Gateway & Home Assistant")
    parser.add_argument("--role", default=None, help="Initial user role (default: least-privileged role in policy.yaml)")
    args = parser.parse_args()

    roles_cfg = security.policy_loader.POLICY.get("roles", {})
    valid_roles = list(roles_cfg.keys())

    if args.role is not None:
        if args.role not in valid_roles:
            valid_roles_str = ", ".join(valid_roles)
            print(f"Error: Role '{args.role}' not found in policy.yaml. Valid roles: {valid_roles_str}")
            sys.exit(1)
        active_role = args.role
    else:
        active_role = get_default_role()

    print("=" * 60)
    print(" AegisAgent ".center(60, "="))
    print(f" Active Role: {active_role}")
    print(" [NOTE] /role is a DEMO feature — in production, roles come from authentication.")
    print("=" * 60)

    print("\nLoading model (first run can take a while)...")
    try:
        ollama.chat(model=MODEL, messages=[{"role": "user", "content": "hi"}], keep_alive="30m")
        print("Ready.")
    except Exception as e:
        print("Ollama not running — start it with `ollama serve`")
        sys.exit(1)

    print_tools_table()

    print("Type a request in plain English (or '/role <name>', '/whoami', 'quit')\n")

    while True:
        try:
            user_text = input(f"You [{active_role}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_text:
            continue
        if user_text.lower() in ("quit", "exit"):
            break

        if user_text.startswith("/role"):
            parts = user_text.split(maxsplit=1)
            if len(parts) < 2 or not parts[1].strip():
                print(f"Usage: /role <name>. Valid roles: {', '.join(valid_roles)}")
                continue
            target_role = parts[1].strip()
            if target_role not in valid_roles:
                print(f"Unknown role '{target_role}'. Valid roles: {', '.join(valid_roles)}")
            else:
                security.logger.log_role_change(active_role, target_role)
                print(f"Switched role from '{active_role}' to '{target_role}'.")
                active_role = target_role
            continue

        if user_text.lower() == "/whoami":
            allowed_tools = roles_cfg.get(active_role, {}).get("allowed_tools", [])
            tools_str = ", ".join(allowed_tools) if allowed_tools else "none"
            print(f"Current role: {active_role} | Allowed tools: {tools_str}")
            continue

        run_agent(user_text, role=active_role)