"""
AegisAgent -- Security Policy Enforcement Gateway & Home Automation Assistant.

WHAT THIS FILE DOES:
1. Takes a plain-English sentence from the user (e.g. "turn on the light", "unlock the door")
2. Checks user message for prompt injection via security.gateway
3. Sends sentence to local Ollama model with tool descriptions
4. Evaluates tool requests through security gateway (RBAC, Rate Limiting, Human Approval)
5. Executes allowed tools and scans tool outputs for safety
"""

import argparse
from dataclasses import dataclass
import sys
import time
from typing import Any, Callable
import uuid

import ollama
import security.gateway
import security.hardware
import security.logger
import security.policy_loader
import security.rate_limiter
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


@dataclass
class TurnResult:
    reply: str | None = None
    decision: str = "ALLOW"
    tool_called: str | None = None
    tool_result: Any = None
    error: str | None = None


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


def run_turn(
    text: str,
    role: str = "guest",
    session_id: str = "default",
    emit: Callable[[str, str, dict], None] | None = None,
    request_id: str | None = None,
) -> TurnResult:
    """
    Executes a single conversational or command turn through the complete AegisAgent pipeline:
    [detection -> llm -> rbac -> rate_limit -> approval -> hardware -> output_scan].
    Calls emit(stage, status, detail) at each stage with status in [running, pass, review, block, skip, error].
    """
    start_turn_time = time.perf_counter()
    if not request_id:
        request_id = str(uuid.uuid4())
    detected_rule_ids = []

    def _finalize(res: TurnResult) -> TurnResult:
        latency_ms = round((time.perf_counter() - start_turn_time) * 1000, 2)
        try:
            security.logger.log_turn_summary(
                request_id=request_id,
                session_id=session_id,
                decision=res.decision,
                tool=res.tool_called,
                rule_ids=list(detected_rule_ids),
                latency_ms=latency_ms,
            )
        except Exception:
            raise
        return res

    def _emit(stage: str, status: str, detail: dict):
        if emit is not None:
            try:
                emit(stage, status, detail)
            except Exception:
                pass

    # 1. Detection Stage
    _emit("detection", "running", {"text": text[:200]})
    verdict = security.gateway.inspect_user_message(session_id, text)
    detection_mode = security.policy_loader.POLICY.get("detection", {}).get("mode", "monitor")

    for res in verdict.results:
        if getattr(res, "rule_ids", None):
            detected_rule_ids.extend(res.rule_ids)

    if verdict.decision == "BLOCK":
        top_reason = "Prompt injection detected"
        for res in verdict.results:
            if res.reasons:
                top_reason = res.reasons[0]
                break
        if detection_mode == "enforce":
            try:
                security.hardware.trigger_block_alert()
            except Exception:
                pass
            _emit("detection", "block", {"reason": top_reason, "score": verdict.score})
            for s in ("llm", "rbac", "rate_limit", "approval", "hardware", "output_scan"):
                _emit(s, "skip", {"reason": "Blocked by detection"})
            return _finalize(TurnResult(
                reply=f"Request blocked by AegisAgent: {top_reason}",
                decision="BLOCK",
                error=top_reason,
            ))
        else:
            _emit("detection", "pass", {"monitor": True, "score": verdict.score, "reason": top_reason})
    elif verdict.decision == "REVIEW":
        _emit("detection", "review", {"score": verdict.score})
        allowed = security.gateway.handle_review(session_id, verdict, text=text)
        if not allowed:
            _emit("detection", "block", {"reason": "Denied by human operator"})
            for s in ("llm", "rbac", "rate_limit", "approval", "hardware", "output_scan"):
                _emit(s, "skip", {"reason": "Denied by operator review"})
            return _finalize(TurnResult(
                reply="Request denied by human operator",
                decision="DENY",
                error="Review denied",
            ))
        else:
            _emit("detection", "pass", {"reason": "Approved by human operator"})
    else:
        _emit("detection", "pass", {"score": verdict.score})

    # 2. LLM Stage
    _emit("llm", "running", {"model": MODEL})
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
        {"role": "user", "content": text},
    ]

    try:
        response = ollama.chat(model=MODEL, messages=messages, tools=TOOLS, keep_alive="30m")
    except Exception as e:
        _emit("llm", "error", {"error": str(e)})
        for s in ("rbac", "rate_limit", "approval", "hardware", "output_scan"):
            _emit(s, "skip", {"reason": "LLM communication error"})
        return _finalize(TurnResult(
            reply=f"LLM communication error: {e}",
            decision="ERROR",
            error=str(e),
        ))

    message = response.get("message", {})
    tool_calls = message.get("tool_calls")

    if not tool_calls:
        content = message.get("content", "")
        _emit("llm", "pass", {"tool_calls": 0, "reply": content})
        for s in ("rbac", "rate_limit", "approval", "hardware", "output_scan"):
            _emit(s, "skip", {"reason": "No tool call generated"})
        return _finalize(TurnResult(reply=content, decision="ALLOW"))

    _emit("llm", "pass", {"tool_calls": len(tool_calls)})

    # Tool Execution & Pipeline Evaluation
    scan_tool_outputs = security.policy_loader.POLICY.get("detection", {}).get("scan_tool_outputs", True)
    last_turn_result = None

    for call in tool_calls:
        function_name = call["function"]["name"]
        function_args = call["function"].get("arguments", {}) or {}

        # 3. RBAC stage
        _emit("rbac", "running", {"tool": function_name, "role": role})
        if function_name not in AVAILABLE_FUNCTIONS:
            _emit("rbac", "block", {"tool": function_name, "reason": "unknown tool"})
            for s in ("rate_limit", "approval", "hardware", "output_scan"):
                _emit(s, "skip", {"reason": "unknown tool"})
            return _finalize(TurnResult(
                reply=f"REJECTED — '{function_name}' is not a real tool.",
                decision="BLOCK",
                tool_called=function_name,
                error="unknown tool",
            ))

        if not security.policy_loader.is_tool_allowed_for_role(function_name, role):
            reason_msg = f"permission denied: role '{role}' cannot use '{function_name}'"
            _emit("rbac", "block", {"tool": function_name, "role": role, "reason": reason_msg})
            security.gateway.evaluate(function_name, function_args, text, role=role, session_id=session_id)
            for s in ("rate_limit", "approval", "hardware", "output_scan"):
                _emit(s, "skip", {"reason": "RBAC denied"})
            return _finalize(TurnResult(
                reply=f"Request blocked by policy: {reason_msg}",
                decision="BLOCK",
                tool_called=function_name,
                error=reason_msg,
            ))
        _emit("rbac", "pass", {"tool": function_name, "role": role})

        # 4. Rate Limit stage
        _emit("rate_limit", "running", {"tool": function_name})
        if not security.rate_limiter.check_rate_limit(function_name):
            reason_msg = f"rate limit exceeded for '{function_name}'"
            _emit("rate_limit", "block", {"tool": function_name, "reason": reason_msg})
            security.gateway.evaluate(function_name, function_args, text, role=role, session_id=session_id)
            for s in ("approval", "hardware", "output_scan"):
                _emit(s, "skip", {"reason": "Rate limit exceeded"})
            return _finalize(TurnResult(
                reply=f"Request blocked: {reason_msg}",
                decision="BLOCK",
                tool_called=function_name,
                error=reason_msg,
            ))
        _emit("rate_limit", "pass", {"tool": function_name})

        # 5. Approval stage
        evaluation = security.gateway.evaluate(function_name, function_args, text, role=role, session_id=session_id, emit=_emit)
        decision = evaluation.get("decision")
        reason = evaluation.get("reason", "")

        risk = security.policy_loader.get_risk(function_name)
        approval_cfg = security.policy_loader.POLICY.get("approval", {})
        requires_approval = approval_cfg.get("enabled", True) and (risk in approval_cfg.get("require_for_risk", ["HIGH"]))

        if decision != "ALLOW":
            _emit("approval", "block", {"reason": reason})
            for s in ("hardware", "output_scan"):
                _emit(s, "skip", {"reason": "Approval denied or blocked"})
            return _finalize(TurnResult(
                reply=f"Action blocked: {reason}",
                decision="BLOCK",
                tool_called=function_name,
                error=reason,
            ))

        if requires_approval:
            _emit("approval", "pass", {"reason": reason})
        else:
            _emit("approval", "skip", {"reason": "LOW risk auto-allowed"})

        # 6. Hardware execution stage
        _emit("hardware", "running", {"tool": function_name, "args": function_args})
        expected_args = TOOL_SCHEMAS.get(function_name, set())
        clean_args = {k: v for k, v in function_args.items() if k in expected_args}

        try:
            tool_result = AVAILABLE_FUNCTIONS[function_name](**clean_args)
            _emit("hardware", "pass", {"tool": function_name, "result": str(tool_result)})
        except Exception as e:
            _emit("hardware", "error", {"tool": function_name, "error": str(e)})
            _emit("output_scan", "skip", {"reason": "Hardware execution error"})
            return _finalize(TurnResult(
                reply=f"Error executing tool {function_name}: {e}",
                decision="ERROR",
                tool_called=function_name,
                error=str(e),
            ))

        # 7. Output Scan stage
        if scan_tool_outputs:
            _emit("output_scan", "running", {})
            tool_verdict = security.gateway.inspect_tool_output(session_id, str(tool_result))
            if tool_verdict.decision == "BLOCK" and detection_mode == "enforce":
                try:
                    security.hardware.trigger_block_alert()
                except Exception:
                    pass
                _emit("output_scan", "block", {"reason": "Tool output blocked by policy"})
                return _finalize(TurnResult(
                    reply="[tool output withheld by AegisAgent]",
                    decision="BLOCK",
                    tool_called=function_name,
                    tool_result=None,
                    error="tool output withheld",
                ))
            elif tool_verdict.decision == "REVIEW":
                _emit("output_scan", "review", {"score": tool_verdict.score})
                allowed_output = security.gateway.handle_review(session_id, tool_verdict, text=str(tool_result))
                if not allowed_output:
                    _emit("output_scan", "block", {"reason": "Tool output review denied"})
                    return _finalize(TurnResult(
                        reply="[tool output withheld by AegisAgent]",
                        decision="DENY",
                        tool_called=function_name,
                        tool_result=None,
                        error="tool output denied by operator",
                    ))
                _emit("output_scan", "pass", {"reason": "Tool output review allowed"})
            else:
                _emit("output_scan", "pass", {"score": tool_verdict.score})
        else:
            _emit("output_scan", "skip", {"reason": "Output scanning disabled"})

        last_turn_result = TurnResult(
            reply=f"Executed {function_name}: {tool_result}",
            decision="ALLOW",
            tool_called=function_name,
            tool_result=tool_result,
        )

    return _finalize(last_turn_result or TurnResult(reply="Done.", decision="ALLOW"))


def run_agent(user_text: str, session_id: str = "default", role: str = "guest") -> TurnResult:
    """CLI wrapper around run_turn, preserving console log output."""
    def cli_emit(stage, status, detail):
        if stage == "detection" and status == "pass" and detail.get("monitor"):
            print(f"[GATEWAY MONITOR] Injection detected (score {detail.get('score', 0):.2f}): {detail.get('reason')}")
        elif stage == "llm" and status == "pass" and detail.get("tool_calls") == 0:
            print(f"[AGENT] No tool matched. Model said: {detail.get('reply')}")
        elif stage == "rbac" and status == "running":
            print(f"[AGENT] Model chose tool: {detail.get('tool')}")
        elif stage == "output_scan" and status == "block":
            print("[GATEWAY] [tool output withheld by AegisAgent]")

    res = run_turn(user_text, role=role, session_id=session_id, emit=cli_emit)
    if res.decision != "ALLOW" and res.reply:
        print(res.reply)
    elif res.tool_called:
        print(f"[GATEWAY] Decision: {res.decision} | Reason: {res.reply or 'Approved'}")
    return res


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