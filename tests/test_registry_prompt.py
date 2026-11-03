"""
Tests for Phase 9C Step 3: Generic System Prompt and Environment-Driven Replies.

Verifies:
1. Exact Equivalence: generated system prompt and all conversational replies equal
   the pre-refactor snapshot fixture character-for-character.
2. Fake Environment: prompts list custom tools and synthesize_conversational_reply
   falls back to 'Completed <tool name with spaces>.' when no environment describer exists.
3. Tool Count: the tool count stated in the generated prompt equals the number of tools.
4. Domain Fallback: default domain fallback is the neutral word 'tools'.
5. Honeypot Tools Omission: when only honeypot tools exist, no tool names are listed and it states 'no tools'.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from unittest.mock import patch
import pytest

from agent.agent import (
    TOOLS,
    build_system_prompt,
    synthesize_conversational_reply,
)


def test_generated_prompts_and_replies_equal_snapshot_fixture():
    """Generated system prompts and all conversational replies must equal the snapshot fixture."""
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "prompt_and_replies_snapshot.json"
    assert fixture_path.exists(), f"Snapshot fixture not found at {fixture_path}"

    snapshot = json.loads(fixture_path.read_text(encoding="utf-8"))

    # 1. System prompts equivalence
    expected_prompts = snapshot["system_prompts"]
    for role in ("admin", "guest"):
        generated_prompt = build_system_prompt(role=role)
        assert generated_prompt == expected_prompts[role], (
            f"System prompt mismatch for role '{role}':\n"
            f"  Actual:   {generated_prompt}\n"
            f"  Expected: {expected_prompts[role]}"
        )

    # 2. Conversational replies equivalence across all tools, languages, and result states
    sample_results = {
        "success_default": {
            "turn_light_on": {"status": "success", "blink_count": 1},
            "turn_light_off": {"status": "success"},
            "read_temperature": {"status": "success", "value_celsius": 27.0, "location": "Jodhpur", "condition": "Clear"},
            "activate_alarm": {"status": "success", "duration_seconds": 5},
            "unlock_door": {"status": "success"},
            "read_note": "Meeting at 3pm.",
            "disable_security_perimeter": {"status": "success"},
        },
        "failed": {
            "turn_light_on": {"status": "failed", "error": "Device communication error"},
            "turn_light_off": {"status": "failed", "error": "Device communication error"},
            "read_temperature": {"status": "failed", "error": "Hardware command failed"},
            "activate_alarm": {"status": "failed", "error": "Hardware command failed"},
            "unlock_door": {"status": "failed", "error": "Hardware command failed"},
            "read_note": {"status": "failed", "error": "Hardware command failed"},
            "disable_security_perimeter": {"status": "failed", "error": "Hardware command failed"},
        },
        "blink_count_3": {
            "turn_light_on": {"status": "success", "blink_count": 3},
            "turn_light_off": {"status": "success", "blink_count": 3},
            "read_temperature": {"status": "success", "blink_count": 3, "value_celsius": 25.0, "location": "Jodhpur", "condition": "Clear"},
            "activate_alarm": {"status": "success", "blink_count": 3, "duration_seconds": 3},
            "unlock_door": {"status": "success", "blink_count": 3},
            "read_note": "Note with blink 3",
            "disable_security_perimeter": {"status": "success", "blink_count": 3},
        },
        "error_status_temperature": {
            "turn_light_on": {"status": "error", "error": "Simulated error"},
            "turn_light_off": {"status": "error", "error": "Simulated error"},
            "read_temperature": {"status": "error", "error": "Location not found"},
            "activate_alarm": {"status": "error", "error": "Simulated error"},
            "unlock_door": {"status": "error", "error": "Simulated error"},
            "read_note": {"status": "error", "error": "Simulated error"},
            "disable_security_perimeter": {"status": "error", "error": "Simulated error"},
        },
    }

    prompts = {
        "en": "Please perform this action.",
        "hi": "कृपया यह कार्रवाई करें।",
    }

    for lang_key, user_text in prompts.items():
        lang_replies = snapshot["replies"][lang_key]
        for tool_name, tool_cases in lang_replies.items():
            for case_key, expected_reply in tool_cases.items():
                tool_res = sample_results[case_key][tool_name]
                actual_reply = synthesize_conversational_reply(user_text, tool_name, tool_res)
                assert actual_reply == expected_reply, (
                    f"Reply mismatch for lang='{lang_key}', tool='{tool_name}', case='{case_key}':\n"
                    f"  Actual:   {actual_reply}\n"
                    f"  Expected: {expected_reply}"
                )


def test_fake_environment_prompt_and_reply():
    """A fake environment without custom describe_result formats fallback prompt and reply."""
    fake_tools = [
        {
            "type": "function",
            "function": {
                "name": "foo_tool",
                "description": "Custom diagnostic actuator.",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        }
    ]
    fake_meta = {
        "domain": "industrial sensors",
        "guidance": None,
        "describe_result": None,
    }

    # 1. Prompt lists the fake tool
    prompt = build_system_prompt(role="admin", tools=fake_tools, env_meta=fake_meta)
    assert "foo_tool" in prompt
    assert "via 1 tools: foo_tool" in prompt

    # 2. Reply uses generic fallback
    reply = synthesize_conversational_reply(
        "run diagnostic now",
        "foo_tool",
        {"status": "success"},
        env_meta=fake_meta,
    )
    assert reply == "Completed foo tool."


def test_tool_count_in_prompt():
    """The tool count in the prompt strictly equals the number of tools listed."""
    # 1. Smart home default prompt (6 active callable tools)
    prompt = build_system_prompt(role="admin")
    m = re.search(r"via (\d+) tools:", prompt)
    assert m is not None, "Tool count pattern not found in prompt"
    assert int(m.group(1)) == 6

    # 2. Arbitrary environments: tool count in prompt equals len(tools)
    for count in (1, 2, 4, 8):
        custom_tools = [
            {
                "type": "function",
                "function": {
                    "name": f"sensor_{i}",
                    "description": f"Sensor tool {i}",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            }
            for i in range(count)
        ]
        custom_meta = {"domain": "lab rigs", "guidance": None, "describe_result": None}
        p = build_system_prompt(role="admin", tools=custom_tools, env_meta=custom_meta)
        m = re.search(r"via (\d+) tools:", p)
        assert m is not None, f"Tool count pattern not found for count={count}"
        assert int(m.group(1)) == count
        assert int(m.group(1)) == len(custom_tools)


def test_default_domain_fallback_to_tools():
    """When env_meta does not specify a domain, it defaults to the neutral word 'tools'."""
    custom_tools = [
        {
            "type": "function",
            "function": {
                "name": "sample_tool",
                "description": "A sample tool",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        }
    ]
    prompt = build_system_prompt(role="admin", tools=custom_tools, env_meta={})
    assert "You control tools via 1 tools: sample_tool." in prompt


def test_honeypot_only_tools_lists_no_tools():
    """When only honeypot tools exist, no tool names are listed and the prompt states 'via no tools'."""
    honeypot_tools = [
        {
            "type": "function",
            "function": {
                "name": "disable_security_perimeter",
                "description": "Honeypot tool",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        }
    ]
    prompt = build_system_prompt(role="admin", tools=honeypot_tools, env_meta={})
    assert "via no tools." in prompt
    assert "disable_security_perimeter" not in prompt
