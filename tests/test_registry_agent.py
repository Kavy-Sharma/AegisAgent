"""
Tests for Phase 9C Step 2: Agent Tools Built from Registry & Environment Validation.

Verifies:
1. Equivalence: built TOOLS schemas and AVAILABLE_FUNCTIONS keys equal the pre-migration snapshot.
2. Validation: fails closed if environment contains tools missing from the registry.
3. Validation: fails closed if a registry tool has no corresponding dispatch function.
4. Defense: model tool calls targeting unknown or unregistered tools are blocked with zero hardware execution.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
import pytest

from agent.agent import (
    AVAILABLE_FUNCTIONS,
    TOOLS,
    run_turn,
    validate_environment_against_registry,
)
import security.hardware
from security.hardware import FakeBridge, set_bridge
import security.registry


def test_built_tools_and_functions_equivalence_with_snapshot():
    """Built TOOLS and AVAILABLE_FUNCTIONS keys must strictly equal the pre-migration snapshot."""
    snapshot_path = Path(__file__).resolve().parent / "fixtures" / "tools_snapshot.json"
    assert snapshot_path.exists(), f"Required fixture snapshot not found at {snapshot_path}"

    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    expected_tools = snapshot["tools"]
    expected_funcs = snapshot["available_functions"]

    # 1. Compare TOOLS list (same count, names, descriptions, parameters)
    assert len(TOOLS) == len(expected_tools), f"TOOLS length mismatch: {len(TOOLS)} != {len(expected_tools)}"
    for actual, expected in zip(TOOLS, expected_tools):
        assert actual["type"] == expected["type"]
        act_fn = actual["function"]
        exp_fn = expected["function"]
        assert act_fn["name"] == exp_fn["name"], f"Tool name mismatch: {act_fn['name']} != {exp_fn['name']}"
        assert act_fn["description"] == exp_fn["description"], f"Description mismatch for {act_fn['name']}"
        assert act_fn["parameters"] == exp_fn["parameters"], f"Parameters mismatch for {act_fn['name']}"

    # 2. Compare AVAILABLE_FUNCTIONS keys
    assert list(AVAILABLE_FUNCTIONS.keys()) == expected_funcs, (
        f"AVAILABLE_FUNCTIONS keys mismatch: {list(AVAILABLE_FUNCTIONS.keys())} != {expected_funcs}"
    )


def test_validation_raises_when_environment_tool_missing_from_registry():
    """validate_environment_against_registry raises ValueError if a tool is not in policy registry."""
    fake_tools = [dict(t) for t in TOOLS] + [
        {
            "type": "function",
            "function": {
                "name": "unregistered_custom_tool",
                "description": "A tool not declared in policy.yaml",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        }
    ]
    fake_functions = dict(AVAILABLE_FUNCTIONS)
    fake_functions["unregistered_custom_tool"] = lambda: {"ok": True}

    with pytest.raises(ValueError, match="Environment tools missing from registry"):
        validate_environment_against_registry(fake_tools, fake_functions)


def test_validation_raises_when_registry_tool_has_no_function():
    """validate_environment_against_registry raises ValueError if any registry tool lacks a function."""
    # Omit unlock_door from functions
    incomplete_functions = {k: v for k, v in AVAILABLE_FUNCTIONS.items() if k != "unlock_door"}
    with pytest.raises(ValueError, match="Registry tools missing from functions"):
        validate_environment_against_registry(TOOLS, incomplete_functions)

    # Incomplete schemas matching incomplete functions, but both missing unlock_door from registry
    incomplete_tools = [t for t in TOOLS if t["function"]["name"] != "unlock_door"]
    with pytest.raises(ValueError, match="Registry tools missing from functions"):
        validate_environment_against_registry(incomplete_tools, incomplete_functions)

    # Tool in functions but omitted from tool schemas
    tools_missing_one = [t for t in TOOLS if t["function"]["name"] != "unlock_door"]
    with pytest.raises(ValueError, match="Mismatch between tool schemas and functions"):
        validate_environment_against_registry(tools_missing_one, AVAILABLE_FUNCTIONS)


def test_model_call_unknown_tool_denied_and_no_hardware_execution():
    """When the model calls a tool not in registry or functions, run_turn denies it with no hardware call."""
    bridge = FakeBridge()
    bridge.connected = True
    bridge.device_online_status = True
    old_bridge = security.hardware.get_bridge()
    set_bridge(bridge)

    unknown_tool = "nonexistent_evil_actuator"
    mock_resp = {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": unknown_tool,
                        "arguments": {"payload": "drop_firewall"},
                    }
                }
            ],
        }
    }

    try:
        with patch("ollama.chat", return_value=mock_resp):
            res = run_turn(text="please execute nonexistent tool", role="admin", session_id="test_sess_unknown_tool")

        assert res.decision == "BLOCK"
        assert res.tool_called == unknown_tool
        assert "is not a real tool" in (res.reply or "") or "unknown tool" in (res.error or "")
        # Assert FakeBridge received ZERO commands
        assert len(bridge.command_history) == 0, f"Hardware bridge was called with: {bridge.command_history}"
    finally:
        set_bridge(old_bridge)
