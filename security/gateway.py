"""
Phase 3 — Security Gateway (Wiring Phase)

WHAT THIS FILE DOES:
Acts as the security gateway intercepting tool execution requests from the AI agent.
Currently operates in 'allow everything' monitor-only mode to prove the agent-gateway-tool
wiring works before any real security logic is added in later phases.
"""


def evaluate(tool_name: str, tool_args: dict, user_text: str) -> dict:
    """
    Evaluates a tool execution request against security policies.

    Args:
        tool_name: The name of the tool requested by the model.
        tool_args: Arguments passed to the tool.
        user_text: Raw user prompt text.

    Returns:
        dict: Security evaluation decision and reason.
    """
    return {
        "decision": "ALLOW",
        "reason": "monitor-only mode, all actions currently allowed",
    }
