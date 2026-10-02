"""
Phase 4 — Policy Loader

WHAT THIS FILE DOES:
Loads policy.yaml configuration once at import time and provides lookup helper
functions for tool risk levels, role-based permissions, and rate limits.
"""

from pathlib import Path
import yaml

# Path to policy.yaml at project root
POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.yaml"


def _load_policy() -> dict:
    """Loads and parses the policy.yaml file."""
    if not POLICY_PATH.exists():
        raise FileNotFoundError(f"Policy file not found at {POLICY_PATH}")
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# Load policy once at import time
POLICY = _load_policy()


def get_risk(tool_name: str) -> str | None:
    """
    Returns the risk level ('LOW' or 'HIGH') for a given tool.
    Returns None if tool is unknown.
    """
    tools = POLICY.get("tools", {})
    if tool_name not in tools:
        return None
    return tools[tool_name].get("risk")


def is_tool_allowed_for_role(tool_name: str, role: str) -> bool:
    """
    Checks if a tool is allowed for a specific role based on policy.yaml.
    """
    roles = POLICY.get("roles", {})
    role_config = roles.get(role, {})
    allowed_tools = role_config.get("allowed_tools", [])
    return tool_name in allowed_tools


def get_rate_limit() -> tuple[int, int]:
    """
    Returns (max_calls, window_seconds) from rate_limits.default in policy.yaml.
    """
    rate_limits = POLICY.get("rate_limits", {})
    default_limit = rate_limits.get("default", {})
    max_calls = default_limit.get("max_calls", 5)
    window_seconds = default_limit.get("window_seconds", 60)
    return max_calls, window_seconds
