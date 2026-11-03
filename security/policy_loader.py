"""
Phase 4 -- Policy Loader

WHAT THIS FILE DOES:
Loads policy.yaml configuration once at import time and provides lookup helper
functions for tool risk levels, role-based permissions, and rate limits.
"""

import os
from pathlib import Path
import yaml

# Path to policy.yaml at project root (or overridden via AEGIS_POLICY_PATH)
POLICY_PATH = Path(os.environ.get("AEGIS_POLICY_PATH") or (Path(__file__).resolve().parent.parent / "policy.yaml"))


def _resolve_policy_path(env: str | None = None) -> Path:
    if not env or env == "smart_home":
        return POLICY_PATH
    elif env == "office":
        p = Path(__file__).resolve().parent.parent / "policies" / "office.yaml"
        if not p.exists():
            raise FileNotFoundError(f"Office policy file not found at {p}")
        return p
    else:
        raise ValueError(f"Unknown environment: '{env}'. Must be 'smart_home' or 'office'.")


def get_configured_environment() -> str:
    """Reads the environment key from AEGIS_ENV env var or root policy.yaml, defaulting to 'smart_home'."""
    env_var = os.environ.get("AEGIS_ENV")
    if env_var:
        if env_var not in ("smart_home", "office"):
            raise ValueError(f"Unknown environment in AEGIS_ENV: '{env_var}'. Must be 'smart_home' or 'office'.")
        return env_var
    p_path = Path(os.environ.get("AEGIS_POLICY_PATH") or (Path(__file__).resolve().parent.parent / "policy.yaml"))
    if not p_path.exists():
        return "smart_home"
    with open(p_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        return "smart_home"
    return data.get("environment", "smart_home")


def _load_policy(policy_path: Path | None = None, env: str | None = None) -> dict:
    """Loads and parses the policy.yaml file."""
    env_var = os.environ.get("AEGIS_ENV")
    if env_var and env_var not in ("smart_home", "office"):
        raise ValueError(f"Unknown environment in AEGIS_ENV: '{env_var}'. Must be 'smart_home' or 'office'.")

    configured_env = env_var or get_configured_environment()
    target_env = env if env is not None else (None if policy_path is not None else configured_env)

    if policy_path is None:
        p_path = _resolve_policy_path(target_env)
    else:
        p_path = policy_path

    if not p_path.exists():
        raise FileNotFoundError(f"Policy file not found at {p_path}")
    with open(p_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f) or {}

    # If loading default root policy and no explicit env passed, check if environment key directs to another policy
    if policy_path is None and env is None:
        if configured_env != "smart_home" and target_env != configured_env:
            target_path = _resolve_policy_path(configured_env)
            if not target_path.exists():
                raise FileNotFoundError(f"Policy file not found at {target_path}")
            with open(target_path, "r", encoding="utf-8") as f:
                policy = yaml.safe_load(f) or {}

    return policy


# Load policy once at import time
POLICY = _load_policy()


def load_environment(env: str) -> None:
    """Reloads policy configuration for a specific environment ('smart_home' | 'office')."""
    target_path = _resolve_policy_path(env)
    new_policy = _load_policy(target_path)
    POLICY.clear()
    POLICY.update(new_policy)


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


def is_untrusted_output(tool_name: str) -> bool:
    """
    Returns True if the tool output is untrusted (e.g., read_note),
    triggering taint tracking for provenance.
    """
    tools = POLICY.get("tools", {})
    if tool_name not in tools:
        return False
    return bool(tools[tool_name].get("untrusted_output", False))
