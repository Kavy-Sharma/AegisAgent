"""
Phase 9C -- Tool Registry (Step 1)

WHAT THIS FILE DOES:
Provides a centralized, read-only, fail-closed interface for tool definitions,
risk levels, role permissions, approval requirements, and intent mappings.
Currently loads from policy.yaml to maintain 100% backward equivalence with zero
behavioral regression.

FAIL-CLOSED GUARANTEES:
- Unknown tools return None / empty allowed roles (never allowed).
- Broken or malformed policy raises ValueError at load time.
- Exposes only read-only query functions (no write/mutate functions).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import yaml

POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.yaml"

VALID_RISKS = frozenset({"LOW", "HIGH", "HONEYPOT"})


def _load_and_validate_registry(policy_path: Path | None = None) -> dict[str, Any]:
    """Loads and validates policy configuration, failing closed on any corruption."""
    p_path = policy_path or POLICY_PATH
    if not p_path.exists():
        raise FileNotFoundError(f"Policy file not found at {p_path}")

    with open(p_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)

    if not isinstance(policy, dict):
        raise ValueError(f"Malformed policy file at {p_path}: root must be a mapping")

    tools = policy.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise ValueError("Policy must contain a non-empty 'tools' mapping")

    for tool_name, tool_cfg in tools.items():
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError(f"Invalid tool name '{tool_name}' in policy")
        if not isinstance(tool_cfg, dict):
            raise ValueError(f"Tool definition for '{tool_name}' must be a dictionary")
        risk = tool_cfg.get("risk")
        if risk not in VALID_RISKS:
            raise ValueError(f"Tool '{tool_name}' has invalid or missing risk level: '{risk}'. Must be one of {sorted(VALID_RISKS)}")

    roles = policy.get("roles")
    if not isinstance(roles, dict):
        raise ValueError("Policy must contain a 'roles' mapping")

    return policy


# Load and validate once at import time
_POLICY: dict[str, Any] = _load_and_validate_registry()


def list_tools() -> list[str]:
    """Returns a list of all known tool names."""
    tools = _POLICY.get("tools", {})
    return list(tools.keys())


def get_tool(name: str) -> dict[str, Any] | None:
    """
    Returns a copy of the tool metadata dictionary.
    Returns None if the tool is unknown (fail closed).
    """
    if not isinstance(name, str):
        return None
    tools = _POLICY.get("tools", {})
    cfg = tools.get(name)
    if cfg is None:
        return None
    res = dict(cfg)
    res["name"] = name
    return res


def risk(name: str) -> str | None:
    """
    Returns the risk level ('LOW', 'HIGH', 'HONEYPOT') for the tool.
    Returns None if the tool is unknown (fail closed).
    """
    if not isinstance(name, str):
        return None
    tools = _POLICY.get("tools", {})
    cfg = tools.get(name)
    if cfg is None:
        return None
    return cfg.get("risk")


def roles_allowed(name: str) -> list[str]:
    """
    Returns a list of role names allowed to execute this tool.
    Returns an empty list if the tool is unknown (fail closed).
    """
    if not isinstance(name, str):
        return []
    tools = _POLICY.get("tools", {})
    if name not in tools:
        return []

    roles = _POLICY.get("roles", {})
    allowed: list[str] = []
    for role_name, role_cfg in roles.items():
        if isinstance(role_cfg, dict):
            allowed_tools = role_cfg.get("allowed_tools", [])
            if name in allowed_tools:
                allowed.append(role_name)
    return allowed


def is_tool_allowed_for_role(name: str, role: str) -> bool:
    """Checks if a tool is allowed for a given role (fail closed)."""
    return role in roles_allowed(name)


def needs_approval(name: str) -> bool:
    """
    Returns True if the tool requires human operator approval before execution.
    Returns False for unknown tools or low-risk tools.
    """
    tool_risk = risk(name)
    if not tool_risk:
        return False

    approval_cfg = _POLICY.get("approval", {})
    if not approval_cfg.get("enabled", True):
        return False

    require_for_risk = approval_cfg.get("require_for_risk", ["HIGH"])
    return tool_risk in require_for_risk


def intent_keywords() -> dict[str, list[str]]:
    """Returns a mapping of intent group names to their configured trigger keywords."""
    intents = _POLICY.get("intents", {})
    return {
        k: list(v.get("keywords", []))
        for k, v in intents.items()
        if isinstance(v, dict)
    }


def default_scope() -> list[str]:
    """
    Returns the configured default intent scope list from policy.yaml.
    Fails closed with an empty list if not configured.
    """
    intent_lock_cfg = _POLICY.get("intent_lock", {})
    scope = intent_lock_cfg.get("default_scope")
    if isinstance(scope, list):
        return list(scope)
    return []
