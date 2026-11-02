"""
Unit tests for security.registry (Tool Registry Loader - Step 1)

Verifies:
1. EQUIVALENCE: registry answers for every tool and role are identical to policy_loader.
2. FAIL-CLOSED: unknown tools are denied / return None.
3. VALIDATION: broken or malformed policy files raise ValueError at load.
4. IMMUTABILITY: registry exposes strictly read-only functions (no write methods).
5. INTENT DEFAULT SCOPE: missing default_scope fails closed to empty scope.
"""

from pathlib import Path
import pytest
import yaml

from security import policy_loader
from security import registry
from security.intent import compute_scope


# ============================================================================
# 1. EQUIVALENCE TESTS
# ============================================================================

def test_registry_lists_all_policy_tools():
    """list_tools() must return the exact set of tools configured in policy.yaml."""
    expected_tools = set(policy_loader.POLICY.get("tools", {}).keys())
    registered_tools = set(registry.list_tools())
    assert registered_tools == expected_tools
    assert len(registered_tools) == 7


def test_registry_risk_equivalence():
    """registry.risk(t) must match policy_loader.get_risk(t) for all tools."""
    for tool_name in registry.list_tools():
        assert registry.risk(tool_name) == policy_loader.get_risk(tool_name)


def test_registry_roles_equivalence():
    """registry role permissions must match policy_loader.is_tool_allowed_for_role across all roles."""
    roles_to_test = ["guest", "admin", "operator", "root", "unknown_role"]
    for tool_name in registry.list_tools():
        allowed_roles = registry.roles_allowed(tool_name)
        for role in roles_to_test:
            expected = policy_loader.is_tool_allowed_for_role(tool_name, role)
            assert (role in allowed_roles) == expected
            assert registry.is_tool_allowed_for_role(tool_name, role) == expected


def test_registry_needs_approval_equivalence():
    """registry.needs_approval(t) must match policy approval rules for all tools."""
    approval_cfg = policy_loader.POLICY.get("approval", {})
    enabled = approval_cfg.get("enabled", True)
    req_risks = approval_cfg.get("require_for_risk", ["HIGH"])

    for tool_name in registry.list_tools():
        expected = enabled and (registry.risk(tool_name) in req_risks)
        assert registry.needs_approval(tool_name) == expected


def test_registry_default_scope_equivalence():
    """registry.default_scope() must match policy.yaml intent_lock.default_scope."""
    expected_scope = list(policy_loader.POLICY.get("intent_lock", {}).get("default_scope", []))
    assert registry.default_scope() == expected_scope


def test_registry_intent_keywords_equivalence():
    """registry.intent_keywords() must contain all intent groups and keywords from policy."""
    expected_intents = policy_loader.POLICY.get("intents", {})
    reg_keywords = registry.intent_keywords()
    for intent_name, intent_data in expected_intents.items():
        assert intent_name in reg_keywords
        assert reg_keywords[intent_name] == list(intent_data.get("keywords", []))


# ============================================================================
# 2. FAIL-CLOSED BEHAVIOR
# ============================================================================

@pytest.mark.parametrize("unknown_name", [
    "self_destruct",
    "launch_missiles",
    "format_disk",
    "read_admin_passwords",
    "unknown_tool_xyz",
    "",
    None,
])
def test_unknown_tool_fails_closed(unknown_name):
    """Unknown or invalid tool names must be denied and return None/empty."""
    assert registry.get_tool(unknown_name) is None
    assert registry.risk(unknown_name) is None
    assert registry.roles_allowed(unknown_name) == []
    assert registry.is_tool_allowed_for_role(unknown_name, "admin") is False
    assert registry.is_tool_allowed_for_role(unknown_name, "guest") is False
    assert registry.needs_approval(unknown_name) is False


# ============================================================================
# 3. BROKEN POLICY VALIDATION
# ============================================================================

def test_missing_policy_file_raises(tmp_path):
    """Non-existent policy file must raise FileNotFoundError."""
    missing = tmp_path / "nonexistent_policy.yaml"
    with pytest.raises(FileNotFoundError):
        registry._load_and_validate_registry(missing)


def test_malformed_policy_raises(tmp_path):
    """Malformed YAML or invalid structure must raise ValueError at load."""
    p1 = tmp_path / "not_dict.yaml"
    p1.write_text("- item1\n- item2", encoding="utf-8")
    with pytest.raises(ValueError, match="root must be a mapping"):
        registry._load_and_validate_registry(p1)

    p2 = tmp_path / "missing_tools.yaml"
    p2.write_text("roles:\n  guest: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="'tools' mapping"):
        registry._load_and_validate_registry(p2)

    p3 = tmp_path / "invalid_risk.yaml"
    p3.write_text("tools:\n  my_tool:\n    risk: SUPER_DANGEROUS\nroles: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid or missing risk level"):
        registry._load_and_validate_registry(p3)


# ============================================================================
# 4. IMMUTABILITY & READ-ONLY ENFORCEMENT
# ============================================================================

def test_registry_exposes_no_write_functions():
    """Registry must expose strictly read-only functions (no write or mutation APIs)."""
    forbidden_write_attrs = [
        "add_tool", "register_tool", "set_tool", "modify_tool",
        "update_tool", "delete_tool", "remove_tool", "write_tool"
    ]
    for attr in forbidden_write_attrs:
        assert not hasattr(registry, attr), f"Registry illegally exposes write method '{attr}'!"


def test_returned_tool_dict_mutation_does_not_affect_registry():
    """Mutating a returned metadata dict must not modify the internal registry."""
    tool_meta = registry.get_tool("turn_light_on")
    assert tool_meta is not None
    original_risk = tool_meta.get("risk")

    # Mutate caller copy
    tool_meta["risk"] = "HIGH"
    tool_meta["hacked"] = True

    # Verify registry remains unchanged
    fresh_meta = registry.get_tool("turn_light_on")
    assert fresh_meta["risk"] == original_risk
    assert "hacked" not in fresh_meta


# ============================================================================
# 5. INTENT DEFAULT SCOPE FAIL-CLOSED
# ============================================================================

def test_intent_default_scope_missing_fails_closed():
    """When intent_lock.default_scope is missing from policy, compute_scope fails closed to empty."""
    minimal_policy = {
        "intent_lock": {"enabled": True},
        "intents": {
            "light": {"keywords": ["light"], "tools": ["turn_light_on"]}
        }
    }
    # User text has no keywords matching 'light'
    scope, matched = compute_scope("hello there how are you", policy=minimal_policy)
    assert matched == []
    assert scope == set()
