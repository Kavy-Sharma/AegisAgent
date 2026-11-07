"""
Aegis Stage Map - Canonical Audit Layer to Gate Index Mapping.
Zero-based indexing (0..8) across Overview, Console, and Attack Lab.
"""

from typing import Optional

# Canonical 0-based mapping from audit stage/layer names to gate indices
STAGE_MAP: dict[str, int] = {
    # Gate 0: Prompt Injection Detection & Quarantine
    "detection": 0,
    "injection": 0,
    "quarantine": 0,

    # Gate 1: Intent Lock & Scope Validation
    "intent": 1,
    "intent_lock": 1,
    "scope": 1,

    # Gate 2: Model / LLM Policy
    "llm": 2,
    "model": 2,

    # Gate 3: RBAC / Role Permissions
    "rbac": 3,
    "role": 3,

    # Gate 4: Parameter Guard (Path, SQL, Range, Type)
    "param_guard": 4,
    "parameters": 4,
    "parameter": 4,

    # Gate 5: Rate Limiter
    "rate_limit": 5,
    "rate": 5,

    # Gate 6: Cryptographic Human Approval
    "approval": 6,
    "human": 6,

    # Gate 7: Device Safety / Physical Actuation / Tool Execution
    "hardware": 7,
    "device": 7,
    "tool": 7,

    # Gate 8: Tool Output Sanitizer / Content Scan
    "output_scan": 8,
    "output": 8,
}

STAGE_LABELS_SMART_HOME: list[str] = [
    "Detection",
    "Intent lock",
    "Model",
    "Role",
    "Parameters",
    "Rate limit",
    "Approval",
    "Device (simulated)",
    "Output scan",
]

STAGE_LABELS_OFFICE: list[str] = [
    "Detection",
    "Intent lock",
    "Model",
    "Role",
    "Parameters",
    "Rate limit",
    "Approval",
    "Tool",
    "Output scan",
]


def get_gate_index(layer: Optional[str]) -> int:
    """Returns the 0-based gate index for a layer name, or -1 if unknown."""
    if not layer:
        return -1
    normalized = str(layer).strip().lower()
    if normalized in STAGE_MAP:
        return STAGE_MAP[normalized]
    # Check substring matches
    for k, idx in STAGE_MAP.items():
        if k in normalized:
            return idx
    return -1


def get_stage_labels(env_name: str = "smart_home") -> list[str]:
    """Returns the gate labels for the given environment."""
    if env_name == "office":
        return list(STAGE_LABELS_OFFICE)
    return list(STAGE_LABELS_SMART_HOME)
