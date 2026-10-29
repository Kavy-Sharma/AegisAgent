"""
Phase 9A -- Intent Lock: Scoped Execution Boundary

WHAT THIS FILE DOES:
Computes the allowed tool execution scope based on the user's explicit intent
expressed in user text. Matches keywords whole-word case-insensitively.
If no keywords match, falls back to the configured default_scope.
Pure function with no LLM dependency and NO hardware imports.
"""

import re
from typing import Any


def compute_scope(
    user_text: str,
    policy: dict[str, Any] | None = None,
) -> tuple[set[str], list[str]]:
    """
    Computes (scope_set, matched_intent_names) from user_text against policy intents.
    Performs whole-word matching strictly against user_text (never tool output).

    Returns:
        (scope, matched_intents):
            scope: set of allowed tool names
            matched_intents: list of matched intent group names
    """
    if policy is None:
        from security import policy_loader
        policy = policy_loader.POLICY

    intent_lock_cfg = policy.get("intent_lock", {})
    default_scope = list(intent_lock_cfg.get("default_scope", ["read_temperature", "read_note"]))
    intents = policy.get("intents", {})

    if not user_text or not isinstance(user_text, str):
        return set(default_scope), []

    matched_intents: list[str] = []
    scope: set[str] = set()

    for intent_name, intent_data in intents.items():
        keywords = intent_data.get("keywords", [])
        tools = intent_data.get("tools", [])
        matched = False
        for kw in keywords:
            # Whole-word regex match: \b{escaped_keyword}\b
            pattern = rf"\b{re.escape(str(kw))}\b"
            if re.search(pattern, user_text, re.IGNORECASE):
                matched = True
                break
        if matched:
            matched_intents.append(intent_name)
            scope.update(tools)

    if not matched_intents:
        return set(default_scope), []

    return scope, matched_intents

