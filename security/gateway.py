"""
Phase 4 — Security Gateway (Permissions, Risk & Rate Limiting)

WHAT THIS FILE DOES:
Intercepts tool execution requests from the agent and applies policy checks:
1. Tool existence check
2. Role-Based Access Control (RBAC)
3. Sliding window rate limiting
4. Risk-level assessment (LOW auto-allowed, HIGH blocked pending Phase 6 approval)
5. Tamper-evident audit logging
"""

from security import logger, policy_loader, rate_limiter


def evaluate(tool_name: str, tool_args: dict, user_text: str, role: str = "guest") -> dict:
    """
    Evaluates a tool execution request against active policy rules.

    Args:
        tool_name: Name of tool requested.
        tool_args: Dictionary of arguments.
        user_text: Original prompt text from user.
        role: User role ('guest' or 'admin'). Default is 'guest'.

    Returns:
        dict: {"decision": "ALLOW" | "BLOCK", "reason": str}
    """
    risk = policy_loader.get_risk(tool_name)

    # a. If tool_name not in policy -> decision BLOCK, reason "unknown tool"
    if risk is None:
        decision = "BLOCK"
        reason = "unknown tool"
        logger.log_decision(tool_name, tool_args, role, risk, decision, reason)
        return {"decision": decision, "reason": reason}

    # b. If NOT is_tool_allowed_for_role(tool_name, role) -> decision BLOCK
    if not policy_loader.is_tool_allowed_for_role(tool_name, role):
        decision = "BLOCK"
        reason = f"permission denied: role '{role}' cannot use '{tool_name}'"
        logger.log_decision(tool_name, tool_args, role, risk, decision, reason)
        return {"decision": decision, "reason": reason}

    # c. If NOT rate_limiter.check_rate_limit(tool_name) -> decision BLOCK
    if not rate_limiter.check_rate_limit(tool_name):
        decision = "BLOCK"
        reason = f"rate limit exceeded for '{tool_name}'"
        logger.log_decision(tool_name, tool_args, role, risk, decision, reason)
        return {"decision": decision, "reason": reason}

    # e. Call rate_limiter.record_call(tool_name) ONLY if we got past step (c)
    rate_limiter.record_call(tool_name)

    # d. Otherwise look up risk = get_risk(tool_name)
    if risk == "LOW":
        decision = "ALLOW"
        reason = "low risk, auto-allowed"
    elif risk == "HIGH":
        decision = "BLOCK"
        reason = "high risk, blocked pending human-approval flow (Phase 6)"
    else:
        decision = "BLOCK"
        reason = f"unrecognized risk level '{risk}'"

    # f. Call logger.log_decision(...) for EVERY call
    logger.log_decision(tool_name, tool_args, role, risk, decision, reason)

    # g. Return {"decision": decision, "reason": reason}
    return {"decision": decision, "reason": reason}


from security.detection.engine import DetectionEngine, Verdict

_detection_engine = None


def get_detection_engine() -> DetectionEngine:
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    return _detection_engine


def handle_review(session_id: str, verdict: Verdict) -> str:
    # Phase 6: human-in-the-loop approval plugs in here
    print(f"[GATEWAY WARNING] Prompt injection review required for session '{session_id}' (score: {verdict.score:.2f})")
    return "allow"


def inspect_user_message(session_id: str, text: str) -> Verdict:
    engine = get_detection_engine()
    try:
        verdict = engine.inspect(session_id, text, source="user")
        rule_ids = [r for res in verdict.results for r in res.rule_ids]
        logger.log_injection_check(
            session_id=session_id,
            source="user",
            decision=verdict.decision,
            score=verdict.score,
            rule_ids=rule_ids,
            text=text,
        )
        return verdict
    except Exception as e:
        logger.log_engine_error(
            session_id=session_id,
            source="user",
            error=str(e),
            text=text,
        )
        mode = getattr(engine, "mode", "enforce")
        if mode == "enforce":
            return Verdict(
                decision="BLOCK",
                score=1.0,
                results=[],
                session_id=session_id,
                source="user",
            )
        else:
            return Verdict(
                decision="ALLOW",
                score=0.0,
                results=[],
                session_id=session_id,
                source="user",
            )


def inspect_tool_output(session_id: str, text: str) -> Verdict:
    engine = get_detection_engine()
    try:
        verdict = engine.inspect(session_id, text, source="tool_output")
        rule_ids = [r for res in verdict.results for r in res.rule_ids]
        logger.log_injection_check(
            session_id=session_id,
            source="tool_output",
            decision=verdict.decision,
            score=verdict.score,
            rule_ids=rule_ids,
            text=text,
        )
        return verdict
    except Exception as e:
        logger.log_engine_error(
            session_id=session_id,
            source="tool_output",
            error=str(e),
            text=text,
        )
        return Verdict(
            decision="BLOCK",
            score=1.0,
            results=[],
            session_id=session_id,
            source="tool_output",
        )

