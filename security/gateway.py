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
from security.approval import ApprovalManager, ApprovalRequest
from security.detection.engine import DetectionEngine, Verdict
import security.hardware



def evaluate(tool_name: str, tool_args: dict, user_text: str, role: str = "guest", session_id: str = "default") -> dict:
    """
    Evaluates a tool execution request against active policy rules.

    ORDER OF CHECKS:
    1. Tool existence check
    2. Role-Based Access Control (RBAC)
    3. Sliding window rate limiting
    4. Human approval check (if tool risk requires approval)
    5. Tamper-evident audit logging
    """
    risk = policy_loader.get_risk(tool_name)

    # a. If tool_name not in policy -> decision BLOCK, reason "unknown tool"
    if risk is None:
        decision = "BLOCK"
        reason = "unknown tool"
        logger.log_decision(tool_name, tool_args, role, risk, decision, reason)
        security.hardware.trigger_block_alert()
        return {"decision": decision, "reason": reason}

    # b. If NOT is_tool_allowed_for_role(tool_name, role) -> decision BLOCK (human operator NEVER asked)
    if not policy_loader.is_tool_allowed_for_role(tool_name, role):
        decision = "BLOCK"
        reason = f"permission denied: role '{role}' cannot use '{tool_name}'"
        logger.log_decision(tool_name, tool_args, role, risk, decision, reason)
        security.hardware.trigger_block_alert()
        return {"decision": decision, "reason": reason}

    # c. If NOT rate_limiter.check_rate_limit(tool_name) -> decision BLOCK (human operator NEVER asked)
    if not rate_limiter.check_rate_limit(tool_name):
        decision = "BLOCK"
        reason = f"rate limit exceeded for '{tool_name}'"
        logger.log_decision(tool_name, tool_args, role, risk, decision, reason)
        security.hardware.trigger_block_alert()
        return {"decision": decision, "reason": reason}

    # e. Call rate_limiter.record_call(tool_name) ONLY if we got past step (c)
    rate_limiter.record_call(tool_name)

    # d. Check approval policy for risk-level requirements
    approval_cfg = policy_loader.POLICY.get("approval", {})
    approval_enabled = approval_cfg.get("enabled", True)
    require_for_risk = approval_cfg.get("require_for_risk", ["HIGH"])

    if approval_enabled and risk in require_for_risk:
        reasons = [f"Tool '{tool_name}' with risk '{risk}' requires operator approval"]
        
        # Check if current session triggered injection detection (even in monitor mode)
        engine = get_detection_engine()
        last_v = engine.get_last_verdict(session_id)
        if last_v and last_v.decision in ("REVIEW", "BLOCK"):
            reasons.append(f"WARNING: this session triggered injection detection (score {last_v.score:.2f})")

        req = ApprovalRequest(
            session_id=session_id,
            kind="tool_call",
            tool=tool_name,
            args=tool_args,
            risk=risk,
            reasons=reasons,
        )
        mgr = get_approval_manager()
        app_result = mgr.request(req)

        if app_result.approved:
            decision = "ALLOW"
            reason = f"allowed by human operator ({app_result.decided_by})"
        else:
            decision = "BLOCK"
            if app_result.timed_out:
                reason = "Approval timed out, action denied"
            else:
                reason = "Action denied by human operator"
            # Note: Human operator denial or approval timeout is NOT an attack-type block;
            # trigger_block_alert() must fire ONLY for attack-type blocks (unknown tool, RBAC denial,
            # rate-limit exceeded, detection BLOCK). It must NOT fire for human operator denial or timeout.
    else:
        if risk == "LOW":
            decision = "ALLOW"
            reason = "low risk, auto-allowed"
        elif risk == "HIGH":
            decision = "BLOCK"
            reason = "high risk, blocked pending human-approval flow (Phase 6)"
            security.hardware.trigger_block_alert()
        else:
            decision = "BLOCK"
            reason = f"unrecognized risk level '{risk}'"
            security.hardware.trigger_block_alert()

    # f. Call logger.log_decision(...) for EVERY call
    logger.log_decision(tool_name, tool_args, role, risk, decision, reason)

    # g. Return {"decision": decision, "reason": reason}
    return {"decision": decision, "reason": reason}


_detection_engine = None
_approval_manager = None


def get_detection_engine() -> DetectionEngine:
    global _detection_engine
    if _detection_engine is None:
        _detection_engine = DetectionEngine()
    return _detection_engine


def get_approval_manager() -> ApprovalManager:
    global _approval_manager
    if _approval_manager is None:
        _approval_manager = ApprovalManager()
    return _approval_manager


def set_approval_manager(manager: ApprovalManager | None):
    global _approval_manager
    _approval_manager = manager


def handle_review(session_id: str, verdict: Verdict, text: str = "") -> bool:
    """
    Handles a REVIEW verdict on a user message or tool output.
    If require_for_review_verdict is true, prompts ApprovalManager (kind="message_review").
    Returns True if allowed/approved, False if denied.
    """
    approval_cfg = policy_loader.POLICY.get("approval", {})
    enabled = approval_cfg.get("enabled", True)
    require_for_review = approval_cfg.get("require_for_review_verdict", True)

    if enabled and require_for_review:
        reasons = [r for res in verdict.results for r in res.reasons]
        
        engine = get_detection_engine()
        last_v = engine.get_last_verdict(session_id)
        if last_v and last_v.decision in ("REVIEW", "BLOCK"):
            warn_msg = f"WARNING: this session triggered injection detection (score {last_v.score:.2f})"
            if warn_msg not in reasons:
                reasons.append(warn_msg)

        req = ApprovalRequest(
            session_id=session_id,
            kind="message_review",
            tool=None,
            args={"text": text[:200]},
            risk="REVIEW",
            reasons=reasons,
        )
        mgr = get_approval_manager()
        app_result = mgr.request(req)
        return app_result.approved
    else:
        print(f"[GATEWAY WARNING] Prompt injection review required for session '{session_id}' (score: {verdict.score:.2f})")
        return True


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
        mode = getattr(engine, "mode", "enforce")
        if verdict.decision == "BLOCK" and mode == "enforce":
            security.hardware.trigger_block_alert()
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
            security.hardware.trigger_block_alert()
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
        mode = getattr(engine, "mode", "enforce")
        if verdict.decision == "BLOCK" and mode == "enforce":
            security.hardware.trigger_block_alert()
        return verdict
    except Exception as e:
        logger.log_engine_error(
            session_id=session_id,
            source="tool_output",
            error=str(e),
            text=text,
        )
        security.hardware.trigger_block_alert()
        return Verdict(
            decision="BLOCK",
            score=1.0,
            results=[],
            session_id=session_id,
            source="tool_output",
        )



