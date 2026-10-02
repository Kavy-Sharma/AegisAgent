"""
Phase 5 — Detection Engine and Session Store
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from security.detection.base import (
    DetectionContext,
    DetectionResult,
    HistoryEntry,
)
from security.detection.context_detector import ContextDetector
from security.detection.rule_detector import RuleDetector
import security.policy_loader


@dataclass
class Verdict:
    decision: str  # "ALLOW" | "REVIEW" | "BLOCK"
    score: float
    results: list[DetectionResult] = field(default_factory=list)
    session_id: str = "default"
    source: str = "user"


# Detector registry mapping name -> factory function
DETECTOR_REGISTRY = {
    "rules": lambda cfg: RuleDetector(cfg.get("rules_file", "security/rules/injection_rules.yaml")),
    "context": lambda cfg, rule_det: ContextDetector(
        rule_det, window_size=cfg.get("context_window", 4)
    ),
}


class DetectionEngine:
    def __init__(self, policy_dict: dict | None = None):
        if policy_dict is None:
            policy_dict = security.policy_loader.POLICY

        detection_cfg = policy_dict.get("detection", {})
        self.enabled = detection_cfg.get("enabled", True)
        self.mode = detection_cfg.get("mode", "monitor")
        self.review_threshold = float(detection_cfg.get("review_threshold", 0.5))
        self.block_threshold = float(detection_cfg.get("block_threshold", 0.8))
        self.context_window = int(detection_cfg.get("context_window", 4))
        self.scan_tool_outputs = detection_cfg.get("scan_tool_outputs", True)
        self.rules_file = detection_cfg.get("rules_file", "security/rules/injection_rules.yaml")

        detector_names = detection_cfg.get("detectors", ["rules", "context"])

        # Session store: dict session_id -> deque(maxlen=context_window) of HistoryEntry
        self.sessions: dict[str, deque[HistoryEntry]] = defaultdict(
            lambda: deque(maxlen=self.context_window)
        )

        # Build detectors from policy in listed order
        self.detectors = []
        self.rule_detector_instance = None

        for name in detector_names:
            if name == "rules":
                rule_det = DETECTOR_REGISTRY["rules"]({"rules_file": self.rules_file})
                self.rule_detector_instance = rule_det
                self.detectors.append(rule_det)
            elif name == "context":
                if not self.rule_detector_instance:
                    # Rules detector must run before context detector
                    self.rule_detector_instance = DETECTOR_REGISTRY["rules"]({"rules_file": self.rules_file})
                ctx_det = DETECTOR_REGISTRY["context"](
                    {"context_window": self.context_window}, self.rule_detector_instance
                )
                self.detectors.append(ctx_det)
            else:
                raise ValueError(f"Unknown detector name in policy: '{name}'")

    def inspect(self, session_id: str, text: str, source: str = "user") -> Verdict:
        # Build DetectionContext (history is non-empty only when source == "user")
        if source == "user":
            history = list(self.sessions[session_id])
        else:
            history = []

        ctx = DetectionContext(
            text=text,
            source=source,
            history=history,
            prior_results=[],
        )

        # Run detectors in order, passing earlier results in prior_results
        for detector in self.detectors:
            res = detector.analyze(ctx)
            ctx.prior_results.append(res)

        # ensemble voting plugs in here later
        final_score = max((res.score for res in ctx.prior_results), default=0.0)
        final_score = round(final_score, 4)

        if not self.enabled:
            decision = "ALLOW"
        elif final_score >= self.block_threshold:
            decision = "BLOCK"
        elif final_score >= self.review_threshold:
            decision = "REVIEW"
        else:
            decision = "ALLOW"

        # Append HistoryEntry to the session ONLY when source == "user"
        # message_level_score = the rule detector's score (NOT context score, to avoid feedback loops)
        if source == "user":
            rule_res = next((res for res in ctx.prior_results if res.detector == "rules"), None)
            message_level_score = rule_res.score if rule_res else 0.0
            self.sessions[session_id].append(HistoryEntry(text=text, score=message_level_score))

        return Verdict(
            decision=decision,
            score=final_score,
            results=ctx.prior_results,
            session_id=session_id,
            source=source,
        )

    def reset_session(self, session_id: str):
        if session_id in self.sessions:
            self.sessions[session_id].clear()
