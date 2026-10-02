"""
Phase 5 — Multi-Turn Context Detector
"""

from security.detection.base import Detector, DetectionContext, DetectionResult
from security.detection.rule_detector import RuleDetector


class ContextDetector(Detector):
    name = "context"

    def __init__(self, rule_detector: RuleDetector, window_size: int = 4):
        self.rule_detector = rule_detector
        self.window_size = window_size

    def analyze(self, ctx: DetectionContext) -> DetectionResult:
        if not ctx.history:
            return DetectionResult(
                detector=self.name,
                score=0.0,
                reasons=[],
                rule_ids=[],
            )

        current_msg_score = max((res.score for res in ctx.prior_results), default=0.0)

        # a) Cumulative suspicion: noisy-OR over history entries + current message's score
        history_scores = [h.score for h in ctx.history]
        all_scores = history_scores + [current_msg_score]

        prod = 1.0
        for s in all_scores:
            prod *= (1.0 - s)
        cum_score = round(1.0 - prod, 4)

        N = len(ctx.history) + 1
        cum_reason = f"Cumulative suspicion across {N} messages in window"

        # b) Split payload: join texts of history entries + current text with single spaces, run rule_detector
        joined_text = " ".join([h.text for h in ctx.history] + [ctx.text])
        split_ctx = DetectionContext(
            text=joined_text,
            source=ctx.source,
            history=[],
            prior_results=[],
        )
        split_result = self.rule_detector.analyze(split_ctx)

        split_score = split_result.score
        split_payload_active = False

        if split_score > current_msg_score:
            split_payload_active = True

        # Return the check with the higher score
        if split_payload_active and split_score > cum_score:
            return DetectionResult(
                detector=self.name,
                score=split_score,
                reasons=[f"Split payload across {N} messages"],
                rule_ids=split_result.rule_ids,
            )
        elif cum_score > 0.0:
            return DetectionResult(
                detector=self.name,
                score=cum_score,
                reasons=[cum_reason],
                rule_ids=[],
            )
        else:
            return DetectionResult(
                detector=self.name,
                score=0.0,
                reasons=[],
                rule_ids=[],
            )
