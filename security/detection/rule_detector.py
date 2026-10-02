"""
Phase 5 — Rule-Based Detector
"""

from pathlib import Path
import re
import yaml

from security.detection.base import Detector, DetectionContext, DetectionResult
from security.detection.normalizer import get_text_views


class RuleDetector(Detector):
    name = "rules"

    def __init__(self, rules_file_path: str | Path):
        self.rules_file_path = Path(rules_file_path)
        self.rules = self._load_and_validate_rules()

    def _load_and_validate_rules(self) -> list[dict]:
        if not self.rules_file_path.exists():
            raise FileNotFoundError(f"Rules file not found at {self.rules_file_path}")

        with open(self.rules_file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if not isinstance(data, dict) or "rules" not in data or not isinstance(data["rules"], list):
            raise ValueError(f"Invalid rules file format in {self.rules_file_path}: missing top-level 'rules' list")

        raw_rules = data["rules"]
        validated_rules = []
        seen_ids = set()

        required_fields = {"id", "category", "weight", "description", "pattern"}

        for idx, rule in enumerate(raw_rules):
            if not isinstance(rule, dict):
                raise ValueError(f"Rule at index {idx} is not a dictionary")

            missing = required_fields - set(rule.keys())
            if missing:
                raise ValueError(f"Rule at index {idx} missing required fields: {missing}")

            rule_id = str(rule["id"]).strip()
            if not rule_id:
                raise ValueError(f"Rule at index {idx} has an empty id")

            if rule_id in seen_ids:
                raise ValueError(f"Duplicate rule id found: '{rule_id}'")
            seen_ids.add(rule_id)

            weight = rule["weight"]
            if not isinstance(weight, (int, float)) or not (0.0 <= weight <= 1.0):
                raise ValueError(f"Rule '{rule_id}' weight {weight} is invalid (must be between 0.0 and 1.0)")

            pattern_str = str(rule["pattern"])
            try:
                compiled_pattern = re.compile(pattern_str, re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"Rule '{rule_id}' has invalid regex pattern '{pattern_str}': {e}")

            validated_rules.append({
                "id": rule_id,
                "category": str(rule["category"]),
                "weight": float(weight),
                "description": str(rule["description"]),
                "pattern": compiled_pattern,
            })

        return validated_rules

    def analyze(self, ctx: DetectionContext) -> DetectionResult:
        views = get_text_views(ctx.text)
        matched_weights = []
        rule_ids = []
        reasons = []

        for rule in self.rules:
            for view_name, view_text in views:
                if rule["pattern"].search(view_text):
                    matched_weights.append(rule["weight"])
                    rule_ids.append(rule["id"])
                    reasons.append(f"{rule['id']} {rule['category']} (via {view_name})")
                    break  # Each rule counts at most once

        if not matched_weights:
            score = 0.0
        else:
            prod = 1.0
            for w in matched_weights:
                prod *= (1.0 - w)
            score = 1.0 - prod

        return DetectionResult(
            detector=self.name,
            score=round(score, 4),
            reasons=reasons,
            rule_ids=rule_ids,
        )
