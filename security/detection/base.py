"""
Phase 5 — Base Data Structures and Interface for Prompt Injection Detection
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    detector: str
    score: float
    reasons: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)


@dataclass
class HistoryEntry:
    text: str
    score: float


@dataclass
class DetectionContext:
    text: str
    source: str  # "user" or "tool_output"
    history: list[HistoryEntry] = field(default_factory=list)
    prior_results: list[DetectionResult] = field(default_factory=list)


class Detector(ABC):
    name: str

    @abstractmethod
    def analyze(self, ctx: DetectionContext) -> DetectionResult:
        pass
