"""Regex-based prompt injection detector."""

from __future__ import annotations

from detector.engine.base import BaseDetector
from detector.models import DetectorResult, AttackCategory
from detector.patterns.injection_patterns import ALL_PATTERNS


class RegexDetector(BaseDetector):
    name = "regex"

    def detect(self, prompt: str) -> DetectorResult:
        triggered_patterns = []

        for pattern in ALL_PATTERNS:
            if pattern.pattern.search(prompt):
                triggered_patterns.append(pattern)

        if not triggered_patterns:
            return DetectorResult(
                detector_name=self.name,
                triggered=False,
                confidence=0.0,
                categories=[],
                details="No known injection patterns detected.",
            )

        max_confidence = max(p.confidence for p in triggered_patterns)
        categories = list({p.category for p in triggered_patterns})
        pattern_names = [p.name for p in triggered_patterns]

        return DetectorResult(
            detector_name=self.name,
            triggered=True,
            confidence=max_confidence,
            categories=categories,
            details=f"Matched patterns: {', '.join(pattern_names)}",
        )
