"""Ensemble scoring engine that combines all detectors."""

from __future__ import annotations

import hashlib

from detector.engine.base import BaseDetector
from detector.engine.regex_detector import RegexDetector
from detector.engine.heuristic_detector import HeuristicDetector
from detector.engine.ml_detector import MLDetector
from detector.models import (
    AnalysisResponse,
    AttackCategory,
    DetectorResult,
    Verdict,
)
from detector.config import settings


class EnsembleDetector:
    """Combines regex, heuristic, and ML detectors with weighted scoring."""

    def __init__(self):
        self.regex = RegexDetector()
        self.heuristic = HeuristicDetector()
        self.ml = MLDetector()

        self._detectors: list[BaseDetector] = [self.regex, self.heuristic, self.ml]

    @property
    def loaded_detectors(self) -> list[str]:
        names = ["regex", "heuristic"]
        if self.ml.is_loaded:
            names.append("ml_classifier")
        return names

    def analyze(self, prompt: str) -> AnalysisResponse:
        results: list[DetectorResult] = []
        for detector in self._detectors:
            result = detector.detect(prompt)
            results.append(result)

        regex_result, heuristic_result, ml_result = results

        # Weighted score calculation
        weights = {
            "regex": settings.regex_weight,
            "heuristic": settings.heuristic_weight,
            "ml_classifier": settings.ml_weight,
        }

        # If ML model isn't loaded, redistribute its weight
        if not self.ml.is_loaded:
            total_non_ml = weights["regex"] + weights["heuristic"]
            weights["regex"] = weights["regex"] / total_non_ml
            weights["heuristic"] = weights["heuristic"] / total_non_ml
            weights["ml_classifier"] = 0.0

        weighted_score = (
            regex_result.confidence * weights["regex"]
            + heuristic_result.confidence * weights["heuristic"]
            + ml_result.confidence * weights["ml_classifier"]
        )

        # Boost: if regex matches with high confidence, ensure the score reflects it
        if regex_result.triggered and regex_result.confidence >= 0.9:
            weighted_score = max(weighted_score, 0.75)

        # Determine verdict
        if weighted_score >= settings.malicious_threshold:
            verdict = Verdict.MALICIOUS
        elif weighted_score >= settings.suspicious_threshold:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        # Determine primary category
        all_categories = []
        for r in results:
            if r.triggered:
                all_categories.extend(r.categories)

        if all_categories:
            category_counts: dict[AttackCategory, int] = {}
            for cat in all_categories:
                category_counts[cat] = category_counts.get(cat, 0) + 1
            primary_category = max(category_counts, key=category_counts.get)
        else:
            primary_category = AttackCategory.NONE

        # Build explanation
        triggered = [r for r in results if r.triggered]
        if triggered:
            trigger_details = "; ".join(
                f"{r.detector_name} ({r.confidence:.2f}): {r.details}" for r in triggered
            )
            explanation = f"Detected by {len(triggered)} detector(s). {trigger_details}"
        else:
            explanation = "No injection patterns detected across all detection layers."

        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()

        return AnalysisResponse(
            verdict=verdict,
            confidence=round(weighted_score, 4),
            triggered_detectors=results,
            primary_category=primary_category,
            explanation=explanation,
            prompt_hash=prompt_hash,
        )
