"""Heuristic-based prompt injection detector.

Uses statistical properties of the prompt to detect injection attempts:
- Character entropy analysis
- Instruction-like token ratio
- Structural markers (role tags, delimiters)
- Special character density
"""

from __future__ import annotations

import math
import re
from collections import Counter

from detector.engine.base import BaseDetector
from detector.models import DetectorResult, AttackCategory

INSTRUCTION_TOKENS = {
    "ignore", "override", "forget", "disregard", "bypass", "system", "prompt",
    "instructions", "instruction", "previous", "rules", "pretend", "act",
    "role", "admin", "sudo", "root", "developer", "mode", "jailbreak",
    "restrict", "unrestrict", "filter", "safety", "guardrail", "execute",
    "command", "inject", "payload", "output", "reveal", "secret", "hidden",
    "confidential", "internal", "print", "repeat", "verbatim", "decode",
}

ROLE_MARKERS = re.compile(
    r"\[(SYSTEM|INST|SYS|ADMIN|USER|ASSISTANT|HUMAN|BOT)\]|"
    r"<\s*/?\s*(system|instruction|prompt|context)\s*>|"
    r'"""|###|---{3,}|==={3,}',
    re.IGNORECASE,
)

SPECIAL_CHARS = set('{}[]<>\\|`~^')


def _char_entropy(text: str) -> float:
    """Calculate Shannon entropy of character distribution."""
    if not text:
        return 0.0
    counts = Counter(text.lower())
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _instruction_token_ratio(text: str) -> float:
    """Ratio of instruction-like tokens to total tokens."""
    words = re.findall(r'\w+', text.lower())
    if not words:
        return 0.0
    instruction_count = sum(1 for w in words if w in INSTRUCTION_TOKENS)
    return instruction_count / len(words)


def _structural_marker_density(text: str) -> float:
    """Count of role/delimiter markers normalized by text length."""
    matches = ROLE_MARKERS.findall(text)
    if not text:
        return 0.0
    return len(matches) / max(len(text) / 100, 1)


def _special_char_density(text: str) -> float:
    """Ratio of special characters that are common in injection payloads."""
    if not text:
        return 0.0
    special_count = sum(1 for c in text if c in SPECIAL_CHARS)
    return special_count / len(text)


class HeuristicDetector(BaseDetector):
    name = "heuristic"

    # Thresholds determined through analysis of injection vs. benign prompts
    ENTROPY_THRESHOLD = 4.5
    TOKEN_RATIO_THRESHOLD = 0.08
    STRUCTURAL_THRESHOLD = 0.3
    SPECIAL_CHAR_THRESHOLD = 0.05

    def detect(self, prompt: str) -> DetectorResult:
        entropy = _char_entropy(prompt)
        token_ratio = _instruction_token_ratio(prompt)
        structural = _structural_marker_density(prompt)
        special = _special_char_density(prompt)

        signals = []
        scores = []

        if token_ratio > self.TOKEN_RATIO_THRESHOLD:
            signals.append(f"instruction_token_ratio={token_ratio:.3f}")
            scores.append(min(token_ratio / 0.2, 1.0))

        if structural > self.STRUCTURAL_THRESHOLD:
            signals.append(f"structural_markers={structural:.3f}")
            scores.append(min(structural / 1.0, 1.0))

        if special > self.SPECIAL_CHAR_THRESHOLD:
            signals.append(f"special_char_density={special:.3f}")
            scores.append(min(special / 0.15, 1.0))

        if entropy > self.ENTROPY_THRESHOLD and len(prompt) > 50:
            signals.append(f"high_entropy={entropy:.2f}")
            scores.append(0.3)

        if not scores:
            return DetectorResult(
                detector_name=self.name,
                triggered=False,
                confidence=0.0,
                categories=[],
                details="No heuristic signals triggered.",
            )

        confidence = min(sum(scores) / len(scores) + 0.1 * (len(scores) - 1), 1.0)

        categories = []
        if structural > self.STRUCTURAL_THRESHOLD:
            categories.append(AttackCategory.DELIMITER_INJECTION)
        if token_ratio > self.TOKEN_RATIO_THRESHOLD:
            categories.append(AttackCategory.ROLE_OVERRIDE)

        return DetectorResult(
            detector_name=self.name,
            triggered=True,
            confidence=round(confidence, 3),
            categories=categories or [AttackCategory.CONTEXT_MANIPULATION],
            details=f"Heuristic signals: {', '.join(signals)}",
        )
