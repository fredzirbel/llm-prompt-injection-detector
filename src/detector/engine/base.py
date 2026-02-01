"""Abstract base class for all detection engines."""

from __future__ import annotations

from abc import ABC, abstractmethod

from detector.models import DetectorResult


class BaseDetector(ABC):
    """All detector implementations must inherit from this class."""

    name: str = ""

    @abstractmethod
    def detect(self, prompt: str) -> DetectorResult:
        """Analyze a prompt and return a detection result."""
        ...
