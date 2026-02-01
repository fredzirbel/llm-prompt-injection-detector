"""Log event schemas for SIEM ingestion."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone


@dataclass
class AnalysisLogEvent:
    """Structured log event for a prompt analysis. Designed for SIEM consumption."""

    timestamp: str
    event_type: str = "prompt_analysis"
    prompt_hash: str = ""
    prompt_length: int = 0
    verdict: str = ""
    confidence: float = 0.0
    primary_category: str = ""
    triggered_detectors: list[str] | None = None
    detector_confidences: dict[str, float] | None = None
    latency_ms: float = 0.0
    source_ip: str = ""
    request_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_analysis(
        cls,
        prompt_hash: str,
        prompt_length: int,
        verdict: str,
        confidence: float,
        primary_category: str,
        triggered_detectors: list[str],
        detector_confidences: dict[str, float],
        latency_ms: float,
        source_ip: str = "",
        request_id: str = "",
    ) -> AnalysisLogEvent:
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            prompt_hash=prompt_hash,
            prompt_length=prompt_length,
            verdict=verdict,
            confidence=confidence,
            primary_category=primary_category,
            triggered_detectors=triggered_detectors,
            detector_confidences=detector_confidences,
            latency_ms=latency_ms,
            source_ip=source_ip,
            request_id=request_id,
        )
