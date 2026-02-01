"""Pydantic request/response schemas."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class AttackCategory(str, Enum):
    ROLE_OVERRIDE = "role_override"
    INSTRUCTION_LEAK = "instruction_leak"
    ENCODING_EVASION = "encoding_evasion"
    DELIMITER_INJECTION = "delimiter_injection"
    INDIRECT_INJECTION = "indirect_injection"
    CONTEXT_MANIPULATION = "context_manipulation"
    NONE = "none"


class AnalysisRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="The prompt text to analyze")
    metadata: dict | None = Field(default=None, description="Optional metadata about the request")


class DetectorResult(BaseModel):
    detector_name: str
    triggered: bool
    confidence: float = Field(ge=0.0, le=1.0)
    categories: list[AttackCategory] = Field(default_factory=list)
    details: str = ""


class AnalysisResponse(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    triggered_detectors: list[DetectorResult]
    primary_category: AttackCategory
    explanation: str
    prompt_hash: str = Field(description="SHA-256 hash of the prompt (privacy)")


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str
    detectors_loaded: list[str]


class StatsResponse(BaseModel):
    total_analyzed: int
    total_clean: int
    total_suspicious: int
    total_malicious: int
    top_categories: dict[str, int]
