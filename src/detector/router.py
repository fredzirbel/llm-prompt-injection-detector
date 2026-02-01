"""FastAPI routes."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request

from detector import __version__
from detector.engine.ensemble import EnsembleDetector
from detector.logging_.schemas import AnalysisLogEvent
from detector.logging_.structured_logger import log_analysis
from detector.models import (
    AnalysisRequest,
    AnalysisResponse,
    HealthResponse,
    StatsResponse,
)
from detector.storage.sqlite_store import AnalysisStore
from detector.config import settings

router = APIRouter()
ensemble = EnsembleDetector()
store = AnalysisStore(settings.db_path)


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_prompt(request: AnalysisRequest, req: Request) -> AnalysisResponse:
    start = time.perf_counter()

    result = ensemble.analyze(request.prompt)

    latency_ms = (time.perf_counter() - start) * 1000

    # Persist to storage
    triggered_names = [d.detector_name for d in result.triggered_detectors if d.triggered]
    store.save(
        prompt_hash=result.prompt_hash,
        prompt_length=len(request.prompt),
        verdict=result.verdict.value,
        confidence=result.confidence,
        primary_category=result.primary_category.value,
        triggered_detectors=",".join(triggered_names),
        explanation=result.explanation,
        latency_ms=latency_ms,
    )

    # Structured logging
    client_ip = req.client.host if req.client else ""
    event = AnalysisLogEvent.from_analysis(
        prompt_hash=result.prompt_hash,
        prompt_length=len(request.prompt),
        verdict=result.verdict.value,
        confidence=result.confidence,
        primary_category=result.primary_category.value,
        triggered_detectors=triggered_names,
        detector_confidences={
            d.detector_name: d.confidence for d in result.triggered_detectors
        },
        latency_ms=latency_ms,
        source_ip=client_ip,
    )
    log_analysis(event)

    return result


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version=__version__,
        detectors_loaded=ensemble.loaded_detectors,
    )


@router.get("/stats", response_model=StatsResponse)
async def stats() -> StatsResponse:
    data = store.get_stats()
    return StatsResponse(**data)
