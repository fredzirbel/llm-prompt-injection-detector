"""Structured JSON logger for SIEM-consumable output."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

from detector.logging_.schemas import AnalysisLogEvent


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "event_data"):
            log_data["event"] = record.event_data
        return json.dumps(log_data)


def get_logger(name: str = "detector") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def log_analysis(event: AnalysisLogEvent) -> None:
    logger = get_logger("detector.analysis")
    record = logger.makeRecord(
        name="detector.analysis",
        level=logging.INFO,
        fn="",
        lno=0,
        msg=f"Analysis: {event.verdict} (confidence={event.confidence:.4f})",
        args=(),
        exc_info=None,
    )
    record.event_data = event.to_dict()  # type: ignore[attr-defined]
    logger.handle(record)
