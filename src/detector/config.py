"""Application configuration via pydantic-settings."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings

# Project root: two levels up from this file (src/detector/config.py -> project root)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    app_name: str = "Prompt Injection Detector"
    debug: bool = False

    # Detection thresholds
    suspicious_threshold: float = 0.4
    malicious_threshold: float = 0.7

    # Detector weights for ensemble scoring
    regex_weight: float = 0.35
    heuristic_weight: float = 0.25
    ml_weight: float = 0.40

    # ML model paths
    model_path: str = str(_PROJECT_ROOT / "ml" / "model" / "classifier.joblib")
    vectorizer_path: str = str(_PROJECT_ROOT / "ml" / "model" / "vectorizer.joblib")

    # Storage
    db_path: str = str(_PROJECT_ROOT / "detector_results.db")

    model_config = {"env_prefix": "DETECTOR_"}


settings = Settings()
