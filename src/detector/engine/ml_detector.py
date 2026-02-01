"""ML-based prompt injection detector using TF-IDF + Logistic Regression."""

from __future__ import annotations

from pathlib import Path

from detector.engine.base import BaseDetector
from detector.models import DetectorResult, AttackCategory
from detector.config import settings


class MLDetector(BaseDetector):
    name = "ml_classifier"

    def __init__(self):
        self._model = None
        self._vectorizer = None
        self._loaded = False
        self._load_model()

    def _load_model(self) -> None:
        model_path = Path(settings.model_path)
        vectorizer_path = Path(settings.vectorizer_path)

        if not model_path.exists() or not vectorizer_path.exists():
            return

        try:
            import joblib
            self._model = joblib.load(model_path)
            self._vectorizer = joblib.load(vectorizer_path)
            self._loaded = True
        except Exception:
            self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def detect(self, prompt: str) -> DetectorResult:
        if not self._loaded:
            return DetectorResult(
                detector_name=self.name,
                triggered=False,
                confidence=0.0,
                categories=[],
                details="ML model not loaded. Run ml/train.py to train the classifier.",
            )

        features = self._vectorizer.transform([prompt])
        proba = self._model.predict_proba(features)[0]

        # Assumes binary classification: index 0 = benign, index 1 = injection
        injection_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

        triggered = injection_prob > 0.5

        return DetectorResult(
            detector_name=self.name,
            triggered=triggered,
            confidence=round(injection_prob, 4),
            categories=[AttackCategory.ROLE_OVERRIDE] if triggered else [],
            details=f"ML classifier probability: {injection_prob:.4f}",
        )
