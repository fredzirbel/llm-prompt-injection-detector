"""Evaluate the trained model and output metrics.

Usage:
    python -m ml.evaluate
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score

MODEL_DIR = Path(__file__).parent / "model"
DATA_DIR = Path(__file__).parent.parent / "data"


def evaluate():
    model_path = MODEL_DIR / "classifier.joblib"
    vectorizer_path = MODEL_DIR / "vectorizer.joblib"

    if not model_path.exists() or not vectorizer_path.exists():
        print("Model not found. Run ml/train.py first.")
        return

    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)

    # Load data
    from ml.train import load_data
    texts, labels = load_data()

    if not texts:
        print("No data found.")
        return

    X = vectorizer.transform(texts)

    # Cross-validation on full dataset
    cv_scores = cross_val_score(model, X, labels, cv=5, scoring="f1")
    print(f"5-fold CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    y_pred = model.predict(X)
    print("\nFull Dataset Classification Report:")
    print(classification_report(labels, y_pred, target_names=["benign", "injection"]))
    print("Confusion Matrix:")
    print(confusion_matrix(labels, y_pred))

    # Check minimum F1 threshold
    metrics_path = MODEL_DIR / "metrics.json"
    if metrics_path.exists():
        with open(metrics_path) as f:
            metrics = json.load(f)
        f1 = metrics.get("test_f1_injection", 0)
        threshold = 0.80
        if f1 >= threshold:
            print(f"\nModel meets minimum F1 threshold: {f1:.4f} >= {threshold}")
        else:
            print(f"\nWARNING: Model below F1 threshold: {f1:.4f} < {threshold}")


if __name__ == "__main__":
    evaluate()
