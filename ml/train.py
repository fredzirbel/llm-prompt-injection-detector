"""Train the TF-IDF + Logistic Regression classifier.

Usage:
    python -m ml.train

Requires: pip install .[ml]
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report, confusion_matrix

DATA_DIR = Path(__file__).parent.parent / "data"
MODEL_DIR = Path(__file__).parent / "model"


def load_data() -> tuple[list[str], list[int]]:
    """Load labeled data from CSV files in data/ directory."""
    texts, labels = [], []

    injection_path = DATA_DIR / "injection_samples.csv"
    benign_path = DATA_DIR / "benign_samples.csv"

    if injection_path.exists():
        df = pd.read_csv(injection_path)
        texts.extend(df["text"].tolist())
        labels.extend([1] * len(df))

    if benign_path.exists():
        df = pd.read_csv(benign_path)
        texts.extend(df["text"].tolist())
        labels.extend([0] * len(df))

    # Also try the combined dataset from HuggingFace download
    combined_path = DATA_DIR / "combined_dataset.csv"
    if combined_path.exists():
        df = pd.read_csv(combined_path)
        texts.extend(df["text"].tolist())
        labels.extend(df["label"].tolist())

    return texts, labels


def train():
    texts, labels = load_data()

    if len(texts) < 50:
        print(f"Only {len(texts)} samples found. Run data/download_data.py first.")
        print("Minimum 50 samples needed for training.")
        return

    print(f"Loaded {len(texts)} samples ({sum(labels)} injection, {len(labels) - sum(labels)} benign)")

    # TF-IDF with both character and word n-grams
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=10000,
        sublinear_tf=True,
    )

    X = vectorizer.fit_transform(texts)
    y = labels

    # Cross-validation
    model = LogisticRegression(max_iter=1000, C=1.0, class_weight="balanced")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="f1")
    print(f"\n5-fold CV F1 scores: {cv_scores}")
    print(f"Mean F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Train/test split for final evaluation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    print("\nClassification Report:")
    report = classification_report(y_test, y_pred, target_names=["benign", "injection"])
    print(report)

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    # Train final model on all data
    final_model = LogisticRegression(max_iter=1000, C=1.0, class_weight="balanced")
    final_model.fit(X, y)

    # Save artifacts
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, MODEL_DIR / "classifier.joblib")
    joblib.dump(vectorizer, MODEL_DIR / "vectorizer.joblib")

    # Save metrics
    report_dict = classification_report(y_test, y_pred, target_names=["benign", "injection"], output_dict=True)
    metrics = {
        "cv_f1_mean": round(cv_scores.mean(), 4),
        "cv_f1_std": round(cv_scores.std(), 4),
        "test_precision_injection": round(report_dict["injection"]["precision"], 4),
        "test_recall_injection": round(report_dict["injection"]["recall"], 4),
        "test_f1_injection": round(report_dict["injection"]["f1-score"], 4),
        "total_samples": len(texts),
        "test_samples": len(y_test),
    }
    with open(MODEL_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nModel saved to {MODEL_DIR / 'classifier.joblib'}")
    print(f"Vectorizer saved to {MODEL_DIR / 'vectorizer.joblib'}")
    print(f"Metrics saved to {MODEL_DIR / 'metrics.json'}")


if __name__ == "__main__":
    train()
