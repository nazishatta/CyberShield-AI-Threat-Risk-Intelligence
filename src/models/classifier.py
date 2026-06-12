"""
Lightweight baseline ML classifier for CVE high-risk prioritisation.

Uses scikit-learn only — no XGBoost or other heavy ML dependencies required.
This is an educational baseline model. See docs/modeling.md for limitations.
"""

from __future__ import annotations

from typing import Literal

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.utils.config import load_config

# ── Constants ─────────────────────────────────────────────────────────────────

ML_FEATURE_COLS: tuple[str, ...] = (
    "severity_numeric",
    "base_score",
    "attack_vector_numeric",
    "age_days",
    "kev_numeric",
)

HIGH_RISK_THRESHOLD: float = 70.0  # risk_score >= this → high_risk = 1
MIN_TRAINING_SAMPLES: int = 10


# ── Exceptions ────────────────────────────────────────────────────────────────

class ModelTrainingError(Exception):
    """Raised when training cannot proceed (too few samples, single class, etc.)."""


# ── Internal helpers ──────────────────────────────────────────────────────────

def _model_cfg() -> dict:
    return load_config()["model"]


def _make_pipeline(model_type: str) -> Pipeline:
    rng = _model_cfg()["random_state"]
    if model_type == "random_forest":
        clf = RandomForestClassifier(
            n_estimators=50,
            max_depth=4,
            random_state=rng,
            class_weight="balanced",
        )
    else:  # "logistic" (default)
        clf = LogisticRegression(
            max_iter=1000,
            random_state=rng,
            class_weight="balanced",
        )
    return Pipeline([("scaler", StandardScaler()), ("clf", clf)])


# ── Public API ────────────────────────────────────────────────────────────────

def build_labels(df: pd.DataFrame, threshold: float = HIGH_RISK_THRESHOLD) -> pd.Series:
    """Binary high_risk label: 1 if risk_score >= threshold, else 0."""
    return (df["risk_score"] >= threshold).astype(int).rename("high_risk")


def train(
    df: pd.DataFrame,
    *,
    model_type: Literal["logistic", "random_forest"] = "logistic",
    threshold: float = HIGH_RISK_THRESHOLD,
) -> tuple[Pipeline, dict]:
    """Train a binary high_risk classifier on df.

    Parameters
    ----------
    df:
        Feature DataFrame from build_features(). Must contain ML_FEATURE_COLS
        and risk_score.
    model_type:
        ``"logistic"`` (default) or ``"random_forest"``.
    threshold:
        risk_score cutoff for the high_risk label.

    Returns
    -------
    tuple[Pipeline, dict]
        Trained sklearn Pipeline and a metrics dict with keys:
        ``accuracy``, ``precision``, ``recall``, ``f1``,
        ``n_train``, ``n_test``.

    Raises
    ------
    ModelTrainingError
        When training cannot proceed (< MIN_TRAINING_SAMPLES rows, or all
        samples share the same label).
    """
    if len(df) < MIN_TRAINING_SAMPLES:
        raise ModelTrainingError(
            f"Need at least {MIN_TRAINING_SAMPLES} samples to train; got {len(df)}. "
            "Fetch more CVEs and retry."
        )

    y = build_labels(df, threshold=threshold)
    n_classes = y.nunique()

    if n_classes < 2:
        label_name = "high_risk" if int(y.iloc[0]) == 1 else "not_high_risk"
        raise ModelTrainingError(
            f"All {len(df)} samples have the same label ({label_name}). "
            f"Adjust the threshold (currently {threshold}) or fetch more diverse CVEs."
        )

    X = df[list(ML_FEATURE_COLS)].fillna(0)
    cfg = _model_cfg()

    # Stratify only when every class has >= 2 samples (sklearn requirement)
    min_class_count = int(y.value_counts().min())
    use_stratify = min_class_count >= 2

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=cfg["test_size"],
        random_state=cfg["random_state"],
        stratify=y if use_stratify else None,
    )

    pipeline = _make_pipeline(model_type)
    pipeline.fit(X_train, y_train)

    metrics = evaluate(pipeline, X_test, y_test)
    metrics["n_train"] = len(X_train)
    metrics["n_test"] = len(X_test)

    return pipeline, metrics


def predict(pipeline: Pipeline, df: pd.DataFrame) -> pd.Series:
    """Return predicted high_risk probabilities (0.0–1.0) for each row in df."""
    X = df[list(ML_FEATURE_COLS)].fillna(0)
    proba = pipeline.predict_proba(X)[:, 1]
    return pd.Series(proba, index=df.index, name="high_risk_prob")


def evaluate(pipeline: Pipeline, X_test, y_test) -> dict:
    """Return accuracy, precision, recall, and f1 as a dict."""
    preds = pipeline.predict(X_test)
    return {
        "accuracy": round(float(accuracy_score(y_test, preds)), 4),
        "precision": round(float(precision_score(y_test, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, preds, zero_division=0)), 4),
    }
