"""
Tests for src/models/classifier.py.
All data is constructed in-process — no network calls.
"""

from __future__ import annotations

import pandas as pd
import pytest

from src.models.classifier import (
    HIGH_RISK_THRESHOLD,
    ML_FEATURE_COLS,
    MIN_TRAINING_SAMPLES,
    ModelTrainingError,
    build_labels,
    evaluate,
    predict,
    train,
)


# ── Synthetic data helpers ────────────────────────────────────────────────────

def _make_df(n_high: int = 15, n_low: int = 15) -> pd.DataFrame:
    """Synthetic DataFrame with two clearly separable classes."""
    high_rows = [
        {
            "cve_id": f"CVE-2024-H{i:04d}",
            "severity_numeric": 4,
            "base_score": 9.5,
            "attack_vector_numeric": 4,
            "age_days": 500,
            "kev_numeric": 1,
            "risk_score": 95.0,
        }
        for i in range(n_high)
    ]
    low_rows = [
        {
            "cve_id": f"CVE-2023-L{i:04d}",
            "severity_numeric": 1,
            "base_score": 2.0,
            "attack_vector_numeric": 1,
            "age_days": 100,
            "kev_numeric": 0,
            "risk_score": 8.0,
        }
        for i in range(n_low)
    ]
    return pd.DataFrame(high_rows + low_rows)


def _make_single_class_df(n: int = 15) -> pd.DataFrame:
    """Synthetic DataFrame where all risk_scores fall below the threshold."""
    return pd.DataFrame([
        {
            "cve_id": f"CVE-2023-L{i:04d}",
            "severity_numeric": 1,
            "base_score": 2.0,
            "attack_vector_numeric": 1,
            "age_days": 100,
            "kev_numeric": 0,
            "risk_score": 8.0,
        }
        for i in range(n)
    ])


# ── build_labels ──────────────────────────────────────────────────────────────

def test_build_labels_at_threshold_is_high_risk():
    df = pd.DataFrame([{"risk_score": 70.0}])
    assert build_labels(df).iloc[0] == 1


def test_build_labels_just_below_threshold_is_low_risk():
    df = pd.DataFrame([{"risk_score": 69.9}])
    assert build_labels(df).iloc[0] == 0


def test_build_labels_well_above_threshold():
    df = pd.DataFrame([{"risk_score": 95.0}])
    assert build_labels(df).iloc[0] == 1


def test_build_labels_well_below_threshold():
    df = pd.DataFrame([{"risk_score": 8.0}])
    assert build_labels(df).iloc[0] == 0


def test_build_labels_custom_threshold_above():
    df = pd.DataFrame([{"risk_score": 50.0}])
    assert build_labels(df, threshold=40.0).iloc[0] == 1


def test_build_labels_custom_threshold_below():
    df = pd.DataFrame([{"risk_score": 50.0}])
    assert build_labels(df, threshold=60.0).iloc[0] == 0


def test_build_labels_series_name():
    df = pd.DataFrame([{"risk_score": 80.0}])
    assert build_labels(df).name == "high_risk"


# ── ML_FEATURE_COLS ───────────────────────────────────────────────────────────

def test_ml_feature_cols_contains_expected_columns():
    expected = {
        "severity_numeric",
        "base_score",
        "attack_vector_numeric",
        "age_days",
        "kev_numeric",
    }
    assert set(ML_FEATURE_COLS) == expected


def test_ml_feature_cols_is_tuple():
    assert isinstance(ML_FEATURE_COLS, tuple)


# ── train ─────────────────────────────────────────────────────────────────────

def test_train_returns_pipeline_and_metrics():
    pipeline, metrics = train(_make_df())
    assert pipeline is not None
    assert isinstance(metrics, dict)


def test_train_metrics_has_required_keys():
    _, metrics = train(_make_df())
    for key in ("accuracy", "precision", "recall", "f1", "n_train", "n_test"):
        assert key in metrics, f"Missing metric key: {key}"


def test_train_metrics_are_in_valid_range():
    _, metrics = train(_make_df())
    for key in ("accuracy", "precision", "recall", "f1"):
        assert 0.0 <= metrics[key] <= 1.0, f"{key}={metrics[key]} out of [0, 1]"


def test_train_n_samples_sum_equals_total():
    df = _make_df(n_high=15, n_low=15)
    _, metrics = train(df)
    assert metrics["n_train"] + metrics["n_test"] == len(df)


def test_train_logistic_regression_default():
    pipeline, _ = train(_make_df())
    clf = pipeline.named_steps["clf"]
    assert "LogisticRegression" in type(clf).__name__


def test_train_random_forest_model_type():
    pipeline, _ = train(_make_df(), model_type="random_forest")
    clf = pipeline.named_steps["clf"]
    assert "RandomForest" in type(clf).__name__


def test_train_pipeline_has_scaler_step():
    pipeline, _ = train(_make_df())
    assert "scaler" in pipeline.named_steps


def test_train_raises_on_insufficient_data():
    tiny_df = _make_df(n_high=2, n_low=2)  # 4 rows < MIN_TRAINING_SAMPLES
    with pytest.raises(ModelTrainingError, match="at least"):
        train(tiny_df)


def test_train_error_message_mentions_min_sample_count():
    tiny_df = _make_df(n_high=1, n_low=1)
    with pytest.raises(ModelTrainingError) as exc_info:
        train(tiny_df)
    assert str(MIN_TRAINING_SAMPLES) in str(exc_info.value)


def test_train_raises_on_single_class():
    with pytest.raises(ModelTrainingError, match="same label"):
        train(_make_single_class_df(n=15))


def test_train_single_class_error_mentions_threshold():
    with pytest.raises(ModelTrainingError) as exc_info:
        train(_make_single_class_df(n=15))
    assert str(HIGH_RISK_THRESHOLD) in str(exc_info.value)


# ── predict ───────────────────────────────────────────────────────────────────

def test_predict_returns_series_with_correct_length():
    df = _make_df()
    pipeline, _ = train(df)
    probs = predict(pipeline, df)
    assert len(probs) == len(df)


def test_predict_probabilities_in_zero_one_range():
    df = _make_df()
    pipeline, _ = train(df)
    probs = predict(pipeline, df)
    assert (probs >= 0.0).all()
    assert (probs <= 1.0).all()


def test_predict_high_risk_rows_score_higher_than_low_risk():
    df = _make_df(n_high=20, n_low=20)
    pipeline, _ = train(df)
    probs = predict(pipeline, df)
    df_copy = df.copy()
    df_copy["prob"] = probs.values
    avg_high = df_copy[df_copy["risk_score"] >= HIGH_RISK_THRESHOLD]["prob"].mean()
    avg_low = df_copy[df_copy["risk_score"] < HIGH_RISK_THRESHOLD]["prob"].mean()
    assert avg_high > avg_low


def test_predict_series_name():
    df = _make_df()
    pipeline, _ = train(df)
    assert predict(pipeline, df).name == "high_risk_prob"


def test_predict_preserves_dataframe_index():
    df = _make_df().set_index("cve_id")
    pipeline, _ = train(df.reset_index())  # train on plain int index
    pipeline2, _ = train(_make_df())
    probs = predict(pipeline2, _make_df())
    assert list(probs.index) == list(_make_df().index)


# ── evaluate ──────────────────────────────────────────────────────────────────

def test_evaluate_returns_correct_keys():
    df = _make_df()
    pipeline, _ = train(df)
    X_test = df[list(ML_FEATURE_COLS)]
    y_test = build_labels(df)
    metrics = evaluate(pipeline, X_test, y_test)
    assert set(metrics.keys()) == {"accuracy", "precision", "recall", "f1"}


def test_evaluate_metrics_in_valid_range():
    df = _make_df()
    pipeline, _ = train(df)
    X_test = df[list(ML_FEATURE_COLS)]
    y_test = build_labels(df)
    metrics = evaluate(pipeline, X_test, y_test)
    for key, val in metrics.items():
        assert 0.0 <= val <= 1.0, f"{key}={val} out of [0, 1]"


# ── class_weight="balanced" ───────────────────────────────────────────────────

def test_logistic_regression_has_balanced_class_weight():
    pipeline, _ = train(_make_df(), model_type="logistic")
    clf = pipeline.named_steps["clf"]
    assert clf.class_weight == "balanced"


def test_random_forest_has_balanced_class_weight():
    pipeline, _ = train(_make_df(), model_type="random_forest")
    clf = pipeline.named_steps["clf"]
    assert clf.class_weight == "balanced"
