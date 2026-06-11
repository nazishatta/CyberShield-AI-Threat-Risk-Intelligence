"""
Tests for src/models/evaluation.py.
All data is constructed in-process — no network calls.
"""

from __future__ import annotations

import pandas as pd
import pytest

from src.models.classifier import ML_FEATURE_COLS, build_labels, train
from src.models.evaluation import (
    class_balance,
    classification_report_dict,
    confusion_matrix_values,
    feature_importance_rf,
    is_accuracy_misleading,
    permutation_importance_df,
    recommend_threshold,
    threshold_sweep,
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


def _X(df: pd.DataFrame):
    return df[list(ML_FEATURE_COLS)].fillna(0)


def _y(df: pd.DataFrame):
    return build_labels(df)


# ── class_balance ─────────────────────────────────────────────────────────────

def test_class_balance_equal_classes():
    y = pd.Series([0] * 10 + [1] * 10)
    result = class_balance(y)
    assert result["n_high_risk"] == 10
    assert result["n_not_high_risk"] == 10
    assert result["frac_high_risk"] == 0.5


def test_class_balance_all_high_risk():
    y = pd.Series([1] * 20)
    result = class_balance(y)
    assert result["n_high_risk"] == 20
    assert result["n_not_high_risk"] == 0
    assert result["frac_high_risk"] == 1.0


def test_class_balance_all_low_risk():
    y = pd.Series([0] * 20)
    result = class_balance(y)
    assert result["n_high_risk"] == 0
    assert result["n_not_high_risk"] == 20
    assert result["frac_high_risk"] == 0.0


def test_class_balance_keys_present():
    y = pd.Series([0, 1, 0, 1])
    result = class_balance(y)
    assert set(result.keys()) == {"n_high_risk", "n_not_high_risk", "frac_high_risk"}


def test_class_balance_empty_series_returns_zero_frac():
    result = class_balance(pd.Series([], dtype=int))
    assert result["frac_high_risk"] == 0.0


def test_class_balance_minority_class():
    y = pd.Series([1] * 5 + [0] * 45)
    result = class_balance(y)
    assert result["n_high_risk"] == 5
    assert result["frac_high_risk"] == pytest.approx(0.1, abs=1e-4)


# ── confusion_matrix_values ───────────────────────────────────────────────────

def test_confusion_matrix_values_returns_all_keys():
    df = _make_df()
    pipeline, _ = train(df)
    cm = confusion_matrix_values(pipeline, _X(df), _y(df))
    assert set(cm.keys()) == {"tp", "fp", "fn", "tn"}


def test_confusion_matrix_values_are_nonnegative():
    df = _make_df()
    pipeline, _ = train(df)
    cm = confusion_matrix_values(pipeline, _X(df), _y(df))
    for key, val in cm.items():
        assert val >= 0, f"{key}={val} is negative"


def test_confusion_matrix_values_sum_to_dataset_size():
    df = _make_df(n_high=20, n_low=20)
    pipeline, _ = train(df)
    cm = confusion_matrix_values(pipeline, _X(df), _y(df))
    assert cm["tp"] + cm["fp"] + cm["fn"] + cm["tn"] == len(df)


def test_confusion_matrix_single_class_in_predictions_still_returns_four_keys():
    """labels=[0,1] guarantees a 2x2 matrix even with single-class predictions."""
    df = _make_df()
    pipeline, _ = train(df)
    # Evaluate on a subset containing only one true label
    low_only = df[df["risk_score"] < 70].head(5)
    cm = confusion_matrix_values(pipeline, _X(low_only), _y(low_only))
    assert set(cm.keys()) == {"tp", "fp", "fn", "tn"}


# ── classification_report_dict ────────────────────────────────────────────────

def test_classification_report_dict_has_expected_top_level_keys():
    df = _make_df()
    pipeline, _ = train(df)
    report = classification_report_dict(pipeline, _X(df), _y(df))
    for key in ("0", "1", "accuracy"):
        assert key in report, f"Missing key: {key!r}"


def test_classification_report_dict_per_class_keys():
    df = _make_df()
    pipeline, _ = train(df)
    report = classification_report_dict(pipeline, _X(df), _y(df))
    for cls in ("0", "1"):
        assert "precision" in report[cls]
        assert "recall" in report[cls]
        assert "f1-score" in report[cls]


def test_classification_report_dict_accuracy_in_range():
    df = _make_df()
    pipeline, _ = train(df)
    report = classification_report_dict(pipeline, _X(df), _y(df))
    assert 0.0 <= report["accuracy"] <= 1.0


# ── feature_importance_rf ─────────────────────────────────────────────────────

def test_feature_importance_rf_returns_dataframe():
    df = _make_df()
    pipeline, _ = train(df, model_type="random_forest")
    fi = feature_importance_rf(pipeline)
    assert isinstance(fi, pd.DataFrame)


def test_feature_importance_rf_columns():
    df = _make_df()
    pipeline, _ = train(df, model_type="random_forest")
    fi = feature_importance_rf(pipeline)
    assert list(fi.columns) == ["feature", "importance"]


def test_feature_importance_rf_row_count_equals_feature_count():
    df = _make_df()
    pipeline, _ = train(df, model_type="random_forest")
    fi = feature_importance_rf(pipeline)
    assert len(fi) == len(ML_FEATURE_COLS)


def test_feature_importance_rf_sorted_descending():
    df = _make_df()
    pipeline, _ = train(df, model_type="random_forest")
    fi = feature_importance_rf(pipeline)
    importances = fi["importance"].tolist()
    assert importances == sorted(importances, reverse=True)


def test_feature_importance_rf_importances_sum_to_one():
    df = _make_df()
    pipeline, _ = train(df, model_type="random_forest")
    fi = feature_importance_rf(pipeline)
    assert fi["importance"].sum() == pytest.approx(1.0, abs=1e-6)


def test_feature_importance_rf_raises_for_logistic_regression():
    df = _make_df()
    pipeline, _ = train(df, model_type="logistic")
    with pytest.raises(ValueError, match="RandomForestClassifier"):
        feature_importance_rf(pipeline)


def test_feature_importance_rf_features_are_ml_feature_cols():
    df = _make_df()
    pipeline, _ = train(df, model_type="random_forest")
    fi = feature_importance_rf(pipeline)
    assert set(fi["feature"]) == set(ML_FEATURE_COLS)


# ── permutation_importance_df ─────────────────────────────────────────────────

def test_permutation_importance_df_returns_dataframe():
    df = _make_df()
    pipeline, _ = train(df)
    pi = permutation_importance_df(pipeline, _X(df), _y(df), n_repeats=3)
    assert isinstance(pi, pd.DataFrame)


def test_permutation_importance_df_has_correct_columns():
    df = _make_df()
    pipeline, _ = train(df)
    pi = permutation_importance_df(pipeline, _X(df), _y(df), n_repeats=3)
    assert list(pi.columns) == ["feature", "mean_importance", "std_importance"]


def test_permutation_importance_df_row_count_equals_feature_count():
    df = _make_df()
    pipeline, _ = train(df)
    pi = permutation_importance_df(pipeline, _X(df), _y(df), n_repeats=3)
    assert len(pi) == len(ML_FEATURE_COLS)


def test_permutation_importance_df_features_are_ml_feature_cols():
    df = _make_df()
    pipeline, _ = train(df)
    pi = permutation_importance_df(pipeline, _X(df), _y(df), n_repeats=3)
    assert set(pi["feature"]) == set(ML_FEATURE_COLS)


def test_permutation_importance_df_sorted_descending():
    df = _make_df()
    pipeline, _ = train(df)
    pi = permutation_importance_df(pipeline, _X(df), _y(df), n_repeats=3)
    means = pi["mean_importance"].tolist()
    assert means == sorted(means, reverse=True)


def test_permutation_importance_df_works_for_random_forest():
    df = _make_df()
    pipeline, _ = train(df, model_type="random_forest")
    pi = permutation_importance_df(pipeline, _X(df), _y(df), n_repeats=3)
    assert len(pi) == len(ML_FEATURE_COLS)


# ── is_accuracy_misleading ────────────────────────────────────────────────────

def test_is_accuracy_misleading_true_for_imbalanced_with_poor_f1():
    metrics = {"accuracy": 0.90, "precision": 0.0, "recall": 0.0, "f1": 0.0}
    balance = {"n_high_risk": 5, "n_not_high_risk": 45, "frac_high_risk": 0.10}
    assert is_accuracy_misleading(metrics, balance) is True


def test_is_accuracy_misleading_false_for_balanced_data():
    metrics = {"accuracy": 0.90, "precision": 0.90, "recall": 0.90, "f1": 0.90}
    balance = {"n_high_risk": 25, "n_not_high_risk": 25, "frac_high_risk": 0.50}
    assert is_accuracy_misleading(metrics, balance) is False


def test_is_accuracy_misleading_false_when_f1_close_to_accuracy():
    # Imbalanced data but F1 is close to accuracy → no inflation
    metrics = {"accuracy": 0.88, "precision": 0.80, "recall": 0.80, "f1": 0.80}
    balance = {"n_high_risk": 5, "n_not_high_risk": 45, "frac_high_risk": 0.10}
    assert is_accuracy_misleading(metrics, balance) is False


def test_is_accuracy_misleading_true_for_high_majority_class():
    # > 80 % high_risk is also imbalanced
    metrics = {"accuracy": 0.85, "precision": 0.0, "recall": 0.0, "f1": 0.0}
    balance = {"n_high_risk": 45, "n_not_high_risk": 5, "frac_high_risk": 0.90}
    assert is_accuracy_misleading(metrics, balance) is True


def test_is_accuracy_misleading_false_when_f1_matches_accuracy():
    metrics = {"accuracy": 0.85, "f1": 0.85}
    balance = {"frac_high_risk": 0.10}
    assert is_accuracy_misleading(metrics, balance) is False


def test_is_accuracy_misleading_false_for_moderate_imbalance():
    # 25% minority is above the 20% threshold — not flagged as imbalanced
    metrics = {"accuracy": 0.95, "f1": 0.0}
    balance = {"frac_high_risk": 0.25}
    assert is_accuracy_misleading(metrics, balance) is False


# ── confusion_matrix_values with threshold parameter ─────────────────────────

def test_confusion_matrix_values_threshold_high_reduces_positives():
    """A very high threshold should produce fewer predicted positives (more TN)."""
    df = _make_df(n_high=20, n_low=20)
    pipeline, _ = train(df)
    cm_low = confusion_matrix_values(pipeline, _X(df), _y(df), threshold=0.1)
    cm_high = confusion_matrix_values(pipeline, _X(df), _y(df), threshold=0.9)
    positives_low = cm_low["tp"] + cm_low["fp"]
    positives_high = cm_high["tp"] + cm_high["fp"]
    assert positives_low >= positives_high


def test_confusion_matrix_values_sum_unchanged_across_thresholds():
    """tp+fp+fn+tn must equal dataset size regardless of threshold."""
    df = _make_df()
    pipeline, _ = train(df)
    for thresh in (0.2, 0.5, 0.8):
        cm = confusion_matrix_values(pipeline, _X(df), _y(df), threshold=thresh)
        assert cm["tp"] + cm["fp"] + cm["fn"] + cm["tn"] == len(df)


# ── threshold_sweep ───────────────────────────────────────────────────────────

def test_threshold_sweep_returns_dataframe():
    df = _make_df()
    pipeline, _ = train(df)
    result = threshold_sweep(pipeline, _X(df), _y(df))
    assert isinstance(result, pd.DataFrame)


def test_threshold_sweep_default_row_count():
    df = _make_df()
    pipeline, _ = train(df)
    result = threshold_sweep(pipeline, _X(df), _y(df))
    assert len(result) == 9  # 0.10 through 0.90


def test_threshold_sweep_columns():
    df = _make_df()
    pipeline, _ = train(df)
    result = threshold_sweep(pipeline, _X(df), _y(df))
    assert list(result.columns) == [
        "threshold", "precision", "recall", "f1", "predicted_positive_count"
    ]


def test_threshold_sweep_threshold_values_match_defaults():
    df = _make_df()
    pipeline, _ = train(df)
    result = threshold_sweep(pipeline, _X(df), _y(df))
    expected = [round(t, 2) for t in (0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90)]
    assert list(result["threshold"]) == expected


def test_threshold_sweep_precision_in_unit_interval():
    df = _make_df()
    pipeline, _ = train(df)
    result = threshold_sweep(pipeline, _X(df), _y(df))
    assert (result["precision"] >= 0.0).all()
    assert (result["precision"] <= 1.0).all()


def test_threshold_sweep_recall_in_unit_interval():
    df = _make_df()
    pipeline, _ = train(df)
    result = threshold_sweep(pipeline, _X(df), _y(df))
    assert (result["recall"] >= 0.0).all()
    assert (result["recall"] <= 1.0).all()


def test_threshold_sweep_f1_in_unit_interval():
    df = _make_df()
    pipeline, _ = train(df)
    result = threshold_sweep(pipeline, _X(df), _y(df))
    assert (result["f1"] >= 0.0).all()
    assert (result["f1"] <= 1.0).all()


def test_threshold_sweep_predicted_positive_count_nonnegative():
    df = _make_df()
    pipeline, _ = train(df)
    result = threshold_sweep(pipeline, _X(df), _y(df))
    assert (result["predicted_positive_count"] >= 0).all()


def test_threshold_sweep_high_threshold_fewer_or_equal_positives():
    """Increasing the threshold must not increase the predicted positive count."""
    df = _make_df(n_high=20, n_low=20)
    pipeline, _ = train(df)
    result = threshold_sweep(pipeline, _X(df), _y(df))
    counts = result["predicted_positive_count"].tolist()
    # Counts must be weakly decreasing as threshold increases
    assert all(counts[i] >= counts[i + 1] for i in range(len(counts) - 1))


def test_threshold_sweep_custom_thresholds():
    df = _make_df()
    pipeline, _ = train(df)
    custom = (0.25, 0.75)
    result = threshold_sweep(pipeline, _X(df), _y(df), thresholds=custom)
    assert len(result) == 2
    assert list(result["threshold"]) == [0.25, 0.75]


def test_threshold_sweep_works_for_random_forest():
    df = _make_df()
    pipeline, _ = train(df, model_type="random_forest")
    result = threshold_sweep(pipeline, _X(df), _y(df))
    assert len(result) == 9


# ── recommend_threshold ───────────────────────────────────────────────────────

def test_recommend_threshold_returns_float():
    df = _make_df()
    pipeline, _ = train(df)
    sweep = threshold_sweep(pipeline, _X(df), _y(df))
    assert isinstance(recommend_threshold(sweep), float)


def test_recommend_threshold_is_in_sweep_thresholds():
    df = _make_df()
    pipeline, _ = train(df)
    sweep = threshold_sweep(pipeline, _X(df), _y(df))
    rec = recommend_threshold(sweep)
    assert rec in sweep["threshold"].tolist()


def test_recommend_threshold_maximises_f1():
    sweep = pd.DataFrame({
        "threshold": [0.3, 0.5, 0.7],
        "precision": [0.50, 0.70, 0.90],
        "recall": [0.90, 0.70, 0.40],
        "f1": [0.64, 0.70, 0.57],
        "predicted_positive_count": [20, 15, 8],
    })
    assert recommend_threshold(sweep) == 0.5


def test_recommend_threshold_prefer_recall_maximises_recall():
    sweep = pd.DataFrame({
        "threshold": [0.3, 0.5, 0.7],
        "precision": [0.50, 0.70, 0.90],
        "recall": [0.90, 0.70, 0.40],
        "f1": [0.64, 0.70, 0.57],
        "predicted_positive_count": [20, 15, 8],
    })
    assert recommend_threshold(sweep, prefer_recall=True) == 0.3


def test_recommend_threshold_empty_df_returns_default():
    empty = pd.DataFrame(columns=["threshold", "precision", "recall", "f1", "predicted_positive_count"])
    assert recommend_threshold(empty) == 0.5


def test_recommend_threshold_f1_tie_broken_by_lower_threshold():
    sweep = pd.DataFrame({
        "threshold": [0.3, 0.5, 0.7],
        "precision": [0.60, 0.80, 0.90],
        "recall": [0.85, 0.65, 0.50],
        "f1": [0.70, 0.70, 0.65],
        "predicted_positive_count": [18, 12, 8],
    })
    # Both 0.3 and 0.5 have f1=0.70; lower threshold wins
    assert recommend_threshold(sweep) == 0.3


def test_recommend_threshold_recall_tie_broken_by_higher_f1():
    sweep = pd.DataFrame({
        "threshold": [0.2, 0.4],
        "precision": [0.40, 0.60],
        "recall": [0.90, 0.90],
        "f1": [0.55, 0.72],
        "predicted_positive_count": [25, 18],
    })
    # Both have recall=0.90; higher f1 wins → 0.4
    assert recommend_threshold(sweep, prefer_recall=True) == 0.4
