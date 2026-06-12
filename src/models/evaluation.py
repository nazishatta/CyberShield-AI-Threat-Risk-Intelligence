"""
Model evaluation and explainability utilities for the CVE risk classifier.

All functions are pure (no side effects, no disk writes).
They accept an already-trained sklearn Pipeline plus pre-split X / y arrays,
so they work equally well on train-split holdout data or the full dataset.
"""

from __future__ import annotations

import pandas as pd
from sklearn.inspection import permutation_importance as _sk_perm_importance
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline

from src.models.classifier import ML_FEATURE_COLS

# Default probability thresholds evaluated by threshold_sweep
_DEFAULT_THRESHOLDS: tuple[float, ...] = (
    0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90
)


def class_balance(y: pd.Series) -> dict:
    """Summarise the binary label distribution.

    Parameters
    ----------
    y:
        Series of integer labels (0 = not high risk, 1 = high risk).

    Returns
    -------
    dict with keys: n_high_risk, n_not_high_risk, frac_high_risk.
    """
    n_total = len(y)
    n_high = int((y == 1).sum())
    n_low = n_total - n_high
    frac = n_high / n_total if n_total > 0 else 0.0
    return {
        "n_high_risk": n_high,
        "n_not_high_risk": n_low,
        "frac_high_risk": round(frac, 4),
    }


def confusion_matrix_values(
    pipeline: Pipeline, X_test, y_test, *, threshold: float = 0.5
) -> dict:
    """Return TP, FP, FN, TN counts using the given probability threshold.

    ``labels=[0, 1]`` is passed to sklearn so the matrix is always 2×2,
    even when only one class appears in the test set.

    Parameters
    ----------
    pipeline:
        A fitted sklearn Pipeline with a ``predict_proba`` method.
    X_test:
        Feature DataFrame / array.
    y_test:
        True binary labels.
    threshold:
        Probability cutoff for predicting high_risk=1.  Default 0.5 matches
        sklearn's default ``predict()`` behaviour.

    Returns
    -------
    dict with keys: tp, fp, fn, tn (all ints).
    """
    probas = pipeline.predict_proba(X_test)[:, 1]
    preds = (probas >= threshold).astype(int)
    cm = confusion_matrix(y_test, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def classification_report_dict(pipeline: Pipeline, X_test, y_test) -> dict:
    """Return sklearn classification_report as a nested dict.

    The dict includes per-class precision/recall/F1 plus 'accuracy',
    'macro avg', and 'weighted avg' keys.
    """
    preds = pipeline.predict(X_test)
    return classification_report(y_test, preds, zero_division=0, output_dict=True)


def feature_importance_rf(pipeline: Pipeline) -> pd.DataFrame:
    """Extract RandomForest feature importances from a trained Pipeline.

    Returns
    -------
    pd.DataFrame with columns: feature, importance — sorted descending.

    Raises
    ------
    ValueError
        If the pipeline's 'clf' step does not have ``feature_importances_``
        (i.e. it is not a tree-based model).  Use permutation_importance_df
        for LogisticRegression and other model types.
    """
    clf = pipeline.named_steps.get("clf")
    if clf is None or not hasattr(clf, "feature_importances_"):
        raise ValueError(
            "feature_importance_rf requires a tree-based model (e.g. "
            "RandomForestClassifier) in the pipeline's 'clf' step.  "
            "Use permutation_importance_df for LogisticRegression."
        )
    importances = clf.feature_importances_
    return (
        pd.DataFrame({"feature": list(ML_FEATURE_COLS), "importance": importances})
        .sort_values("importance", ascending=False)
        .reset_index(drop=True)
    )


def permutation_importance_df(
    pipeline: Pipeline,
    X_test,
    y_test,
    *,
    n_repeats: int = 5,
    random_state: int = 42,
) -> pd.DataFrame:
    """Compute permutation importance for any sklearn Pipeline.

    Permutation importance measures each feature's contribution by shuffling
    it one at a time and observing the drop in accuracy.  Works for both
    LogisticRegression and RandomForest.

    Parameters
    ----------
    pipeline:
        A fitted sklearn Pipeline.
    X_test:
        Feature array / DataFrame with ML_FEATURE_COLS columns.
    y_test:
        True binary labels.
    n_repeats:
        Number of times each feature is shuffled (default 5).
    random_state:
        Seed for reproducibility (default 42).

    Returns
    -------
    pd.DataFrame with columns: feature, mean_importance, std_importance
        Sorted by mean_importance descending.
    """
    result = _sk_perm_importance(
        pipeline,
        X_test,
        y_test,
        n_repeats=n_repeats,
        random_state=random_state,
        scoring="accuracy",
    )
    df = pd.DataFrame({
        "feature": list(ML_FEATURE_COLS),
        "mean_importance": result.importances_mean,
        "std_importance": result.importances_std,
    })
    return df.sort_values("mean_importance", ascending=False).reset_index(drop=True)


def is_accuracy_misleading(metrics: dict, balance: dict) -> bool:
    """Return True when high accuracy is likely masking poor minority-class performance.

    Fires when both conditions hold:
    - The minority class is < 20 % or > 80 % of the data (strong imbalance), AND
    - accuracy exceeds F1 by more than 0.15 points (accuracy inflated by majority class).
    """
    frac = balance.get("frac_high_risk", 0.5)
    imbalanced = frac < 0.20 or frac > 0.80
    inflated = (metrics.get("accuracy", 0.0) - metrics.get("f1", 0.0)) > 0.15
    return imbalanced and inflated


def threshold_sweep(
    pipeline: Pipeline,
    X_test,
    y_test,
    *,
    thresholds: tuple[float, ...] = _DEFAULT_THRESHOLDS,
) -> pd.DataFrame:
    """Evaluate precision, recall, F1, and predicted-positive count at each threshold.

    Varying the decision threshold trades off Precision against Recall.
    Defensive security teams often prefer a lower threshold to maximise
    Recall (catching more high-risk CVEs) even at the cost of more false alarms.

    Parameters
    ----------
    pipeline:
        A fitted sklearn Pipeline with ``predict_proba``.
    X_test:
        Feature DataFrame / array.
    y_test:
        True binary labels.
    thresholds:
        Iterable of probability cutoffs to evaluate.
        Default: 0.10, 0.20, …, 0.90.

    Returns
    -------
    pd.DataFrame with columns:
        threshold, precision, recall, f1, predicted_positive_count.
    """
    probas = pipeline.predict_proba(X_test)[:, 1]
    rows = []
    for thresh in thresholds:
        preds = (probas >= thresh).astype(int)
        rows.append({
            "threshold": round(float(thresh), 2),
            "precision": round(float(precision_score(y_test, preds, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, preds, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, preds, zero_division=0)), 4),
            "predicted_positive_count": int(preds.sum()),
        })
    return pd.DataFrame(rows)


def recommend_threshold(
    sweep_df: pd.DataFrame,
    *,
    prefer_recall: bool = False,
) -> float:
    """Recommend a decision threshold from a threshold_sweep DataFrame.

    Parameters
    ----------
    sweep_df:
        DataFrame returned by ``threshold_sweep()``.
    prefer_recall:
        If True, return the threshold that maximises Recall (best for defensive
        security teams that want to catch every high-risk CVE, accepting more
        false positives).  If False (default), return the threshold that
        maximises F1 (balanced precision / recall).
        Ties are broken by highest F1 then lowest threshold.

    Returns
    -------
    float: Recommended threshold.  Falls back to 0.5 when sweep_df is empty.
    """
    if sweep_df.empty:
        return 0.5

    if prefer_recall:
        best_idx = (
            sweep_df
            .sort_values(["recall", "f1", "threshold"], ascending=[False, False, True])
            .index[0]
        )
    else:
        best_idx = (
            sweep_df
            .sort_values(["f1", "threshold"], ascending=[False, True])
            .index[0]
        )

    return float(sweep_df.loc[best_idx, "threshold"])
