# ML Modeling — Baseline CVE Risk Classifier

## Purpose

The classifier in `src/models/classifier.py` is a **lightweight, educational baseline model**
that predicts whether a CVE should be treated as "high risk" based on its normalized features.

It demonstrates an end-to-end ML pipeline — raw API data → feature engineering → binary
classification — within the CyberShield AI architecture, without requiring any dataset downloads
or heavy ML frameworks.

---

## What it is NOT

- **Not a production exploit predictor** — the model cannot tell you whether a CVE is being
  actively exploited right now in your environment.
- **Not a replacement for CISA KEV** — the KEV catalogue is the authoritative source for
  confirmed in-the-wild exploitation.
- **Not a vulnerability scanner** — the model makes no claim about your patch status or
  exposure.

Use this model only as one signal among many in a broader vulnerability prioritisation process.

---

## Target label

`high_risk` = **1** when `risk_score >= 70`, else **0**.

The rule-based `risk_score` (from `src/models/risk_scorer.py`) combines CVSS base score,
severity, attack vector, and CISA KEV membership into a 0–100 composite.
The 70-point threshold captures CVEs with strong criticality signals (CRITICAL/HIGH
NETWORK-reachable, or known-exploited); it does not guarantee exploitability.

---

## Input features

| Feature | Source | Range | Notes |
|---|---|---|---|
| `severity_numeric` | NVD CVSS | 0–4 | CRITICAL=4 HIGH=3 MEDIUM=2 LOW=1 UNKNOWN=0 |
| `base_score` | NVD CVSS | 0.0–10.0 | Median-filled when absent |
| `attack_vector_numeric` | NVD CVSS | 0–4 | NETWORK=4 ADJACENT=3 LOCAL=2 PHYSICAL=1 UNKNOWN=0 |
| `age_days` | Derived | ≥0 or −1 | Days since `published`; −1 for missing/malformed dates |
| `kev_numeric` | CISA KEV | 0 or 1 | 1 if the CVE is in the CISA KEV catalogue |

---

## Models available

| `model_type` | Algorithm | When to prefer |
|---|---|---|
| `"logistic"` (default) | Logistic Regression with balanced class weights | Simple, interpretable, fast; good default for small datasets |
| `"random_forest"` | Random Forest (50 trees, max depth 4) | Better with non-linear interactions; less sensitive to feature scale |

Both are wrapped in a `StandardScaler → classifier` sklearn `Pipeline`.

---

## Evaluation metrics

| Metric | What it measures |
|---|---|
| Accuracy | Fraction of all predictions that are correct |
| Precision | Of all predicted high_risk=1, how many actually are |
| Recall | Of all true high_risk=1, how many were caught |
| F1 | Harmonic mean of precision and recall |

The train/test split is 80/20 (configurable via `config.yaml → model.test_size`).
Stratified splitting is used when both classes have ≥ 2 samples.

---

## Threshold tuning

By default, a trained classifier predicts `high_risk=1` whenever the estimated probability
exceeds **0.50**.  This is rarely the optimal decision boundary in practice.

### Why the default threshold is often wrong

With imbalanced CVE result sets (e.g. mostly high-severity results from a narrow keyword),
the 0.50 boundary may produce:
- **High accuracy** — most predictions are correct because the majority class dominates
- **Poor recall** — many true high-risk CVEs are scored just below 0.50 and silently missed

### Threshold sweep

`threshold_sweep(pipeline, X, y)` evaluates Precision, Recall, and F1 at nine thresholds
from 0.10 to 0.90.  The result is a DataFrame showing the Precision–Recall tradeoff:

| Threshold | Precision | Recall | F1 | Predicted Positive |
|---|---|---|---|---|
| 0.10 | low | high | moderate | many |
| 0.50 | moderate | moderate | moderate | moderate |
| 0.90 | high | low | moderate | few |

### Recommended threshold

`recommend_threshold(sweep_df)` returns the threshold with the highest F1.
`recommend_threshold(sweep_df, prefer_recall=True)` returns the threshold with the highest
Recall — preferred for **defensive vulnerability prioritisation**, where missing a truly
exploitable CVE is more costly than investigating a false alarm.

### Why Recall matters in defensive security

| Error type | Consequence |
|---|---|
| False Positive (alert on safe CVE) | Wasted analyst time — recoverable |
| False Negative (miss a dangerous CVE) | Unpatched exposure — may be unrecoverable |

For most security teams, **False Negatives are more dangerous than False Positives**.
A lower decision threshold (e.g. 0.30 instead of 0.50) increases Recall at the cost of
more False Positives — this is usually the right trade-off for triage workflows.

---

## Why accuracy can be misleading

With class-imbalanced datasets, accuracy is often a poor guide to model quality.

**Example:** if 90 % of fetched CVEs are low-risk, a model that predicts "not high risk" for
every CVE achieves 90 % accuracy while being completely useless for finding exploitable issues
(Precision = 0, Recall = 0, F1 = 0).

**What to look at instead:**

| Situation | Preferred metric |
|---|---|
| You care most about catching all high-risk CVEs | **Recall** (minimise false negatives) |
| You care most about precision of alerts | **Precision** (minimise false positives) |
| You want a single balanced number | **F1** (harmonic mean of Precision & Recall) |

The dashboard automatically flags when accuracy exceeds F1 by more than 15 percentage points
AND the minority class is under 20 % of the dataset.

---

## Class imbalance warning

Real NVD query results are often skewed: a keyword like "critical remote code execution" will
return mostly high-severity CVEs (all labelled high_risk=1), while a broad keyword returns
mostly medium-severity CVEs (all labelled high_risk=0).

When strong imbalance is detected (< 20 % or > 80 % for one class), the dashboard shows a
warning. Mitigations:

- **LogisticRegression uses `class_weight="balanced"`** — it internally up-weights the minority
  class during training, which improves Recall at a small cost to Precision.
- **Fetch more diverse CVEs** — use a broader keyword or remove the date filter to capture
  both high and low severity CVEs.
- **Adjust the threshold** — raising the `high_risk` threshold (currently 70) labels fewer CVEs
  as high risk, which can help when the result set is CVSS-heavy.

---

## Responsible interpretation of ML metrics

1. **Confusion matrix over accuracy** — always check TP / FP / FN / TN counts, not just the
   accuracy headline. A high FN count (missed high-risk CVEs) is more dangerous than a high FP
   count (false alarms) in a security context.

2. **Model confidence ≠ ground truth** — the `high_risk_prob` shown in the dashboard is a
   probability estimate from a model trained on the same CVSS features that compose the
   rule-based label. It is not an independent signal.

3. **Small-sample instability** — metrics computed on fewer than ~30 test samples can vary
   significantly between runs just due to the random train/test split. Re-fetch with more CVEs
   for more stable estimates.

4. **KEV is authoritative** — a CISA KEV-listed CVE is confirmed exploited regardless of what
   the model scores. Always check the `In KEV` column first.

---

## Feature importance and explainability

`src/models/evaluation.py` provides two complementary importance measures:

| Function | Works for | How it works |
|---|---|---|
| `feature_importance_rf(pipeline)` | RandomForest only | Uses built-in `feature_importances_` (Gini impurity decrease) |
| `permutation_importance_df(pipeline, X, y)` | Any model | Shuffles each feature and measures accuracy drop |

**Limitations of feature importance:**

- **Correlated features** — `severity_numeric` and `base_score` are correlated (higher severity
  usually means higher score). Permutation importance may spread their shared credit between
  them, understating both.
- **Label leakage** — because `high_risk` is derived from the same CVSS features, importance
  scores reflect which features the risk-score formula weighs most heavily, not independent
  predictors of real-world exploitation.
- **Dataset size** — with < 50 samples, permutation importance standard deviations are large;
  treat rankings as approximate.

---

## Configuration

All hyperparameters are in `config.yaml` under the `model:` key:

```yaml
model:
  random_state: 42
  test_size: 0.2
  cv_folds: 5
```

---

## Related files

| File | Role |
|---|---|
| `src/models/classifier.py` | Classifier: train, predict, build_labels — LogisticRegression / RandomForest, both with class_weight="balanced" |
| `src/models/evaluation.py` | Evaluation: confusion matrix, class balance, threshold sweep, recommended threshold, feature importance |
| `src/models/risk_scorer.py` | Rule-based scorer that generates training labels |
| `src/features/feature_engineering.py` | Produces the normalized DataFrame used as model input |
| `docs/responsible_use.md` | Ethical use guidelines |
