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

## Known limitations

1. **Small training set** — the model is trained on whichever CVEs the current query returns
   (typically 20–200). A production model would need thousands of labelled examples.

2. **Label leakage** — the `high_risk` label is derived from `risk_score`, which is itself
   computed from the same CVSS features that are the model's inputs. The model is essentially
   learning to approximate its own label function. This is intentional for the educational
   baseline, and means ML probabilities will closely track the rule-based score.

3. **Class imbalance** — depending on the keyword search, results may skew toward high-severity
   CVEs, leaving few low-risk examples. `LogisticRegression` uses `class_weight="balanced"` to
   mitigate this.

4. **Requires both classes** — training raises `ModelTrainingError` if all fetched CVEs share
   the same label. Adjust the threshold or fetch more diverse CVEs.

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
| `src/models/classifier.py` | This classifier |
| `src/models/risk_scorer.py` | Rule-based scorer that generates training labels |
| `src/features/feature_engineering.py` | Produces the normalized DataFrame used as model input |
| `docs/responsible_use.md` | Ethical use guidelines |
