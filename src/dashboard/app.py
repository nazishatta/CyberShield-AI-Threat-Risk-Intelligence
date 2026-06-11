"""
CyberShield AI — Streamlit dashboard entry point.
"""

from datetime import date, timedelta

import pandas as pd
import streamlit as st

from src.features.cve_parser import parse_cve
from src.features.feature_engineering import build_features
from src.ingestion.kev_client import CISAKEVError, get_kev_cve_ids
from src.ingestion.nvd_client import NVDAPIError, NVDRateLimitError, iter_cves
from src.models.classifier import (
    ML_FEATURE_COLS,
    MIN_TRAINING_SAMPLES,
    ModelTrainingError,
    build_labels,
    predict,
    train,
)
from src.models.evaluation import (
    class_balance,
    confusion_matrix_values,
    is_accuracy_misleading,
    permutation_importance_df,
    recommend_threshold,
    threshold_sweep,
)
from src.utils.config import load_config
from src.utils.logger import setup_logger

setup_logger()
load_config()  # warm the lru_cache at startup

st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CyberShield AI — Threat & Risk Intelligence")
st.caption("API-first · No local dataset downloads · Live NVD + CISA KEV feeds")

# ── Sidebar controls ──────────────────────────────────────────────────────────
with st.sidebar:
    st.header("Query Settings")

    keyword = st.text_input(
        "CVE keyword search",
        value="remote code execution",
        help="Free-text search forwarded to the NVD keywordSearch parameter.",
    )
    max_results = st.slider(
        "Max CVEs to fetch",
        min_value=10,
        max_value=200,
        value=50,
        step=10,
        help="Kept low by default to stay storage-light. Hard-capped at 2000.",
    )

    st.divider()
    use_date_filter = st.checkbox(
        "Filter by publication date",
        value=False,
        help="Narrow results to CVEs published within a date window.",
    )

    pub_start_date = ""
    pub_end_date = ""

    if use_date_filter:
        today = date.today()
        default_start = today - timedelta(days=365)

        col_a, col_b = st.columns(2)
        with col_a:
            pub_start = st.date_input("From", value=default_start)
        with col_b:
            pub_end = st.date_input("To", value=today)

        if pub_start > pub_end:
            st.warning("'From' date must be before 'To' date.")
            pub_start, pub_end = pub_end, pub_start

        pub_start_date = f"{pub_start.isoformat()}T00:00:00.000"
        pub_end_date = f"{pub_end.isoformat()}T23:59:59.000"

    fetch_btn = st.button("Fetch & Analyse", type="primary", use_container_width=True)

# ── Main panel ────────────────────────────────────────────────────────────────
if fetch_btn:

    # Step 1 — load CISA KEV catalogue
    with st.spinner("Fetching CISA KEV catalogue…"):
        try:
            kev_ids = get_kev_cve_ids()
            st.success(f"KEV catalogue loaded: {len(kev_ids):,} known-exploited CVEs")
        except CISAKEVError as exc:
            st.warning(
                f"Could not load KEV catalogue: {exc}\n\n"
                "Risk scores will not reflect known-exploited status. "
                "Results are still shown using CVSS data only."
            )
            kev_ids = set()

    # Step 2 — fetch CVEs from NVD
    spinner_label = (
        f"Fetching up to {max_results} CVEs from NVD"
        + (f" ({pub_start_date[:10]} → {pub_end_date[:10]})" if use_date_filter else "")
        + "…"
    )
    with st.spinner(spinner_label):
        try:
            raw_records = list(iter_cves(
                keyword=keyword,
                max_results=max_results,
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
            ))
        except NVDRateLimitError as exc:
            st.error(
                "NVD rate limit hit (HTTP 403).\n\n"
                "Add your free `NVD_API_KEY` to `.env`, or wait 30 s and retry.\n\n"
                f"Detail: {exc}"
            )
            st.stop()
        except NVDAPIError as exc:
            st.error(f"NVD API error: {exc}")
            st.stop()

    if not raw_records:
        st.warning(
            "NVD returned no results for that query. "
            "Try a broader keyword or adjust the date range."
        )
        st.stop()

    # Step 3 — parse → feature-engineer (includes KEV overlay and risk score)
    parsed = [parse_cve(r) for r in raw_records]
    df = build_features(parsed, kev_ids=kev_ids)
    df.sort_values("risk_score", ascending=False, inplace=True)

    # Step 4 — summary metrics
    st.subheader(f"Results — {len(df)} CVEs")

    avg_risk = df["risk_score"].mean()
    col1, col2, col3 = st.columns(3)
    col1.metric("Critical", int((df["severity"] == "CRITICAL").sum()))
    col2.metric("In KEV (actively exploited)", int(df["in_kev"].sum()))
    col3.metric("Avg Risk Score", f"{avg_risk:.1f}" if pd.notna(avg_risk) else "—")

    # Step 5 — risk score disclaimer
    with st.expander("ℹ️ About the risk score"):
        st.markdown(
            """
            **The risk score is a defensive prioritisation tool — it is not proof
            of exploitability.**

            It is computed from three public data sources:

            | Component | Source | Weight |
            |---|---|---|
            | CVSS base score (0–10) | NVD CVE metrics | Foundation |
            | Severity × attack-vector multiplier | NVD CVSS metadata | Adjusts score up/down |
            | CISA KEV membership | CISA Known Exploited Vulnerabilities catalogue | +20 bonus points |

            A high score means the vulnerability has characteristics that are
            *commonly associated* with high-impact or actively-targeted issues —
            it does **not** mean your specific environment is affected or that
            exploitation is imminent.

            Use this score alongside your own asset inventory, patch management
            process, and threat intelligence before making remediation decisions.
            """
        )

    # Step 6 — results table (human-readable columns)
    st.dataframe(
        df[[
            "cve_id",
            "severity",
            "base_score",
            "age_days",
            "attack_vector",
            "cwe",
            "in_kev",
            "risk_score",
        ]].rename(columns={
            "cve_id": "CVE ID",
            "severity": "Severity",
            "base_score": "CVSS Score",
            "age_days": "Age (days)",
            "attack_vector": "Attack Vector",
            "cwe": "CWE",
            "in_kev": "In KEV",
            "risk_score": "Risk Score",
        }),
        use_container_width=True,
        hide_index=True,
    )

    # Step 7 — ML features expander (numeric columns for data scientists)
    with st.expander("🔬 Normalized ML features"):
        st.caption(
            "Numeric-encoded columns used as model inputs. "
            "severity_numeric: CRITICAL=4 HIGH=3 MEDIUM=2 LOW=1 UNKNOWN=0. "
            "attack_vector_numeric: NETWORK=4 ADJACENT=3 LOCAL=2 PHYSICAL=1 UNKNOWN=0."
        )
        st.dataframe(
            df[[
                "cve_id",
                "severity_numeric",
                "attack_vector_numeric",
                "age_days",
                "kev_numeric",
                "risk_score",
            ]],
            use_container_width=True,
            hide_index=True,
        )

    # Step 8 — chart
    if len(df) > 1:
        st.subheader("Risk Score Distribution (top 30)")
        st.bar_chart(df.set_index("cve_id")["risk_score"].head(30))

    # Step 9 — ML analysis
    with st.expander("🤖 ML Analysis (baseline model)", expanded=False):
        st.caption(
            "Trains a LogisticRegression on the current result set and scores each CVE. "
            "This is an educational baseline — not a production exploit predictor. "
            "See docs/modeling.md for limitations."
        )
        if len(df) < MIN_TRAINING_SAMPLES:
            st.warning(
                f"ML training requires at least {MIN_TRAINING_SAMPLES} CVEs; "
                f"only {len(df)} fetched. Increase 'Max CVEs' and retry."
            )
        else:
            try:
                pipeline, metrics = train(df)

                # Prepare full-dataset X / y for evaluation and explainability
                X_full = df[list(ML_FEATURE_COLS)].fillna(0)
                y_full = build_labels(df)

                # ── Class balance ─────────────────────────────────────────────
                balance = class_balance(y_full)
                b_col1, b_col2, b_col3 = st.columns(3)
                b_col1.metric("High-Risk CVEs (label=1)", balance["n_high_risk"])
                b_col2.metric("Not-High-Risk CVEs (label=0)", balance["n_not_high_risk"])
                b_col3.metric("Fraction High-Risk", f"{balance['frac_high_risk']:.0%}")
                if balance["frac_high_risk"] < 0.20 or balance["frac_high_risk"] > 0.80:
                    st.warning(
                        "Class imbalance detected — the minority class is "
                        f"{min(balance['frac_high_risk'], 1 - balance['frac_high_risk']):.0%} "
                        "of the dataset. Accuracy may be misleading; focus on Precision, "
                        "Recall, and F1 instead."
                    )

                st.divider()

                # ── Evaluation metrics at default 0.50 threshold ─────────────
                m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                m_col1.metric("Accuracy", f"{metrics['accuracy']:.0%}")
                m_col2.metric("Precision", f"{metrics['precision']:.0%}")
                m_col3.metric("Recall", f"{metrics['recall']:.0%}")
                m_col4.metric("F1", f"{metrics['f1']:.0%}")
                st.caption(
                    f"Trained on {metrics['n_train']} CVEs · "
                    f"Evaluated on {metrics['n_test']} CVEs · "
                    "Label: risk_score ≥ 70 · Decision threshold: 0.50"
                )
                st.info(
                    "This is a **baseline educational model**, not a production "
                    "exploitability predictor.  Metrics are computed on the same "
                    "CVEs just fetched — treat them as illustrative, not definitive."
                )

                if is_accuracy_misleading(metrics, balance):
                    st.warning(
                        "Accuracy is high but Precision / Recall / F1 are low.  "
                        "The model may be predicting the majority class for most inputs.  "
                        "Fetch more diverse CVEs or adjust the risk-score threshold."
                    )

                st.divider()

                # ── Threshold analysis ────────────────────────────────────────
                st.markdown("**Threshold analysis**")
                st.caption(
                    "Each row shows Precision, Recall, and F1 when the decision "
                    "boundary is moved.  Lower thresholds catch more high-risk CVEs "
                    "(higher Recall) at the cost of more false alarms (lower Precision).  "
                    "Defensive teams often favour Recall over Precision."
                )
                sweep = threshold_sweep(pipeline, X_full, y_full)
                rec_thresh = recommend_threshold(sweep)
                rec_thresh_recall = recommend_threshold(sweep, prefer_recall=True)

                t_col1, t_col2 = st.columns(2)
                t_col1.metric(
                    "Recommended threshold (best F1)",
                    f"{rec_thresh:.2f}",
                    help="Threshold that maximises F1 across the sweep.",
                )
                t_col2.metric(
                    "Recommended threshold (best Recall)",
                    f"{rec_thresh_recall:.2f}",
                    help="Threshold that maximises Recall — preferred for defensive prioritisation.",
                )

                st.dataframe(
                    sweep.rename(columns={
                        "threshold": "Threshold",
                        "precision": "Precision",
                        "recall": "Recall",
                        "f1": "F1",
                        "predicted_positive_count": "Predicted Positive",
                    }),
                    use_container_width=True,
                    hide_index=True,
                )

                st.divider()

                # ── Confusion matrix at recommended threshold ─────────────────
                st.markdown(
                    f"**Confusion matrix** at recommended threshold "
                    f"({rec_thresh:.2f}, full result set)"
                )
                cm = confusion_matrix_values(pipeline, X_full, y_full, threshold=rec_thresh)
                st.markdown(
                    f"| | Predicted: Not High Risk | Predicted: High Risk |\n"
                    f"|---|---|---|\n"
                    f"| **Actually: Not High Risk** | TN = {cm['tn']} | FP = {cm['fp']} |\n"
                    f"| **Actually: High Risk** | FN = {cm['fn']} | TP = {cm['tp']} |"
                )

                st.divider()

                # ── Feature importance ────────────────────────────────────────
                st.markdown("**Feature importance** (permutation importance, full result set)")
                st.caption(
                    "Measures how much accuracy drops when each feature is shuffled. "
                    "Higher = more important. Note: features share information with the "
                    "risk_score label — see docs/modeling.md for interpretation guidance."
                )
                pi = permutation_importance_df(pipeline, X_full, y_full, n_repeats=5)
                st.dataframe(
                    pi.rename(columns={
                        "feature": "Feature",
                        "mean_importance": "Mean Importance",
                        "std_importance": "Std Dev",
                    }),
                    use_container_width=True,
                    hide_index=True,
                )

                st.divider()

                # ── Per-CVE probability table ─────────────────────────────────
                st.markdown("**Per-CVE high-risk probability**")
                probs = predict(pipeline, df)
                display_df = df[["cve_id", "risk_score"]].copy()
                display_df["high_risk_prob"] = probs.values
                st.dataframe(
                    display_df.sort_values("high_risk_prob", ascending=False).rename(
                        columns={
                            "cve_id": "CVE ID",
                            "risk_score": "Rule Score",
                            "high_risk_prob": "ML High-Risk Prob",
                        }
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
            except ModelTrainingError as exc:
                st.warning(f"ML training skipped: {exc}")

else:
    st.info("Configure your query in the sidebar and click **Fetch & Analyse**.")
