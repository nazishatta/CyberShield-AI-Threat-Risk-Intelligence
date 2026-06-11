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
from src.models.risk_scorer import score
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
                f"NVD rate limit hit (HTTP 403).\n\n"
                f"Add your free `NVD_API_KEY` to `.env`, or wait 30 s and retry.\n\n"
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

    # Step 3 — parse, feature-engineer, score
    parsed = [parse_cve(r) for r in raw_records]
    df = build_features(parsed)

    df["in_kev"] = df["cve_id"].isin(kev_ids)
    df["risk_score"] = df.apply(
        lambda row: score(row.to_dict(), is_kev=row["in_kev"]), axis=1
    )
    df.sort_values("risk_score", ascending=False, inplace=True)

    # Step 4 — display
    st.subheader(f"Results — {len(df)} CVEs")

    avg_risk = df["risk_score"].mean()
    col1, col2, col3 = st.columns(3)
    col1.metric("Critical", int((df["severity"] == "CRITICAL").sum()))
    col2.metric("In KEV (actively exploited)", int(df["in_kev"].sum()))
    col3.metric("Avg Risk Score", f"{avg_risk:.1f}" if pd.notna(avg_risk) else "—")

    st.dataframe(
        df[[
            "cve_id", "severity", "base_score", "in_kev",
            "risk_score", "attack_vector", "cwe", "published",
        ]],
        use_container_width=True,
        hide_index=True,
    )

    if len(df) > 1:
        st.subheader("Risk Score Distribution (top 30)")
        st.bar_chart(df.set_index("cve_id")["risk_score"].head(30))

else:
    st.info("Configure your query in the sidebar and click **Fetch & Analyse**.")
