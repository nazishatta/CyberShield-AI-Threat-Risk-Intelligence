"""
CyberShield AI — Streamlit dashboard entry point.
Milestone 0: skeleton with a live CVE fetch demo.
"""

import streamlit as st
import pandas as pd

from src.utils.config import load_config
from src.utils.logger import setup_logger
from src.ingestion.nvd_client import iter_cves
from src.ingestion.kev_client import get_kev_cve_ids
from src.features.cve_parser import parse_cve
from src.features.feature_engineering import build_features
from src.models.risk_scorer import score

setup_logger()
cfg = load_config()

st.set_page_config(
    page_title="CyberShield AI",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CyberShield AI — Threat & Risk Intelligence")
st.caption("API-first · No local dataset downloads · Live NVD + CISA KEV feeds")

# ── Sidebar controls ─────────────────────────────────────────────────────────
with st.sidebar:
    st.header("Query Settings")
    keyword = st.text_input("CVE keyword search", value="remote code execution")
    max_results = st.slider("Max CVEs to fetch", 10, 200, 50, step=10)
    fetch_btn = st.button("Fetch & Analyse", type="primary")

# ── Main panel ────────────────────────────────────────────────────────────────
if fetch_btn:
    with st.spinner("Fetching KEV catalogue…"):
        try:
            kev_ids = get_kev_cve_ids()
            st.success(f"KEV catalogue loaded: {len(kev_ids):,} known-exploited CVEs")
        except Exception as exc:
            st.warning(f"Could not fetch KEV: {exc}")
            kev_ids = set()

    with st.spinner(f"Fetching up to {max_results} CVEs from NVD…"):
        raw_records = list(iter_cves(keyword=keyword, max_results=max_results))

    parsed = [parse_cve(r) for r in raw_records]
    df = build_features(parsed)

    # Attach KEV flag and risk score
    df["in_kev"] = df["cve_id"].isin(kev_ids)
    df["risk_score"] = df.apply(
        lambda row: score(row.to_dict(), is_kev=row["in_kev"]), axis=1
    )
    df.sort_values("risk_score", ascending=False, inplace=True)

    st.subheader(f"Results — {len(df)} CVEs")

    col1, col2, col3 = st.columns(3)
    col1.metric("Critical", int((df["severity"] == "CRITICAL").sum()))
    col2.metric("In KEV (actively exploited)", int(df["in_kev"].sum()))
    col3.metric("Avg Risk Score", f"{df['risk_score'].mean():.1f}")

    st.dataframe(
        df[["cve_id", "severity", "base_score", "in_kev", "risk_score",
            "attack_vector", "cwe", "published"]],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Risk Score Distribution")
    st.bar_chart(df.set_index("cve_id")["risk_score"].head(30))
else:
    st.info("Configure your query in the sidebar and click **Fetch & Analyse**.")
