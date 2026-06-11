"""
Transforms parsed CVE dicts into a model-ready DataFrame.
Milestone 1 placeholder — logic filled in next milestone.
"""

from __future__ import annotations

import pandas as pd


def build_features(records: list[dict]) -> pd.DataFrame:
    """Convert a list of parsed CVE dicts into a feature DataFrame."""
    df = pd.DataFrame(records)
    if df.empty:
        return df

    # Binary exploit label: will be joined from KEV in Milestone 1
    if "exploited" not in df.columns:
        df["exploited"] = 0

    # Numeric base score — fill missing with median
    df["base_score"] = pd.to_numeric(df["base_score"], errors="coerce")
    df["base_score"].fillna(df["base_score"].median(), inplace=True)

    # Ordinal severity
    _sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    df["severity_num"] = df["severity"].map(_sev_map).fillna(0).astype(int)

    return df
