"""
Transforms parsed CVE dicts into a normalized, model-ready DataFrame.
All computation happens in memory — nothing is written to disk.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from src.models.risk_scorer import score as _risk_score

# ── Ordinal encoding maps ─────────────────────────────────────────────────────

SEVERITY_MAP: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NONE": 0,
    "UNKNOWN": 0,
}

ATTACK_VECTOR_MAP: dict[str, int] = {
    "NETWORK": 4,
    "ADJACENT_NETWORK": 3,   # CVSS v2 label
    "ADJACENT": 3,            # CVSS v3 label
    "LOCAL": 2,
    "PHYSICAL": 1,
    "UNKNOWN": 0,
}

# Canonical columns present in every DataFrame this module produces.
FEATURE_COLUMNS: tuple[str, ...] = (
    "cve_id",
    "severity",
    "severity_numeric",
    "base_score",
    "attack_vector",
    "attack_vector_numeric",
    "cwe",
    "published",
    "age_days",
    "in_kev",
    "kev_numeric",
    "risk_score",
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _age_days(published: str) -> int:
    """Return whole days elapsed since *published*.

    Returns -1 when the date string is missing, empty, or unparseable.
    Never returns a negative number for valid past dates.
    """
    if not published:
        return -1
    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(tz=timezone.utc) - dt
        return max(0, delta.days)
    except (ValueError, TypeError):
        return -1


# ── Public API ────────────────────────────────────────────────────────────────

def build_features(
    records: list[dict],
    kev_ids: set[str] | None = None,
) -> pd.DataFrame:
    """Convert parsed CVE dicts into a normalized, model-ready DataFrame.

    All 12 canonical columns defined in ``FEATURE_COLUMNS`` are guaranteed to
    be present in the returned DataFrame (when *records* is non-empty).

    Parameters
    ----------
    records:
        Output of ``parse_cve()`` calls — one dict per CVE.
    kev_ids:
        Set of CVE IDs present in the CISA KEV catalogue.
        Defaults to the empty set when ``None`` is passed; every CVE will
        receive ``in_kev = False`` and ``kev_numeric = 0``.

    Returns
    -------
    pd.DataFrame
        Columns: cve_id, severity, severity_numeric, base_score,
        attack_vector, attack_vector_numeric, cwe, published, age_days,
        in_kev, kev_numeric, risk_score.
        Returns an empty DataFrame when *records* is empty.
    """
    _kev = kev_ids if kev_ids is not None else set()

    df = pd.DataFrame(records)
    if df.empty:
        return df

    # ── base_score ────────────────────────────────────────────────────────────
    df["base_score"] = pd.to_numeric(df["base_score"], errors="coerce")
    median_score = df["base_score"].median()
    fill_score = median_score if pd.notna(median_score) else 5.0
    df["base_score"] = df["base_score"].fillna(fill_score)

    # ── severity ──────────────────────────────────────────────────────────────
    df["severity"] = (
        df["severity"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
        .str.strip()
        .replace("", "UNKNOWN")
    )
    df["severity_numeric"] = df["severity"].map(SEVERITY_MAP).fillna(0).astype(int)

    # ── attack_vector ─────────────────────────────────────────────────────────
    df["attack_vector"] = (
        df["attack_vector"]
        .fillna("UNKNOWN")
        .astype(str)
        .str.upper()
        .str.strip()
        .replace("", "UNKNOWN")
    )
    df["attack_vector_numeric"] = (
        df["attack_vector"].map(ATTACK_VECTOR_MAP).fillna(0).astype(int)
    )

    # ── age_days ──────────────────────────────────────────────────────────────
    df["age_days"] = df["published"].apply(_age_days)

    # ── KEV features ──────────────────────────────────────────────────────────
    df["in_kev"] = df["cve_id"].isin(_kev)
    df["kev_numeric"] = df["in_kev"].astype(int)

    # ── risk_score ────────────────────────────────────────────────────────────
    df["risk_score"] = df.apply(
        lambda row: _risk_score(row.to_dict(), is_kev=bool(row["in_kev"])),
        axis=1,
    )

    return df
