"""
Tests for src/features/feature_engineering.py.
No network calls — all data is constructed in-process.
"""

from __future__ import annotations

import math

import pandas as pd
import pytest

from src.features.feature_engineering import (
    ATTACK_VECTOR_MAP,
    FEATURE_COLUMNS,
    SEVERITY_MAP,
    build_features,
)


# ── Shared helpers ────────────────────────────────────────────────────────────

def _rec(
    cve_id: str = "CVE-2024-0001",
    severity: str = "CRITICAL",
    base_score: float = 9.8,
    attack_vector: str = "NETWORK",
    published: str = "2020-01-01T00:00:00.000",
    cwe: str = "CWE-78",
) -> dict:
    """Minimal parsed CVE dict that satisfies build_features."""
    return {
        "cve_id": cve_id,
        "severity": severity,
        "base_score": base_score,
        "attack_vector": attack_vector,
        "published": published,
        "cwe": cwe,
        "last_modified": "",
        "description": "Test description.",
        "ref_count": 1,
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "confidentiality_impact": "HIGH",
        "integrity_impact": "HIGH",
        "availability_impact": "HIGH",
    }


# ── Output shape ──────────────────────────────────────────────────────────────

def test_all_canonical_columns_present():
    df = build_features([_rec()])
    for col in FEATURE_COLUMNS:
        assert col in df.columns, f"Missing column: {col}"


def test_empty_records_returns_empty_dataframe():
    df = build_features([])
    assert df.empty


def test_multiple_records_produces_correct_row_count():
    records = [_rec(cve_id=f"CVE-2024-{i:04d}") for i in range(5)]
    df = build_features(records)
    assert len(df) == 5


# ── severity_numeric mapping ──────────────────────────────────────────────────

@pytest.mark.parametrize("severity, expected", [
    ("CRITICAL", 4),
    ("HIGH",     3),
    ("MEDIUM",   2),
    ("LOW",      1),
    ("NONE",     0),
    ("UNKNOWN",  0),
])
def test_severity_numeric_mapping(severity, expected):
    df = build_features([_rec(severity=severity)])
    assert df.iloc[0]["severity_numeric"] == expected


def test_severity_numeric_unknown_for_unrecognised_value():
    df = build_features([_rec(severity="BANANA")])
    assert df.iloc[0]["severity_numeric"] == 0


def test_severity_normalised_to_upper():
    df = build_features([_rec(severity="critical")])
    assert df.iloc[0]["severity"] == "CRITICAL"
    assert df.iloc[0]["severity_numeric"] == 4


# ── attack_vector_numeric mapping ─────────────────────────────────────────────

@pytest.mark.parametrize("av, expected", [
    ("NETWORK",          4),
    ("ADJACENT",         3),
    ("ADJACENT_NETWORK", 3),
    ("LOCAL",            2),
    ("PHYSICAL",         1),
    ("UNKNOWN",          0),
])
def test_attack_vector_numeric_mapping(av, expected):
    df = build_features([_rec(attack_vector=av)])
    assert df.iloc[0]["attack_vector_numeric"] == expected


def test_attack_vector_normalised_to_upper():
    df = build_features([_rec(attack_vector="network")])
    assert df.iloc[0]["attack_vector"] == "NETWORK"
    assert df.iloc[0]["attack_vector_numeric"] == 4


# ── age_days ──────────────────────────────────────────────────────────────────

def test_age_days_positive_for_old_date():
    # 2020-01-01 is well over 1000 days in the past as of 2026
    df = build_features([_rec(published="2020-01-01T00:00:00.000")])
    assert df.iloc[0]["age_days"] > 1000


def test_age_days_minus_one_for_empty_published():
    df = build_features([_rec(published="")])
    assert df.iloc[0]["age_days"] == -1


def test_age_days_minus_one_for_none_published():
    record = _rec()
    record["published"] = None
    df = build_features([record])
    assert df.iloc[0]["age_days"] == -1


def test_age_days_minus_one_for_malformed_date():
    df = build_features([_rec(published="not-a-date")])
    assert df.iloc[0]["age_days"] == -1


def test_age_days_minus_one_for_garbage_string():
    df = build_features([_rec(published="!!??##")])
    assert df.iloc[0]["age_days"] == -1


def test_age_days_non_negative_for_recent_date():
    df = build_features([_rec(published="2025-01-01T00:00:00.000")])
    assert df.iloc[0]["age_days"] >= 0


# ── KEV features ──────────────────────────────────────────────────────────────

def test_in_kev_true_when_cve_id_in_kev_ids():
    df = build_features([_rec(cve_id="CVE-2021-44228")], kev_ids={"CVE-2021-44228"})
    assert bool(df.iloc[0]["in_kev"]) is True


def test_in_kev_false_when_cve_id_not_in_kev_ids():
    df = build_features([_rec(cve_id="CVE-2021-44228")], kev_ids={"CVE-9999-0000"})
    assert bool(df.iloc[0]["in_kev"]) is False


def test_kev_numeric_one_when_in_kev():
    df = build_features([_rec(cve_id="CVE-2021-44228")], kev_ids={"CVE-2021-44228"})
    assert df.iloc[0]["kev_numeric"] == 1


def test_kev_numeric_zero_when_not_in_kev():
    df = build_features([_rec(cve_id="CVE-2021-44228")], kev_ids=set())
    assert df.iloc[0]["kev_numeric"] == 0


def test_kev_ids_none_defaults_to_no_kev_hits():
    df = build_features([_rec(cve_id="CVE-2021-44228")], kev_ids=None)
    assert bool(df.iloc[0]["in_kev"]) is False
    assert df.iloc[0]["kev_numeric"] == 0


def test_multiple_records_kev_flag_selective():
    records = [
        _rec(cve_id="CVE-2021-44228"),
        _rec(cve_id="CVE-2022-0001"),
    ]
    df = build_features(records, kev_ids={"CVE-2021-44228"})
    kev_hits = df.set_index("cve_id")["in_kev"]
    assert bool(kev_hits["CVE-2021-44228"]) is True
    assert bool(kev_hits["CVE-2022-0001"]) is False


# ── Missing / malformed fields ────────────────────────────────────────────────

def test_missing_base_score_filled_with_median():
    records = [
        _rec(cve_id="CVE-2024-0001", base_score=8.0),
        _rec(cve_id="CVE-2024-0002", base_score=6.0),
        _rec(cve_id="CVE-2024-0003", base_score=None),
    ]
    df = build_features(records)
    expected_median = 7.0  # median of [8.0, 6.0]
    assert df.loc[df["cve_id"] == "CVE-2024-0003", "base_score"].iloc[0] == expected_median


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_all_base_scores_missing_filled_with_default():
    # When every record has no score, pandas median() returns NaN and numpy
    # emits a RuntimeWarning — both expected. The fallback should be 5.0.
    record = _rec(base_score=None)
    df = build_features([record])
    assert df.iloc[0]["base_score"] == 5.0


def test_missing_severity_defaults_to_unknown():
    record = _rec()
    record["severity"] = None
    df = build_features([record])
    assert df.iloc[0]["severity"] == "UNKNOWN"
    assert df.iloc[0]["severity_numeric"] == 0


def test_missing_attack_vector_defaults_to_unknown():
    record = _rec()
    record["attack_vector"] = None
    df = build_features([record])
    assert df.iloc[0]["attack_vector"] == "UNKNOWN"
    assert df.iloc[0]["attack_vector_numeric"] == 0


# ── risk_score ────────────────────────────────────────────────────────────────

def test_risk_score_is_numeric_and_in_range():
    df = build_features([_rec()])
    rs = df.iloc[0]["risk_score"]
    assert isinstance(rs, float)
    assert 0.0 <= rs <= 100.0


def test_kev_membership_increases_risk_score():
    base_rec = _rec(cve_id="CVE-2021-44228")
    df_no_kev = build_features([base_rec], kev_ids=set())
    df_with_kev = build_features([base_rec], kev_ids={"CVE-2021-44228"})
    assert df_with_kev.iloc[0]["risk_score"] > df_no_kev.iloc[0]["risk_score"]


def test_risk_score_not_nan():
    df = build_features([_rec()])
    assert not math.isnan(df.iloc[0]["risk_score"])
