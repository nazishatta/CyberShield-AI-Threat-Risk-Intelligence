"""
Tests for src/recommendations/mitigation.py.
All data is constructed in-process — no network calls.
"""

from __future__ import annotations

import math

import pandas as pd
import pytest

from src.recommendations.mitigation import (
    build_recommendations,
    recommend_mitigation,
)

# ── Constants ─────────────────────────────────────────────────────────────────

_REQUIRED_KEYS = {
    "cve_id",
    "priority_level",
    "action_title",
    "recommendation",
    "rationale",
    "suggested_sla",
    "escalation_required",
    "responsible_use_note",
}

_VALID_PRIORITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

_EXPECTED_COLUMNS = {
    "cve_id", "priority_level", "action_title", "recommendation",
    "rationale", "suggested_sla", "escalation_required", "responsible_use_note",
}

# ── Synthetic row helpers ─────────────────────────────────────────────────────

def _kev_high_risk_row() -> dict:
    """Tier 1: KEV-listed + risk_score >= 70 → CRITICAL."""
    return {
        "cve_id": "CVE-2024-CRITICAL",
        "in_kev": True,
        "kev_numeric": 1,
        "risk_score": 85.0,
        "base_score": 9.0,
        "severity": "CRITICAL",
        "attack_vector": "NETWORK",
        "attack_vector_numeric": 4,
        "age_days": 200,
        "cwe": "UNKNOWN",
    }


def _network_high_cvss_row(risk_score: float = 60.0) -> dict:
    """Tier 2: NETWORK attack vector + base_score >= 7.0, not KEV."""
    return {
        "cve_id": "CVE-2024-NETWORK",
        "in_kev": False,
        "kev_numeric": 0,
        "risk_score": risk_score,
        "base_score": 8.5,
        "severity": "HIGH",
        "attack_vector": "NETWORK",
        "attack_vector_numeric": 4,
        "age_days": 100,
        "cwe": "UNKNOWN",
    }


def _unknown_data_row() -> dict:
    """Tier 3: severity and attack_vector are UNKNOWN."""
    return {
        "cve_id": "CVE-2024-UNKNOWN",
        "in_kev": False,
        "kev_numeric": 0,
        "risk_score": 30.0,
        "base_score": 5.0,
        "severity": "UNKNOWN",
        "attack_vector": "UNKNOWN",
        "attack_vector_numeric": 0,
        "age_days": 50,
        "cwe": "UNKNOWN",
    }


def _old_elevated_row(risk_score: float = 55.0) -> dict:
    """Tier 4: age_days >= 365 + risk_score >= 50, LOCAL attack vector, complete data."""
    return {
        "cve_id": "CVE-2020-OLD",
        "in_kev": False,
        "kev_numeric": 0,
        "risk_score": risk_score,
        "base_score": 6.5,
        "severity": "HIGH",
        "attack_vector": "LOCAL",
        "attack_vector_numeric": 2,
        "age_days": 400,
        "cwe": "UNKNOWN",
    }


def _low_risk_row() -> dict:
    """Tier 5: low risk_score — scheduled remediation."""
    return {
        "cve_id": "CVE-2024-LOW",
        "in_kev": False,
        "kev_numeric": 0,
        "risk_score": 15.0,
        "base_score": 3.0,
        "severity": "LOW",
        "attack_vector": "LOCAL",
        "attack_vector_numeric": 2,
        "age_days": 30,
        "cwe": "UNKNOWN",
    }


# ── Required keys present ─────────────────────────────────────────────────────

def test_output_has_all_required_keys_critical():
    assert _REQUIRED_KEYS == set(recommend_mitigation(_kev_high_risk_row()).keys())


def test_output_has_all_required_keys_network():
    assert _REQUIRED_KEYS == set(recommend_mitigation(_network_high_cvss_row()).keys())


def test_output_has_all_required_keys_unknown():
    assert _REQUIRED_KEYS == set(recommend_mitigation(_unknown_data_row()).keys())


def test_output_has_all_required_keys_old_cve():
    assert _REQUIRED_KEYS == set(recommend_mitigation(_old_elevated_row()).keys())


def test_output_has_all_required_keys_low_risk():
    assert _REQUIRED_KEYS == set(recommend_mitigation(_low_risk_row()).keys())


# ── Priority levels valid ─────────────────────────────────────────────────────

def test_priority_level_valid_all_tiers():
    rows = [
        _kev_high_risk_row(),
        _network_high_cvss_row(),
        _unknown_data_row(),
        _old_elevated_row(),
        _low_risk_row(),
    ]
    for row in rows:
        result = recommend_mitigation(row)
        assert result["priority_level"] in _VALID_PRIORITIES, (
            f"Invalid priority '{result['priority_level']}' for {row['cve_id']}"
        )


# ── Tier 1: KEV + high risk ───────────────────────────────────────────────────

def test_kev_high_risk_priority_is_critical():
    assert recommend_mitigation(_kev_high_risk_row())["priority_level"] == "CRITICAL"


def test_kev_high_risk_escalation_required():
    assert recommend_mitigation(_kev_high_risk_row())["escalation_required"] is True


def test_kev_high_risk_sla_mentions_hours():
    sla = recommend_mitigation(_kev_high_risk_row())["suggested_sla"].lower()
    assert "hour" in sla or "48" in sla


def test_kev_high_risk_cve_id_preserved():
    assert recommend_mitigation(_kev_high_risk_row())["cve_id"] == "CVE-2024-CRITICAL"


def test_kev_high_risk_kev_numeric_only():
    """kev_numeric=1 without in_kev key still triggers Tier 1."""
    row = {
        "cve_id": "CVE-2024-KEV2",
        "kev_numeric": 1,
        "risk_score": 75.0,
        "base_score": 8.0,
        "severity": "CRITICAL",
        "attack_vector": "NETWORK",
        "attack_vector_numeric": 4,
        "age_days": 100,
        "cwe": "UNKNOWN",
    }
    assert recommend_mitigation(row)["priority_level"] == "CRITICAL"


def test_kev_below_high_risk_threshold_not_critical():
    """KEV + risk_score < 70 does not produce CRITICAL priority."""
    row = dict(_kev_high_risk_row())
    row["risk_score"] = 65.0
    # Falls to Tier 2 (NETWORK + base_score=9.0 >= 7.0)
    assert recommend_mitigation(row)["priority_level"] != "CRITICAL"


# ── Tier 2: Network + high CVSS ───────────────────────────────────────────────

def test_network_high_cvss_priority_is_high():
    assert recommend_mitigation(_network_high_cvss_row(risk_score=60.0))["priority_level"] == "HIGH"


def test_network_high_cvss_sla_contains_72():
    assert "72" in recommend_mitigation(_network_high_cvss_row())["suggested_sla"]


def test_network_high_cvss_no_escalation_below_70():
    assert recommend_mitigation(_network_high_cvss_row(risk_score=60.0))["escalation_required"] is False


def test_network_high_cvss_escalation_above_70():
    assert recommend_mitigation(_network_high_cvss_row(risk_score=75.0))["escalation_required"] is True


def test_low_base_score_network_not_high_priority():
    """NETWORK attack vector but base_score < 7.0 should not trigger Tier 2."""
    row = {
        "cve_id": "CVE-2024-NET-LOW",
        "in_kev": False,
        "kev_numeric": 0,
        "risk_score": 25.0,
        "base_score": 4.0,
        "severity": "MEDIUM",
        "attack_vector": "NETWORK",
        "attack_vector_numeric": 4,
        "age_days": 100,
        "cwe": "UNKNOWN",
    }
    assert recommend_mitigation(row)["priority_level"] != "HIGH"


# ── Tier 3: Unknown / missing data ────────────────────────────────────────────

def test_unknown_severity_triggers_manual_review():
    result = recommend_mitigation(_unknown_data_row())
    assert result["priority_level"] == "MEDIUM"
    title = result["action_title"].lower()
    assert "manual" in title or "review" in title


def test_unknown_data_escalation_is_false():
    assert recommend_mitigation(_unknown_data_row())["escalation_required"] is False


def test_missing_base_score_nan_triggers_manual_review():
    row = dict(_unknown_data_row())
    row["severity"] = "HIGH"
    row["attack_vector"] = "LOCAL"
    row["base_score"] = float("nan")
    assert recommend_mitigation(row)["priority_level"] == "MEDIUM"


# ── Tier 4: Old CVE + elevated risk ──────────────────────────────────────────

def test_old_elevated_cve_sla_7_days():
    assert "7" in recommend_mitigation(_old_elevated_row())["suggested_sla"]


def test_old_high_risk_cve_priority_high():
    assert recommend_mitigation(_old_elevated_row(risk_score=75.0))["priority_level"] == "HIGH"


def test_old_medium_risk_cve_priority_medium():
    assert recommend_mitigation(_old_elevated_row(risk_score=55.0))["priority_level"] == "MEDIUM"


def test_old_low_risk_falls_to_tier5():
    """age_days >= 365 but risk_score < 50 should fall to Tier 5 (30-day SLA)."""
    row = dict(_old_elevated_row())
    row["risk_score"] = 40.0
    assert recommend_mitigation(row)["suggested_sla"] == "30 days"


# ── Tier 5: Scheduled remediation ────────────────────────────────────────────

def test_low_risk_sla_30_days():
    assert "30" in recommend_mitigation(_low_risk_row())["suggested_sla"]


def test_medium_risk_score_priority_medium():
    row = dict(_low_risk_row())
    row["risk_score"] = 35.0
    assert recommend_mitigation(row)["priority_level"] == "MEDIUM"


def test_very_low_risk_score_priority_low():
    assert recommend_mitigation(_low_risk_row())["priority_level"] == "LOW"


# ── CWE-aware guidance ────────────────────────────────────────────────────────

def test_known_cwe_adds_guidance_to_recommendation():
    row = {
        "cve_id": "CVE-2024-XSS",
        "in_kev": False,
        "kev_numeric": 0,
        "risk_score": 20.0,
        "base_score": 4.0,  # below 7.0 — avoids Tier 2
        "severity": "MEDIUM",
        "attack_vector": "NETWORK",
        "attack_vector_numeric": 4,
        "age_days": 50,
        "cwe": "CWE-79",
    }
    result = recommend_mitigation(row)
    assert "CWE-79" in result["recommendation"]


def test_unknown_cwe_no_extra_guidance():
    result = recommend_mitigation(_low_risk_row())
    assert "CWE-" not in result["recommendation"]


# ── pd.Series input ───────────────────────────────────────────────────────────

def test_accepts_pandas_series():
    series = pd.Series(_kev_high_risk_row())
    assert recommend_mitigation(series)["priority_level"] == "CRITICAL"


def test_series_and_dict_produce_same_result():
    row = _network_high_cvss_row()
    assert recommend_mitigation(row) == recommend_mitigation(pd.Series(row))


# ── build_recommendations ─────────────────────────────────────────────────────

def test_build_recommendations_returns_dataframe():
    df = pd.DataFrame([_kev_high_risk_row(), _low_risk_row()])
    assert isinstance(build_recommendations(df), pd.DataFrame)


def test_build_recommendations_empty_input_returns_empty_df():
    result = build_recommendations(pd.DataFrame())
    assert isinstance(result, pd.DataFrame)
    assert len(result) == 0


def test_build_recommendations_empty_has_expected_columns():
    result = build_recommendations(pd.DataFrame())
    assert _EXPECTED_COLUMNS == set(result.columns)


def test_build_recommendations_row_count_matches_input():
    df = pd.DataFrame([_kev_high_risk_row(), _network_high_cvss_row(), _low_risk_row()])
    assert len(build_recommendations(df)) == 3


def test_build_recommendations_has_expected_columns():
    df = pd.DataFrame([_kev_high_risk_row()])
    assert _EXPECTED_COLUMNS == set(build_recommendations(df).columns)


def test_build_recommendations_sorted_critical_first():
    df = pd.DataFrame([_low_risk_row(), _kev_high_risk_row()])
    result = build_recommendations(df)
    assert result.iloc[0]["priority_level"] == "CRITICAL"


def test_build_recommendations_sorted_high_before_low():
    df = pd.DataFrame([_low_risk_row(), _network_high_cvss_row()])
    result = build_recommendations(df)
    assert result.iloc[0]["priority_level"] == "HIGH"


def test_build_recommendations_escalation_required_is_bool():
    df = pd.DataFrame([_kev_high_risk_row(), _low_risk_row()])
    result = build_recommendations(df)
    for val in result["escalation_required"]:
        assert isinstance(val, bool), f"Expected bool, got {type(val)}"
