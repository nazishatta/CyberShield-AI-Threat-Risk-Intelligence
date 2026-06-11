"""Unit tests for the rule-based risk scorer."""

from src.models.risk_scorer import score


def test_kev_bonus_raises_score():
    cve = {"base_score": 7.5, "severity": "HIGH", "attack_vector": "NETWORK"}
    without_kev = score(cve, is_kev=False)
    with_kev = score(cve, is_kev=True)
    assert with_kev > without_kev


def test_score_capped_at_100():
    cve = {"base_score": 10.0, "severity": "CRITICAL", "attack_vector": "NETWORK"}
    assert score(cve, is_kev=True) <= 100.0


def test_score_unknown_severity():
    cve = {"base_score": 5.0, "severity": "UNKNOWN", "attack_vector": "UNKNOWN"}
    result = score(cve)
    assert 0 <= result <= 100
