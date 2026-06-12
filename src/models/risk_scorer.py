"""
Rule-based risk scorer (Milestone 0 baseline).
Replaced by an ML model in Milestone 2.
"""

from __future__ import annotations


_SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}
_AV_WEIGHT = {"NETWORK": 1.0, "ADJACENT": 0.7, "LOCAL": 0.4, "PHYSICAL": 0.2}


def score(cve: dict, is_kev: bool = False) -> float:
    """Return a 0-100 composite risk score for a parsed CVE dict."""
    base = float(cve.get("base_score") or 5.0)
    sev = cve.get("severity", "UNKNOWN")
    av = cve.get("attack_vector", "UNKNOWN")

    sev_w = _SEVERITY_WEIGHT.get(sev, 0.5)
    av_w = _AV_WEIGHT.get(av, 0.5)
    kev_bonus = 20.0 if is_kev else 0.0

    raw = base * sev_w * av_w * 10 + kev_bonus
    return round(min(raw, 100.0), 2)
