"""
Defensive mitigation recommendations for CVEs.

Generates prioritised, analyst-ready remediation guidance based on
publicly available vulnerability metadata. Output is descriptive
guidance only — no exploit instructions or attack steps are included.
"""

from __future__ import annotations

import math
import re
from typing import Any

import pandas as pd

_RESPONSIBLE_USE_NOTE = (
    "This recommendation is generated from public CVE metadata and is intended "
    "to assist security analysts — not replace their judgement. Verify against "
    "your asset inventory and organisational risk tolerance before acting."
)

_UNKNOWN_DATA_NOTE = (
    "Incomplete metadata was detected for this CVE. Manual analyst review is "
    "strongly recommended before scheduling remediation."
)

# ── CWE guidance map (defensive context only, no exploit steps) ───────────────

_CWE_GUIDANCE: dict[str, str] = {
    "CWE-79": (
        "For web applications: enforce a strict Content-Security-Policy (CSP) header, "
        "sanitise all user-supplied HTML/JavaScript inputs server-side, and use "
        "output-encoding libraries appropriate to the rendering context."
    ),
    "CWE-89": (
        "Ensure all database queries use parameterised statements or prepared statements. "
        "Apply a least-privilege database account policy and review application logs "
        "for anomalous query patterns."
    ),
    "CWE-20": (
        "Strengthen server-side input validation and rejection of unexpected data shapes "
        "at all API and form boundaries."
    ),
    "CWE-119": (
        "Prioritise patching on memory-unsafe components. Enable OS-level mitigations "
        "(ASLR, DEP/NX) if not already active."
    ),
    "CWE-787": (
        "Prioritise patching on memory-unsafe components. Enable OS-level mitigations "
        "(ASLR, DEP/NX) if not already active."
    ),
    "CWE-125": (
        "Prioritise patching on memory-unsafe components. Enable OS-level mitigations "
        "(ASLR, DEP/NX) if not already active."
    ),
    "CWE-22": (
        "Restrict application file-system access to a defined directory sandbox. "
        "Validate and normalise all path inputs server-side."
    ),
    "CWE-200": (
        "Audit access controls and data exposure points. Ensure sensitive data is "
        "only accessible to authorised principals."
    ),
    "CWE-287": (
        "Review authentication flows for bypass conditions. Enforce multi-factor "
        "authentication where feasible."
    ),
    "CWE-416": (
        "Update or replace affected libraries. Enable memory-safe build options "
        "and OS mitigations (ASLR, DEP/NX)."
    ),
}


def _safe_get(row: dict[str, Any], key: str, default: Any = None) -> Any:
    val = row.get(key, default)
    if val is None:
        return default
    try:
        if math.isnan(float(val)):  # type: ignore[arg-type]
            return default
    except (TypeError, ValueError):
        pass
    return val


def _is_kev(row: dict[str, Any]) -> bool:
    kev_numeric = _safe_get(row, "kev_numeric", 0)
    in_kev = _safe_get(row, "in_kev", False)
    try:
        kev_numeric = int(kev_numeric)
    except (TypeError, ValueError):
        kev_numeric = 0
    return bool(kev_numeric) or bool(in_kev)


def _is_network(row: dict[str, Any]) -> bool:
    av = str(_safe_get(row, "attack_vector", "") or "").upper()
    av_num = _safe_get(row, "attack_vector_numeric", 0)
    try:
        av_num = int(av_num)
    except (TypeError, ValueError):
        av_num = 0
    return av == "NETWORK" or av_num >= 4


def _has_unknown_data(row: dict[str, Any]) -> bool:
    severity = str(_safe_get(row, "severity", "UNKNOWN") or "UNKNOWN").upper()
    av = str(_safe_get(row, "attack_vector", "UNKNOWN") or "UNKNOWN").upper()
    base = _safe_get(row, "base_score", None)
    return severity == "UNKNOWN" or av == "UNKNOWN" or base is None


def _cwe_hint(row: dict[str, Any]) -> str:
    cwe = str(_safe_get(row, "cwe", "") or "")
    m = re.match(r"(CWE-\d+)", cwe, re.IGNORECASE)
    if m:
        key = m.group(1).upper()
        hint = _CWE_GUIDANCE.get(key, "")
        if hint:
            return f" Additional CWE guidance ({key}): {hint}"
    return ""


def recommend_mitigation(row: dict | pd.Series) -> dict:
    """Return a defensive mitigation recommendation for a single CVE row.

    Parameters
    ----------
    row : dict or pd.Series
        Must contain the fields produced by
        ``src.features.feature_engineering.build_features``.

    Returns
    -------
    dict with keys: cve_id, priority_level, action_title, recommendation,
        rationale, suggested_sla, escalation_required, responsible_use_note.
    """
    if isinstance(row, pd.Series):
        row = row.to_dict()

    cve_id = str(_safe_get(row, "cve_id", "UNKNOWN") or "UNKNOWN")
    risk_score = float(_safe_get(row, "risk_score", 0.0) or 0.0)
    base_score = float(_safe_get(row, "base_score", 0.0) or 0.0)

    age_days_raw = _safe_get(row, "age_days", -1)
    try:
        age_days = float(age_days_raw)
        if math.isnan(age_days) or age_days < 0:
            age_days = -1.0
    except (TypeError, ValueError):
        age_days = -1.0

    cwe_hint = _cwe_hint(row)

    # ── Tier 1: KEV + high risk ────────────────────────────────────────────────
    if _is_kev(row) and risk_score >= 70.0:
        return {
            "cve_id": cve_id,
            "priority_level": "CRITICAL",
            "action_title": "Immediate Remediation Required",
            "recommendation": (
                "Apply the vendor-issued patch immediately. If no patch is available, "
                "isolate affected systems from the network and implement compensating "
                "controls (e.g., firewall rules, disable the affected service). "
                "Monitor for exploitation indicators in logs and SIEM alerts."
                + cwe_hint
            ),
            "rationale": (
                f"{cve_id} is listed in the CISA Known Exploited Vulnerabilities (KEV) "
                "catalogue, confirming active exploitation in the wild, and has a high "
                f"calculated risk score ({risk_score:.0f}/100)."
            ),
            "suggested_sla": "24–48 hours",
            "escalation_required": True,
            "responsible_use_note": _RESPONSIBLE_USE_NOTE,
        }

    # ── Tier 2: Network-reachable + high CVSS ─────────────────────────────────
    if _is_network(row) and base_score >= 7.0:
        escalate = risk_score >= 70.0
        return {
            "cve_id": cve_id,
            "priority_level": "HIGH",
            "action_title": "Patch Externally-Exposed Assets",
            "recommendation": (
                "Identify all internet-facing or network-accessible services running "
                "the affected software version. Prioritise patching for those assets. "
                "Apply network segmentation or temporary firewall rules if patching "
                "cannot be completed within the SLA."
                + cwe_hint
            ),
            "rationale": (
                f"{cve_id} is remotely exploitable (NETWORK attack vector) with a CVSS "
                f"base score of {base_score:.1f}/10. Network-reachable high-CVSS "
                "vulnerabilities have a significantly elevated likelihood of exploitation."
            ),
            "suggested_sla": "72 hours",
            "escalation_required": escalate,
            "responsible_use_note": _RESPONSIBLE_USE_NOTE,
        }

    # ── Tier 3: Unknown / missing data ────────────────────────────────────────
    if _has_unknown_data(row):
        return {
            "cve_id": cve_id,
            "priority_level": "MEDIUM",
            "action_title": "Manual Analyst Review Required",
            "recommendation": (
                "Incomplete CVSS metadata prevents automated prioritisation. "
                "A security analyst should assess this CVE against the affected "
                "asset inventory and available threat intelligence before scheduling "
                "remediation."
                + cwe_hint
            ),
            "rationale": (
                f"{cve_id} has missing or unknown severity, attack-vector, or CVSS "
                "base score data. Automated risk scoring cannot be relied upon."
            ),
            "suggested_sla": "5 business days",
            "escalation_required": False,
            "responsible_use_note": _UNKNOWN_DATA_NOTE,
        }

    # ── Tier 4: Old CVE + elevated risk ───────────────────────────────────────
    if age_days >= 365 and risk_score >= 50.0:
        escalate = risk_score >= 70.0
        years = max(1, int(age_days) // 365)
        return {
            "cve_id": cve_id,
            "priority_level": "HIGH" if risk_score >= 70.0 else "MEDIUM",
            "action_title": "Backlog Escalation — Long-Unpatched Vulnerability",
            "recommendation": (
                "Review the patch management backlog for this vulnerability. "
                "Verify whether affected software versions are still deployed. "
                "Apply available patches and document any exceptions with "
                "approved compensating controls."
                + cwe_hint
            ),
            "rationale": (
                f"{cve_id} has been publicly disclosed for over {years} year(s) "
                f"and still carries a risk score of {risk_score:.0f}/100. "
                "Long-unpatched vulnerabilities indicate a gap in the patch "
                "management cycle."
            ),
            "suggested_sla": "7 days",
            "escalation_required": escalate,
            "responsible_use_note": _RESPONSIBLE_USE_NOTE,
        }

    # ── Tier 5: Low / medium risk — scheduled remediation ─────────────────────
    priority = "MEDIUM" if risk_score >= 30.0 else "LOW"
    return {
        "cve_id": cve_id,
        "priority_level": priority,
        "action_title": "Scheduled Remediation",
        "recommendation": (
            "Add to the standard patch management cycle. Consider compensating "
            "controls (e.g., application-layer firewall rules, privilege restrictions) "
            "if patching cannot be applied within the SLA."
            + cwe_hint
        ),
        "rationale": (
            f"{cve_id} has a calculated risk score of {risk_score:.0f}/100, suggesting "
            "limited immediate exploit potential based on current CVSS characteristics."
        ),
        "suggested_sla": "30 days",
        "escalation_required": False,
        "responsible_use_note": _RESPONSIBLE_USE_NOTE,
    }


def build_recommendations(df: pd.DataFrame) -> pd.DataFrame:
    """Generate mitigation recommendations for every CVE in *df*.

    Parameters
    ----------
    df : pd.DataFrame
        Feature DataFrame produced by
        ``src.features.feature_engineering.build_features``.

    Returns
    -------
    pd.DataFrame
        One row per CVE, sorted by priority_level (CRITICAL first) then
        risk_score descending. Columns: cve_id, priority_level,
        action_title, recommendation, rationale, suggested_sla,
        escalation_required, responsible_use_note.
    """
    _output_columns = [
        "cve_id", "priority_level", "action_title", "recommendation",
        "rationale", "suggested_sla", "escalation_required",
        "responsible_use_note",
    ]
    if df.empty:
        return pd.DataFrame(columns=_output_columns)

    records = [recommend_mitigation(row) for _, row in df.iterrows()]
    result = pd.DataFrame(records)

    _priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    result["_sort_priority"] = result["priority_level"].map(
        lambda p: _priority_order.get(p, 99)
    )
    result["_risk_score"] = (
        df["risk_score"].values if "risk_score" in df.columns else 0.0
    )

    result = (
        result
        .sort_values(["_sort_priority", "_risk_score"], ascending=[True, False])
        .drop(columns=["_sort_priority", "_risk_score"])
        .reset_index(drop=True)
    )

    return result
