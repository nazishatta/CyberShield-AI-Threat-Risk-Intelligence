"""
Parses raw NVD CVE JSON objects into flat feature dicts suitable for ML.
No data is written to disk — the caller decides what to do with the output.
"""

from __future__ import annotations

from typing import Any


def parse_cve(raw: dict) -> dict[str, Any]:
    """Extract flat features from a single NVD CVE item.

    Handles CVSS v3.1, v3.0, and v2 metrics gracefully.
    Returns safe defaults for every field — never raises on malformed input.
    """
    cve = raw.get("cve", {})
    cve_id = cve.get("id", "")

    # ── CVSS metrics ──────────────────────────────────────────────────────────
    metrics = cve.get("metrics", {})
    cvss_v3 = _get_cvss_v3(metrics)
    cvss_v2 = _get_cvss_v2(metrics)

    cvss_v3_data = cvss_v3.get("cvssData", {})
    cvss_v2_data = cvss_v2.get("cvssData", {})

    # base_score: prefer v3.1/v3.0, fall back to v2
    base_score = cvss_v3_data.get("baseScore") or cvss_v2_data.get("baseScore")

    # severity: v3 stores it inside cvssData; v2 stores it at the metric entry level
    severity = (
        cvss_v3_data.get("baseSeverity")
        or cvss_v2.get("baseSeverity")
        or "UNKNOWN"
    ).upper()

    # attack_vector: v3 = "attackVector", v2 = "accessVector"
    attack_vector = (
        cvss_v3_data.get("attackVector")
        or cvss_v2_data.get("accessVector")
        or "UNKNOWN"
    ).upper()

    # ── Description (English preferred) ──────────────────────────────────────
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    # ── CWE ──────────────────────────────────────────────────────────────────
    weaknesses = cve.get("weaknesses", [])
    cwes = [
        d["value"]
        for w in weaknesses
        for d in w.get("description", [])
        if d.get("lang") == "en"
    ]

    # ── References ───────────────────────────────────────────────────────────
    refs = cve.get("references", [])

    # ── Dates ────────────────────────────────────────────────────────────────
    published = cve.get("published", "")
    last_modified = cve.get("lastModified", "")

    return {
        "cve_id": cve_id,
        "published": published,
        "last_modified": last_modified,
        "base_score": base_score,
        "severity": severity,
        "description": description,
        "cwe": cwes[0] if cwes else "UNKNOWN",
        "ref_count": len(refs),
        "attack_vector": attack_vector,
        "attack_complexity": cvss_v3_data.get("attackComplexity", "UNKNOWN"),
        "privileges_required": cvss_v3_data.get("privilegesRequired", "UNKNOWN"),
        "user_interaction": cvss_v3_data.get("userInteraction", "UNKNOWN"),
        "confidentiality_impact": cvss_v3_data.get("confidentialityImpact", "UNKNOWN"),
        "integrity_impact": cvss_v3_data.get("integrityImpact", "UNKNOWN"),
        "availability_impact": cvss_v3_data.get("availabilityImpact", "UNKNOWN"),
    }


def _get_cvss_v3(metrics: dict) -> dict:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0]
    return {}


def _get_cvss_v2(metrics: dict) -> dict:
    entries = metrics.get("cvssMetricV2", [])
    return entries[0] if entries else {}
