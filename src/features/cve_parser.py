"""
Parses raw NVD CVE JSON objects into flat feature dicts suitable for ML.
No data is written to disk here — caller decides what to do with the output.
"""

from __future__ import annotations

from typing import Any


def parse_cve(raw: dict) -> dict[str, Any]:
    """Extract flat features from a single NVD CVE item."""
    cve = raw.get("cve", {})
    cve_id = cve.get("id", "")

    # CVSS scores
    metrics = cve.get("metrics", {})
    cvss_v3 = _get_cvss_v3(metrics)
    cvss_v2 = _get_cvss_v2(metrics)

    base_score = cvss_v3.get("cvssData", {}).get("baseScore") or \
                 cvss_v2.get("cvssData", {}).get("baseScore")
    severity = (
        cvss_v3.get("cvssData", {}).get("baseSeverity") or
        cvss_v2.get("baseSeverity") or
        "UNKNOWN"
    ).upper()

    # Description (English preferred)
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    # CWE
    weaknesses = cve.get("weaknesses", [])
    cwes = [
        d["value"]
        for w in weaknesses
        for d in w.get("description", [])
        if d.get("lang") == "en"
    ]

    # References
    refs = cve.get("references", [])
    ref_count = len(refs)

    # Published / modified dates
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
        "ref_count": ref_count,
        "attack_vector": cvss_v3.get("cvssData", {}).get("attackVector", "UNKNOWN"),
        "attack_complexity": cvss_v3.get("cvssData", {}).get("attackComplexity", "UNKNOWN"),
        "privileges_required": cvss_v3.get("cvssData", {}).get("privilegesRequired", "UNKNOWN"),
        "user_interaction": cvss_v3.get("cvssData", {}).get("userInteraction", "UNKNOWN"),
        "confidentiality_impact": cvss_v3.get("cvssData", {}).get("confidentialityImpact", "UNKNOWN"),
        "integrity_impact": cvss_v3.get("cvssData", {}).get("integrityImpact", "UNKNOWN"),
        "availability_impact": cvss_v3.get("cvssData", {}).get("availabilityImpact", "UNKNOWN"),
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
