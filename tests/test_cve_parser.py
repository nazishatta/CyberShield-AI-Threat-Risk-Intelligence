"""Unit tests for the CVE parser — no network calls required."""

import pytest
from src.features.cve_parser import parse_cve

_MOCK_CVE = {
    "cve": {
        "id": "CVE-2024-12345",
        "published": "2024-01-15T10:00:00.000",
        "lastModified": "2024-01-20T12:00:00.000",
        "descriptions": [{"lang": "en", "value": "A critical RCE vulnerability."}],
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "HIGH",
                    "availabilityImpact": "HIGH",
                }
            }]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-78"}]}],
        "references": [{"url": "https://example.com"}],
    }
}


def test_parse_cve_id():
    result = parse_cve(_MOCK_CVE)
    assert result["cve_id"] == "CVE-2024-12345"


def test_parse_base_score():
    result = parse_cve(_MOCK_CVE)
    assert result["base_score"] == 9.8


def test_parse_severity():
    result = parse_cve(_MOCK_CVE)
    assert result["severity"] == "CRITICAL"


def test_parse_attack_vector():
    result = parse_cve(_MOCK_CVE)
    assert result["attack_vector"] == "NETWORK"


def test_parse_cwe():
    result = parse_cve(_MOCK_CVE)
    assert result["cwe"] == "CWE-78"


def test_parse_empty_record():
    result = parse_cve({})
    assert result["cve_id"] == ""
    assert result["severity"] == "UNKNOWN"
