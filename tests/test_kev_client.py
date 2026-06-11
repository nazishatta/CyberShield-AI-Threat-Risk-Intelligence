"""
Tests for src/ingestion/kev_client.py.
All HTTP calls are mocked — no real CISA network requests are made.
"""

from __future__ import annotations

import requests
from unittest.mock import MagicMock, patch

import pytest

from src.ingestion.kev_client import (
    CISAKEVError,
    fetch_kev,
    get_kev_catalogue,
    get_kev_cve_ids,
    get_kev_entries,
)


# ── Shared fixture data ───────────────────────────────────────────────────────

_SAMPLE_ENTRIES = [
    {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10",
        "shortDescription": "Apache Log4j2 contains a critical RCE vulnerability.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2021-12-24",
        "notes": "",
    },
    {
        "cveID": "CVE-2021-45046",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-17",
        "shortDescription": "Apache Log4j2 contains a second RCE vulnerability.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2021-12-31",
        "notes": "",
    },
]

_SAMPLE_CATALOGUE = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.06.01",
    "dateReleased": "2024-06-01T00:00:00Z",
    "count": 2,
    "vulnerabilities": _SAMPLE_ENTRIES,
}


def _ok(data: dict) -> MagicMock:
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = data
    m.raise_for_status.return_value = None
    return m


def _err(status: int) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.raise_for_status.side_effect = requests.exceptions.HTTPError(f"HTTP {status}")
    return m


# ── fetch_kev: happy path ─────────────────────────────────────────────────────

@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_returns_dict(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = fetch_kev()
    assert isinstance(result, dict)


@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_vulnerabilities_key_present(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = fetch_kev()
    assert "vulnerabilities" in result


@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_entry_count_correct(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = fetch_kev()
    assert len(result["vulnerabilities"]) == 2


@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_catalogue_metadata_fields(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = fetch_kev()
    assert result["title"] == "CISA Known Exploited Vulnerabilities Catalog"
    assert result["catalogVersion"] == "2024.06.01"
    assert result["dateReleased"] == "2024-06-01T00:00:00Z"
    assert result["count"] == 2


@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_missing_vulnerabilities_key_does_not_raise(mock_get):
    mock_get.return_value = _ok({"title": "CISA KEV", "catalogVersion": "1.0"})
    result = fetch_kev()
    assert result.get("vulnerabilities", []) == []


# ── fetch_kev: HTTP error handling ────────────────────────────────────────────

@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_404_raises_cisa_kev_error(mock_get):
    mock_get.return_value = _err(404)
    with pytest.raises(CISAKEVError, match="404"):
        fetch_kev()


@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_500_raises_cisa_kev_error(mock_get):
    mock_get.return_value = _err(500)
    with pytest.raises(CISAKEVError, match="HTTP 500"):
        fetch_kev()


@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_503_raises_cisa_kev_error(mock_get):
    mock_get.return_value = _err(503)
    with pytest.raises(CISAKEVError):
        fetch_kev()


# ── fetch_kev: network failure handling ──────────────────────────────────────

@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_connection_error_raises_cisa_kev_error(mock_get):
    mock_get.side_effect = requests.exceptions.ConnectionError("refused")
    with pytest.raises(CISAKEVError, match="Could not connect"):
        fetch_kev()


@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_timeout_raises_cisa_kev_error(mock_get):
    mock_get.side_effect = requests.exceptions.Timeout()
    with pytest.raises(CISAKEVError, match="timed out"):
        fetch_kev()


@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_generic_request_exception_raises_cisa_kev_error(mock_get):
    mock_get.side_effect = requests.exceptions.RequestException("unexpected")
    with pytest.raises(CISAKEVError):
        fetch_kev()


@patch("src.ingestion.kev_client.requests.get")
def test_fetch_kev_bad_json_raises_cisa_kev_error(mock_get):
    m = MagicMock()
    m.status_code = 200
    m.raise_for_status.return_value = None
    m.json.side_effect = ValueError("not JSON")
    mock_get.return_value = m
    with pytest.raises(CISAKEVError, match="non-JSON"):
        fetch_kev()


# ── get_kev_cve_ids ───────────────────────────────────────────────────────────

@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_cve_ids_returns_set(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = get_kev_cve_ids()
    assert isinstance(result, set)


@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_cve_ids_contains_expected_ids(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = get_kev_cve_ids()
    assert "CVE-2021-44228" in result
    assert "CVE-2021-45046" in result


@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_cve_ids_length_matches_entries(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = get_kev_cve_ids()
    assert len(result) == 2


@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_cve_ids_empty_on_no_vulnerabilities(mock_get):
    mock_get.return_value = _ok({"title": "CISA KEV", "vulnerabilities": []})
    result = get_kev_cve_ids()
    assert result == set()


@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_cve_ids_skips_entries_without_cve_id_key(mock_get):
    data = {
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "product": "Log4j"},
            {"product": "SomeProduct"},       # missing cveID — should be skipped
            {"cveID": "CVE-2022-0001", "product": "Other"},
        ]
    }
    mock_get.return_value = _ok(data)
    result = get_kev_cve_ids()
    assert result == {"CVE-2021-44228", "CVE-2022-0001"}


# ── get_kev_entries ───────────────────────────────────────────────────────────

@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_entries_returns_list(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = get_kev_entries()
    assert isinstance(result, list)


@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_entries_length_matches_catalogue(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = get_kev_entries()
    assert len(result) == 2


@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_entries_first_item_has_required_fields(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = get_kev_entries()
    first = result[0]
    for field in ("cveID", "vendorProject", "product", "dateAdded", "dueDate"):
        assert field in first, f"Missing expected field: {field}"


@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_entries_empty_list_when_key_missing(mock_get):
    mock_get.return_value = _ok({"title": "CISA KEV"})
    result = get_kev_entries()
    assert result == []


# ── get_kev_catalogue ─────────────────────────────────────────────────────────

@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_catalogue_returns_full_dict(mock_get):
    mock_get.return_value = _ok(_SAMPLE_CATALOGUE)
    result = get_kev_catalogue()
    assert result["catalogVersion"] == "2024.06.01"
    assert result["count"] == 2
    assert len(result["vulnerabilities"]) == 2


@patch("src.ingestion.kev_client.requests.get")
def test_get_kev_catalogue_propagates_cisa_kev_error(mock_get):
    mock_get.side_effect = requests.exceptions.ConnectionError("refused")
    with pytest.raises(CISAKEVError):
        get_kev_catalogue()
