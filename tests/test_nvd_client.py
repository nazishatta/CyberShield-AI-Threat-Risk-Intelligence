"""
Tests for src/ingestion/nvd_client.py.
All HTTP calls are mocked — no real NVD API requests are made.
"""

from __future__ import annotations

import requests
from unittest.mock import MagicMock, patch

import pytest

from src.ingestion.nvd_client import (
    NVDAPIError,
    NVDRateLimitError,
    _hard_limit,
    fetch_cve_by_id,
    fetch_cves,
    iter_cves,
)

_HARD_LIMIT = _hard_limit()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _nvd_page(cve_ids: list[str], total: int | None = None) -> dict:
    """Build a minimal NVD-shaped page response."""
    vulns = [{"cve": {"id": cid}} for cid in cve_ids]
    return {
        "vulnerabilities": vulns,
        "totalResults": total if total is not None else len(vulns),
        "resultsPerPage": len(vulns),
        "startIndex": 0,
    }


def _ok(data: dict) -> MagicMock:
    """Mock a successful requests.Response."""
    m = MagicMock()
    m.status_code = 200
    m.json.return_value = data
    m.raise_for_status.return_value = None
    return m


def _err(status: int) -> MagicMock:
    """Mock an error requests.Response with raise_for_status wired up."""
    m = MagicMock()
    m.status_code = status
    m.raise_for_status.side_effect = requests.exceptions.HTTPError(f"HTTP {status}")
    return m


# ── fetch_cves: happy path ────────────────────────────────────────────────────

@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_returns_vulnerabilities_key(mock_get):
    mock_get.return_value = _ok(_nvd_page(["CVE-2024-0001"]))
    result = fetch_cves(keyword="test")
    assert "vulnerabilities" in result
    assert result["vulnerabilities"][0]["cve"]["id"] == "CVE-2024-0001"


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_keyword_forwarded_as_keywordSearch(mock_get):
    mock_get.return_value = _ok(_nvd_page([]))
    fetch_cves(keyword="log4j")
    params = mock_get.call_args.kwargs["params"]
    assert params["keywordSearch"] == "log4j"


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_cve_id_forwarded(mock_get):
    mock_get.return_value = _ok(_nvd_page(["CVE-2021-44228"]))
    fetch_cves(cve_id="CVE-2021-44228")
    params = mock_get.call_args.kwargs["params"]
    assert params["cveId"] == "CVE-2021-44228"


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_date_range_forwarded(mock_get):
    mock_get.return_value = _ok(_nvd_page([]))
    fetch_cves(
        pub_start_date="2024-01-01T00:00:00.000",
        pub_end_date="2024-06-30T23:59:59.000",
    )
    params = mock_get.call_args.kwargs["params"]
    assert params["pubStartDate"] == "2024-01-01T00:00:00.000"
    assert params["pubEndDate"] == "2024-06-30T23:59:59.000"


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_omits_empty_optional_params(mock_get):
    mock_get.return_value = _ok(_nvd_page([]))
    fetch_cves()
    params = mock_get.call_args.kwargs["params"]
    assert "keywordSearch" not in params
    assert "cveId" not in params
    assert "pubStartDate" not in params
    assert "pubEndDate" not in params


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_start_index_in_params(mock_get):
    mock_get.return_value = _ok(_nvd_page([]))
    fetch_cves(start_index=200)
    params = mock_get.call_args.kwargs["params"]
    assert params["startIndex"] == 200


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_results_per_page_in_params(mock_get):
    mock_get.return_value = _ok(_nvd_page([]))
    fetch_cves(results_per_page=50)
    params = mock_get.call_args.kwargs["params"]
    assert params["resultsPerPage"] == 50


# ── fetch_cves: HTTP error handling ──────────────────────────────────────────

@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_403_raises_rate_limit_error(mock_get):
    mock_get.return_value = _err(403)
    with pytest.raises(NVDRateLimitError):
        fetch_cves()


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_rate_limit_error_is_subclass_of_api_error(mock_get):
    mock_get.return_value = _err(403)
    with pytest.raises(NVDAPIError):
        fetch_cves()


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_404_returns_empty_result(mock_get):
    mock_get.return_value = _err(404)
    result = fetch_cves(cve_id="CVE-9999-0000")
    assert result["vulnerabilities"] == []
    assert result["totalResults"] == 0


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_500_raises_api_error(mock_get):
    mock_get.return_value = _err(500)
    with pytest.raises(NVDAPIError, match="HTTP 500"):
        fetch_cves()


# ── fetch_cves: network failure handling ─────────────────────────────────────

@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_connection_error_raises_api_error(mock_get):
    mock_get.side_effect = requests.exceptions.ConnectionError("refused")
    with pytest.raises(NVDAPIError, match="Could not connect"):
        fetch_cves()


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_timeout_raises_api_error(mock_get):
    mock_get.side_effect = requests.exceptions.Timeout()
    with pytest.raises(NVDAPIError, match="timed out"):
        fetch_cves()


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cves_bad_json_raises_api_error(mock_get):
    m = MagicMock()
    m.status_code = 200
    m.raise_for_status.return_value = None
    m.json.side_effect = ValueError("not JSON")
    mock_get.return_value = m
    with pytest.raises(NVDAPIError, match="non-JSON"):
        fetch_cves()


# ── fetch_cve_by_id ───────────────────────────────────────────────────────────

@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cve_by_id_returns_item(mock_get):
    mock_get.return_value = _ok(_nvd_page(["CVE-2021-44228"]))
    result = fetch_cve_by_id("CVE-2021-44228")
    assert result is not None
    assert result["cve"]["id"] == "CVE-2021-44228"


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cve_by_id_not_found_returns_none(mock_get):
    mock_get.return_value = _ok(_nvd_page([]))
    result = fetch_cve_by_id("CVE-9999-0000")
    assert result is None


@patch("src.ingestion.nvd_client.requests.get")
def test_fetch_cve_by_id_passes_cve_id_param(mock_get):
    mock_get.return_value = _ok(_nvd_page(["CVE-2021-44228"]))
    fetch_cve_by_id("CVE-2021-44228")
    params = mock_get.call_args.kwargs["params"]
    assert params["cveId"] == "CVE-2021-44228"


# ── iter_cves: single page ────────────────────────────────────────────────────

@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_yields_all_items_single_page(mock_get, mock_sleep):
    ids = [f"CVE-2024-{i:04d}" for i in range(5)]
    mock_get.return_value = _ok(_nvd_page(ids, total=5))
    result = list(iter_cves(keyword="test", max_results=10))
    assert len(result) == 5


@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_no_sleep_on_single_page(mock_get, mock_sleep):
    ids = [f"CVE-2024-{i:04d}" for i in range(3)]
    mock_get.return_value = _ok(_nvd_page(ids, total=3))
    list(iter_cves(keyword="test", max_results=10))
    mock_sleep.assert_not_called()


@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_empty_response_yields_nothing(mock_get, mock_sleep):
    mock_get.return_value = _ok(_nvd_page([], total=0))
    result = list(iter_cves(keyword="nothing", max_results=50))
    assert result == []


# ── iter_cves: max_results cap ────────────────────────────────────────────────

@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_respects_max_results(mock_get, mock_sleep):
    ids = [f"CVE-2024-{i:04d}" for i in range(50)]
    mock_get.return_value = _ok(_nvd_page(ids, total=50))
    result = list(iter_cves(keyword="test", max_results=10))
    assert len(result) == 10


@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_hard_limit_caps_oversized_request(mock_get, mock_sleep):
    ids = [f"CVE-2024-{i:04d}" for i in range(_HARD_LIMIT + 10)]
    mock_get.return_value = _ok(_nvd_page(ids, total=_HARD_LIMIT + 10))
    result = list(iter_cves(keyword="test", max_results=_HARD_LIMIT + 999))
    assert len(result) <= _HARD_LIMIT


# ── iter_cves: pagination ─────────────────────────────────────────────────────

@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_paginates_across_two_pages(mock_get, mock_sleep):
    page1_ids = [f"CVE-2024-{i:04d}" for i in range(3)]
    page2_ids = [f"CVE-2024-{i:04d}" for i in range(3, 6)]

    page1 = _nvd_page(page1_ids, total=6)
    page1["resultsPerPage"] = 3
    page2 = _nvd_page(page2_ids, total=6)

    mock_get.side_effect = [_ok(page1), _ok(page2)]

    result = list(iter_cves(keyword="test", max_results=6))
    assert len(result) == 6


@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_sleeps_between_pages_not_before_first(mock_get, mock_sleep):
    page1_ids = [f"CVE-2024-{i:04d}" for i in range(3)]
    page2_ids = [f"CVE-2024-{i:04d}" for i in range(3, 6)]

    page1 = _nvd_page(page1_ids, total=6)
    page1["resultsPerPage"] = 3
    page2 = _nvd_page(page2_ids, total=6)

    mock_get.side_effect = [_ok(page1), _ok(page2)]
    list(iter_cves(keyword="test", max_results=6))
    assert mock_sleep.call_count == 1


@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_second_page_uses_correct_start_index(mock_get, mock_sleep):
    page1_ids = [f"CVE-2024-{i:04d}" for i in range(3)]
    page2_ids = [f"CVE-2024-{i:04d}" for i in range(3, 6)]

    page1 = _nvd_page(page1_ids, total=6)
    page1["resultsPerPage"] = 3
    page2 = _nvd_page(page2_ids, total=6)

    mock_get.side_effect = [_ok(page1), _ok(page2)]
    list(iter_cves(keyword="test", max_results=6))

    second_call_params = mock_get.call_args_list[1].kwargs["params"]
    assert second_call_params["startIndex"] == 3


# ── iter_cves: filter forwarding ─────────────────────────────────────────────

@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_forwards_date_range(mock_get, mock_sleep):
    mock_get.return_value = _ok(_nvd_page([], total=0))
    list(iter_cves(
        pub_start_date="2024-01-01T00:00:00.000",
        pub_end_date="2024-12-31T23:59:59.000",
        max_results=10,
    ))
    params = mock_get.call_args.kwargs["params"]
    assert params["pubStartDate"] == "2024-01-01T00:00:00.000"
    assert params["pubEndDate"] == "2024-12-31T23:59:59.000"


@patch("src.ingestion.nvd_client.time.sleep")
@patch("src.ingestion.nvd_client.requests.get")
def test_iter_cves_forwards_cve_id(mock_get, mock_sleep):
    mock_get.return_value = _ok(_nvd_page(["CVE-2021-44228"], total=1))
    result = list(iter_cves(cve_id="CVE-2021-44228", max_results=5))
    params = mock_get.call_args.kwargs["params"]
    assert params["cveId"] == "CVE-2021-44228"
    assert len(result) == 1
