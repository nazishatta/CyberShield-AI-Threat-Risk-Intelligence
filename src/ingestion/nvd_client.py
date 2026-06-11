"""
NVD CVE 2.0 REST API client.

Storage-light: fetches only small paginated windows — never downloads a full dump.
Supports keyword search, exact CVE ID lookup, and publication date ranges.
"""

from __future__ import annotations

import os
import time
from typing import Generator

import requests
from loguru import logger

from src.utils.config import load_config

# Fallback hard cap if config key is missing — prevents accidental bulk downloads.
_HARD_LIMIT_FALLBACK = 2_000


# ── Custom exceptions ─────────────────────────────────────────────────────────

class NVDAPIError(Exception):
    """Raised for any NVD API failure (network, non-2xx, bad JSON)."""


class NVDRateLimitError(NVDAPIError):
    """Raised when NVD returns HTTP 403 (rate limit exceeded)."""


# ── Internal helpers ──────────────────────────────────────────────────────────

def _nvd_cfg() -> dict:
    return load_config()["nvd"]


def _headers() -> dict:
    key = os.getenv("NVD_API_KEY", "").strip()
    return {"apiKey": key} if key else {}


def _inter_page_delay() -> float:
    cfg = _nvd_cfg()
    return (
        cfg["request_delay_keyed_s"]
        if os.getenv("NVD_API_KEY", "").strip()
        else cfg["request_delay_s"]
    )


def _hard_limit() -> int:
    return int(_nvd_cfg().get("max_results_hard_limit", _HARD_LIMIT_FALLBACK))


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_cves(
    *,
    keyword: str = "",
    cve_id: str = "",
    pub_start_date: str = "",
    pub_end_date: str = "",
    start_index: int = 0,
    results_per_page: int | None = None,
) -> dict:
    """Fetch one page of CVE results from the NVD CVE 2.0 API.

    Parameters
    ----------
    keyword:
        Free-text keyword search (NVD ``keywordSearch`` param).
    cve_id:
        Exact CVE ID lookup, e.g. ``"CVE-2021-44228"``.
    pub_start_date:
        ISO-8601 start of publication window, e.g. ``"2024-01-01T00:00:00.000"``.
    pub_end_date:
        ISO-8601 end of publication window.
    start_index:
        Zero-based page offset for pagination.
    results_per_page:
        Page size; defaults to ``config.yaml nvd.page_size``.

    Returns
    -------
    dict
        Raw NVD API JSON response.

    Raises
    ------
    NVDRateLimitError
        HTTP 403 — slow down or add an API key.
    NVDAPIError
        Any other non-2xx response, network failure, or malformed JSON.
    """
    cfg = _nvd_cfg()
    page_size = min(
        results_per_page if results_per_page is not None else cfg["page_size"],
        _hard_limit(),
    )

    params: dict[str, str | int] = {
        "startIndex": start_index,
        "resultsPerPage": page_size,
    }
    if keyword:
        params["keywordSearch"] = keyword
    if cve_id:
        params["cveId"] = cve_id
    if pub_start_date:
        params["pubStartDate"] = pub_start_date
    if pub_end_date:
        params["pubEndDate"] = pub_end_date

    try:
        resp = requests.get(
            cfg["base_url"],
            headers=_headers(),
            params=params,
            timeout=30,
        )
    except requests.exceptions.ConnectionError as exc:
        raise NVDAPIError(f"Could not connect to NVD API: {exc}") from exc
    except requests.exceptions.Timeout:
        raise NVDAPIError("NVD API request timed out after 30 s")
    except requests.exceptions.RequestException as exc:
        raise NVDAPIError(f"NVD API request failed: {exc}") from exc

    if resp.status_code == 403:
        raise NVDRateLimitError(
            "NVD API rate limit hit (HTTP 403). "
            "Add NVD_API_KEY to .env or increase request_delay_s in config.yaml."
        )
    if resp.status_code == 404:
        return {"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 0}

    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        raise NVDAPIError(f"NVD API returned HTTP {resp.status_code}: {exc}") from exc

    try:
        return resp.json()
    except ValueError as exc:
        raise NVDAPIError("NVD API returned a non-JSON response") from exc


def fetch_cve_by_id(cve_id: str) -> dict | None:
    """Look up a single CVE by exact ID.

    Returns the CVE item dict, or ``None`` if no matching CVE was found.
    """
    logger.info(f"Looking up {cve_id}")
    data = fetch_cves(cve_id=cve_id, results_per_page=1)
    vulns = data.get("vulnerabilities", [])
    return vulns[0] if vulns else None


def iter_cves(
    *,
    keyword: str = "",
    cve_id: str = "",
    pub_start_date: str = "",
    pub_end_date: str = "",
    max_results: int = 100,
) -> Generator[dict, None, None]:
    """Yield individual CVE items, auto-paging until *max_results* is reached.

    The first page is fetched immediately; subsequent pages wait for the
    configured inter-page delay before the HTTP call to respect NVD rate limits.
    Never fetches more than ``max_results_hard_limit`` items regardless of the
    *max_results* argument.

    Parameters
    ----------
    keyword:
        Free-text keyword search.
    cve_id:
        Exact CVE ID (yields at most one result).
    pub_start_date / pub_end_date:
        ISO-8601 publication date window.
    max_results:
        Maximum number of CVEs to yield. Hard-capped at
        ``config.yaml nvd.max_results_hard_limit``.

    Yields
    ------
    dict
        A single NVD CVE item (the wrapper object from the ``vulnerabilities``
        array, not the inner ``cve`` dict).
    """
    effective_max = min(max_results, _hard_limit())
    cfg = _nvd_cfg()
    page_size = min(cfg["page_size"], effective_max)

    start = 0
    fetched = 0
    first_page = True

    while fetched < effective_max:
        if not first_page:
            time.sleep(_inter_page_delay())
        first_page = False

        logger.info(
            f"NVD fetch | startIndex={start} pageSize={page_size} "
            f"fetched={fetched}/{effective_max}"
        )

        data = fetch_cves(
            keyword=keyword,
            cve_id=cve_id,
            pub_start_date=pub_start_date,
            pub_end_date=pub_end_date,
            start_index=start,
            results_per_page=page_size,
        )

        items = data.get("vulnerabilities", [])
        if not items:
            break

        for item in items:
            yield item
            fetched += 1
            if fetched >= effective_max:
                return

        start += len(items)
        if start >= data.get("totalResults", 0):
            break
