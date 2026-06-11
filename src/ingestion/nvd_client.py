"""
Thin client for the NVD CVE 2.0 REST API.
Fetches data in small paginated windows — never downloads a full local dump.
"""

import os
import time
from typing import Generator

import requests
from loguru import logger

from src.utils.config import load_config

_cfg = load_config()
_NVD_CFG = _cfg["nvd"]


def _headers() -> dict:
    key = os.getenv("NVD_API_KEY", "")
    return {"apiKey": key} if key else {}


def _delay() -> float:
    return (
        _NVD_CFG["request_delay_keyed_s"]
        if os.getenv("NVD_API_KEY")
        else _NVD_CFG["request_delay_s"]
    )


def fetch_cves(
    keyword: str = "",
    start_index: int = 0,
    results_per_page: int | None = None,
) -> dict:
    """Return one page of CVE results from the NVD API."""
    page_size = results_per_page or _NVD_CFG["page_size"]
    params: dict = {"startIndex": start_index, "resultsPerPage": page_size}
    if keyword:
        params["keywordSearch"] = keyword

    resp = requests.get(
        _NVD_CFG["base_url"],
        headers=_headers(),
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def iter_cves(keyword: str = "", max_results: int = 500) -> Generator[dict, None, None]:
    """Yield individual CVE items up to *max_results*, paging automatically."""
    page_size = min(_NVD_CFG["page_size"], max_results)
    start = 0
    fetched = 0

    while fetched < max_results:
        logger.info(f"Fetching CVEs: startIndex={start}, pageSize={page_size}")
        data = fetch_cves(keyword=keyword, start_index=start, results_per_page=page_size)
        items = data.get("vulnerabilities", [])
        if not items:
            break
        for item in items:
            yield item
            fetched += 1
            if fetched >= max_results:
                break
        start += len(items)
        if start >= data.get("totalResults", 0):
            break
        time.sleep(_delay())
