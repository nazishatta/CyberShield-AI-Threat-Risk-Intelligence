"""
Fetches the CISA Known Exploited Vulnerabilities (KEV) catalogue live.
The full JSON is ~2 MB — loaded into memory, never written to disk.
"""

import requests
from loguru import logger

from src.utils.config import load_config

_cfg = load_config()
_KEV_URL = _cfg["cisa_kev"]["url"]


def fetch_kev() -> dict:
    """Return the full KEV catalogue as a dict (live HTTP request)."""
    logger.info(f"Fetching CISA KEV from {_KEV_URL}")
    resp = requests.get(_KEV_URL, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_kev_cve_ids() -> set[str]:
    """Return the set of CVE IDs present in the KEV catalogue."""
    data = fetch_kev()
    return {v["cveID"] for v in data.get("vulnerabilities", [])}
