"""
CISA Known Exploited Vulnerabilities (KEV) catalogue client.

Fetches the catalogue live via a single HTTP GET — nothing is written to disk.
The full JSON is ~2 MB and is held entirely in memory.
"""

from __future__ import annotations

import requests
from loguru import logger

from src.utils.config import load_config


# ── Custom exception ──────────────────────────────────────────────────────────

class CISAKEVError(Exception):
    """Raised for any failure when fetching or parsing the CISA KEV catalogue."""


# ── Internal helper ───────────────────────────────────────────────────────────

def _kev_url() -> str:
    return load_config()["cisa_kev"]["url"]


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_kev() -> dict:
    """Fetch the full CISA KEV catalogue and return it as a dict.

    The JSON is ~2 MB and is processed entirely in memory — nothing is written
    to disk.  All callers in this module delegate to this function so the HTTP
    layer is mocked in a single place during testing.

    Returns
    -------
    dict
        Full catalogue including ``title``, ``catalogVersion``,
        ``dateReleased``, ``count``, and the ``vulnerabilities`` list.

    Raises
    ------
    CISAKEVError
        For any HTTP error, network failure, or malformed JSON response.
    """
    url = _kev_url()
    logger.info(f"Fetching CISA KEV catalogue from {url}")

    try:
        resp = requests.get(url, timeout=30)
    except requests.exceptions.ConnectionError as exc:
        raise CISAKEVError(f"Could not connect to CISA KEV endpoint: {exc}") from exc
    except requests.exceptions.Timeout:
        raise CISAKEVError("CISA KEV request timed out after 30 s")
    except requests.exceptions.RequestException as exc:
        raise CISAKEVError(f"CISA KEV request failed: {exc}") from exc

    if resp.status_code == 404:
        raise CISAKEVError(
            "CISA KEV endpoint returned 404 — the URL may have changed. "
            "Check config.yaml → cisa_kev.url."
        )

    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError as exc:
        raise CISAKEVError(
            f"CISA KEV endpoint returned HTTP {resp.status_code}: {exc}"
        ) from exc

    try:
        data = resp.json()
    except ValueError as exc:
        raise CISAKEVError("CISA KEV endpoint returned a non-JSON response") from exc

    n = len(data.get("vulnerabilities", []))
    logger.info(
        f"KEV catalogue loaded: {n:,} entries "
        f"(version {data.get('catalogVersion', 'unknown')})"
    )
    return data


def get_kev_cve_ids() -> set[str]:
    """Return the set of CVE IDs present in the CISA KEV catalogue.

    Derived from a live HTTP fetch — no local file is read.
    Entries missing the ``cveID`` key are silently skipped.

    Raises
    ------
    CISAKEVError
        Propagated from :func:`fetch_kev` on any fetch failure.
    """
    data = fetch_kev()
    return {
        entry["cveID"]
        for entry in data.get("vulnerabilities", [])
        if "cveID" in entry
    }


def get_kev_entries() -> list[dict]:
    """Return the full list of KEV entry dicts from the catalogue.

    Each entry typically contains: ``cveID``, ``vendorProject``, ``product``,
    ``vulnerabilityName``, ``dateAdded``, ``shortDescription``,
    ``requiredAction``, ``dueDate``, ``notes``.

    Raises
    ------
    CISAKEVError
        Propagated from :func:`fetch_kev` on any fetch failure.
    """
    data = fetch_kev()
    return data.get("vulnerabilities", [])


def get_kev_catalogue() -> dict:
    """Return the full catalogue dict including top-level metadata fields.

    Top-level fields: ``title``, ``catalogVersion``, ``dateReleased``,
    ``count``, ``vulnerabilities``.

    Raises
    ------
    CISAKEVError
        Propagated from :func:`fetch_kev` on any fetch failure.
    """
    return fetch_kev()
