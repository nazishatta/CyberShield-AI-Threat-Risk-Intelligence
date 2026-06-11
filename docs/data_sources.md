# Data Sources

CyberShield AI uses only **live API feeds** — no full datasets are downloaded or stored locally.

---

## 1. NVD CVE 2.0 REST API

| Property | Value |
|---|---|
| Provider | NIST National Vulnerability Database |
| Endpoint | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| Access method | Paginated HTTP GET |
| Auth | Optional free API key (removes rate limit) |
| Rate limit (no key) | 5 requests per 30 seconds |
| Rate limit (with key) | 50 requests per 30 seconds |
| Data format | JSON — CVE items with CVSS metrics, CWEs, references |
| How we use it | Fetch small windows of CVEs (configurable page size, default 100) |

### Getting an API key (free)

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Fill in name + email — key delivered in minutes.
3. Add to `.env`: `NVD_API_KEY=your_key_here`

### Key fields extracted

| NVD field | Our column | Notes |
|---|---|---|
| `cve.id` | `cve_id` | e.g. `CVE-2021-44228` |
| `cvssMetricV31[0].cvssData.baseScore` | `base_score` | CVSS v3.1 preferred; falls back to v2 |
| `cvssData.baseSeverity` | `severity` | CRITICAL / HIGH / MEDIUM / LOW |
| `cvssData.attackVector` | `attack_vector` | NETWORK / ADJACENT / LOCAL / PHYSICAL |
| `weaknesses[0].description[0].value` | `cwe` | e.g. `CWE-78` |
| `references` | `ref_count` | Number of references |
| `published` | `published` | ISO-8601 timestamp |

---

## 2. CISA Known Exploited Vulnerabilities (KEV)

| Property | Value |
|---|---|
| Provider | CISA (Cybersecurity & Infrastructure Security Agency) |
| Endpoint | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| Access method | Single HTTP GET (full catalogue, ~2 MB) |
| Auth | None required |
| Update frequency | Updated by CISA when new exploited CVEs are confirmed |
| How we use it | Load into a Python `set` of CVE IDs; used as exploit label + risk score bonus |

### Why KEV matters

CISA KEV lists CVEs that have been **actively exploited in the wild**.
Being on the KEV list is a strong predictor of real-world threat — far more so than CVSS score alone.
In our model, KEV membership adds 20 points to the rule-based risk score and provides the `exploited=1` label for ML training.

---

## Storage-light NVD ingestion strategy

The NVD provides a bulk data download (a set of large JSON files updated daily).
CyberShield AI deliberately does **not** use those files.
Here is why and how we stay storage-light instead:

### Why we avoid bulk downloads

| Concern | Detail |
|---|---|
| Disk space | The full NVD corpus is hundreds of MB compressed and several GB uncompressed |
| Staleness | A downloaded snapshot is outdated the moment it lands; live API is always current |
| Git hygiene | Large binary/JSON blobs bloat the repository and cannot be diffed meaningfully |
| Reproducibility | A pinned snapshot diverges from the live feed; a live query is always authoritative |

### How pagination keeps requests small

`iter_cves()` in `src/ingestion/nvd_client.py` uses a sliding window:

```
Request 1:  startIndex=0,   resultsPerPage=100  → yields items 0–99
Request 2:  startIndex=100, resultsPerPage=100  → yields items 100–199
...
Stops when: fetched >= max_results  OR  startIndex >= totalResults
```

Key safety mechanisms:

- **`max_results` argument** — the caller decides how many CVEs to fetch (default 100).
- **`max_results_hard_limit`** in `config.yaml` (default 2000) — silently caps any call, even if the caller passes a larger number.
- **Inter-page delay** — 6 s without an API key, 0.6 s with one. Applied only between pages (not before the first request).
- **First-page-free rule** — the delay fires at the top of each iteration after the first, so a single-page query never sleeps at all.

### Query modes

`fetch_cves()` and `iter_cves()` support four mutually composable filters:

| Parameter | NVD API param | Example value |
|---|---|---|
| `keyword` | `keywordSearch` | `"remote code execution"` |
| `cve_id` | `cveId` | `"CVE-2021-44228"` |
| `pub_start_date` | `pubStartDate` | `"2024-01-01T00:00:00.000"` |
| `pub_end_date` | `pubEndDate` | `"2024-12-31T23:59:59.000"` |

### Error classes

| Exception | When raised |
|---|---|
| `NVDRateLimitError` | HTTP 403 — slow down or add `NVD_API_KEY` to `.env` |
| `NVDAPIError` | Any other HTTP error, network failure, or malformed JSON response |

`NVDRateLimitError` is a subclass of `NVDAPIError`, so `except NVDAPIError` catches both.

---

## Data storage policy

| Location | Git-tracked | Purpose |
|---|---|---|
| `data/samples/` | Yes | Tiny fixture files for offline tests (< 10 KB each) |
| `data/raw/` | **No** (git-ignored) | Would hold raw API dumps — leave empty |
| `data/processed/` | **No** (git-ignored) | Would hold processed DataFrames — leave empty |
| `data/cache/` | **No** (git-ignored) | Would hold HTTP response caches — leave empty |

**The project is designed to work with no files in `data/raw/` or `data/processed/`.**
All data is fetched live at runtime.

---

## Future sources (planned)

| Source | Milestone | What it adds |
|---|---|---|
| Exploit-DB / ExploitDB API | M3 | Public exploit code availability |
| Shodan InternetDB | M3 | Exposed service counts per CVE technology |
| MITRE ATT&CK STIX | M4 | Tactic/technique mapping for CVEs |
