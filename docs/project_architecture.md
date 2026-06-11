# Project Architecture

## Design principle

CyberShield AI is **API-first and storage-light**.
It never downloads a full vulnerability dataset to disk.
Every analysis run fetches the minimal data needed via HTTP and processes it in memory.

---

## Layer diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        External APIs                             │
│   NVD CVE 2.0 REST API          CISA KEV JSON feed              │
└────────────────┬─────────────────────────┬───────────────────────┘
                 │  paginated HTTP          │  single HTTP GET
                 ▼                          ▼
┌──────────────────────────────────────────────────────────────────┐
│                    src/ingestion/                                │
│   nvd_client.py  — iter_cves(), fetch_cves()                     │
│   kev_client.py  — fetch_kev(), get_kev_cve_ids()                │
└─────────────────────────────┬────────────────────────────────────┘
                              │  raw dicts (in memory)
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                    src/features/                                 │
│   cve_parser.py        — NVD JSON → flat feature dict            │
│                           (CVSS v3.1 / v3.0 / v2 fallback)      │
│   feature_engineering.py — list[dict] + kev_ids                 │
│                           → normalized DataFrame                 │
│                           (severity_numeric, attack_vector_      │
│                            numeric, age_days, in_kev,            │
│                            kev_numeric, risk_score)              │
└─────────────────────────────┬────────────────────────────────────┘
                              │  normalized DataFrame
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                    src/models/                                   │
│   risk_scorer.py   — rule-based 0-100 score (Milestone 0)        │
│   classifier.py    — scikit-learn baseline classifier (M5)        │
│                       LogisticRegression / RandomForest            │
│                       target: high_risk = risk_score ≥ 70         │
└─────────────────────────────┬────────────────────────────────────┘
                              │  scored DataFrame
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                    src/recommendations/                          │
│   mitigation.py  — recommend_mitigation() / build_recommendations│
│                    tier-based priority: CRITICAL/HIGH/MEDIUM/LOW │
│                    CWE-aware defensive guidance (no exploits)    │
└─────────────────────────────┬────────────────────────────────────┘
                              │  recommendations DataFrame
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                    src/dashboard/                                │
│   app.py  — Streamlit UI: query controls, metrics, charts        │
└──────────────────────────────────────────────────────────────────┘

                    ── also consumed by ──

┌──────────────────────────────────────────────────────────────────┐
│                    src/api/                                      │
│   main.py — FastAPI REST API (M8)                                │
│   GET  /health   GET  /version                                   │
│   POST /score    POST /recommend                                 │
│   Defensive scoring only — no exploit content                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Key files

| File | Role |
|---|---|
| `src/ingestion/nvd_client.py` | Paginated NVD API client; respects rate limits |
| `src/ingestion/kev_client.py` | Live CISA KEV fetch; returns a set of CVE IDs |
| `src/features/cve_parser.py` | Extracts CVSS scores, CWE, attack vectors from raw NVD JSON (v3.1/v3.0/v2) |
| `src/features/feature_engineering.py` | Normalizes parsed dicts → DataFrame with ordinal encodings, age_days, KEV flag, risk score |
| `src/models/risk_scorer.py` | Rule-based 0–100 risk score (called by feature_engineering) |
| `src/models/classifier.py` | scikit-learn baseline classifier — LogisticRegression or RandomForest, trained on-the-fly, never saved to disk by default |
| `src/recommendations/mitigation.py` | Tier-based defensive remediation recommendations — no exploit content |
| `src/api/main.py` | FastAPI REST API — `/health`, `/version`, `/score`, `/recommend`; defensive only |
| `src/dashboard/app.py` | Streamlit entry point |
| `src/utils/config.py` | Loads `config.yaml`; cached after first call |
| `src/utils/logger.py` | Loguru setup (stderr only, no log files written to Git) |
| `config.yaml` | All tuneable parameters — page size, delays, model settings |

---

## Configuration flow

```
.env  ──► python-dotenv ──► os.getenv()
                                │
config.yaml ──► src/utils/config.py (lru_cache) ──► every module
```

`config.yaml` controls all tunable values.
Environment variables (from `.env`) provide secrets and runtime overrides.

---

## Data flow — what is and is NOT stored

| Stage | In memory | Written to disk |
|---|---|---|
| Raw NVD API response | Yes | Never |
| Parsed CVE feature dicts | Yes | Never |
| Feature DataFrame | Yes | Never (unless user explicitly exports) |
| Risk scores | Yes | Never |
| CISA KEV IDs | Yes (set) | Never |
| Sample fixtures | `data/samples/` only | Git-tracked |
| Trained model | In-process | Never by default |

`data/raw/`, `data/processed/`, and `data/cache/` are **git-ignored** and should remain empty in production.

---

## Adding a new data source

1. Create `src/ingestion/<source>_client.py` with a `fetch_*()` function.
2. Add the source URL to `config.yaml`.
3. Wire parsing into `src/features/cve_parser.py` or a new parser file.
4. Add a unit test in `tests/` that mocks the HTTP call.
