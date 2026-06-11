# CyberShield AI — Threat Prediction & Cyber Risk Intelligence Platform

> API-first · storage-light · beginner-friendly · production-grade structure

CyberShield AI fetches vulnerability intelligence **live** from the NVD CVE API and the CISA Known Exploited Vulnerabilities (KEV) catalogue, scores each CVE with a risk model, and surfaces the results in an interactive Streamlit dashboard.
No full dataset is ever downloaded locally.

---

## Architecture overview

```
NVD API  ──► src/ingestion/nvd_client.py  ─┐
                                             ├─► src/features/ ─► src/models/ ─► src/dashboard/
CISA KEV ──► src/ingestion/kev_client.py  ─┘
```

| Layer | What it does |
|---|---|
| **Ingestion** | Paginated live API calls — never stores raw data |
| **Features** | Parses CVE JSON → flat feature dict → Pandas DataFrame |
| **Models** | Rule-based scorer (M0) → XGBoost classifier (M2) |
| **Dashboard** | Streamlit app with live query, metrics, and charts |

---

## Milestones

| # | Name | Status |
|---|---|---|
| 0 | Repo scaffold, config, CI, dashboard skeleton | ✅ Done |
| 1 | Repo hardening — docs, .gitignore, architecture guide | ✅ Done |
| 2 | Production NVD CVE ingestion — keyword, CVE ID, date range, pagination, error handling | ✅ Done |
| 3 | Production CISA KEV ingestion — typed exceptions, full entry metadata, dashboard date filters | ✅ Done |
| 4 | Feature engineering — normalized columns, age_days, severity/AV encoding, KEV flag, risk score | ✅ Done |
| 5 | ML exploit-likelihood classifier (XGBoost) | 🔜 Next |
| 5 | NLP description embeddings (sentence-transformers) | Planned |
| 6 | CVSS trend analysis & time-series plots | Planned |
| 7 | Docker deployment + GitHub Actions full CI/CD | Planned |

---

## Quick start

### 1 — Clone & create a virtual environment

```powershell
git clone https://github.com/<your-username>/CyberShield-AI-Threat-Risk-Intelligence.git
cd CyberShield-AI-Threat-Risk-Intelligence
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2 — Configure environment variables

```powershell
Copy-Item .env.example .env
# Open .env and add your NVD_API_KEY (optional but removes rate-limit)
```

### 3 — Run the dashboard

```powershell
.\run_app.ps1
```

Or manually:

```powershell
streamlit run src\dashboard\app.py
```

### 4 — Run tests

```powershell
pytest tests/ -v --cov=src
```

---

## Project structure

```
CyberShield-AI-Threat-Risk-Intelligence/
├── src/
│   ├── ingestion/          # NVD + KEV live API clients
│   ├── features/           # CVE parser + feature engineering
│   ├── models/             # Risk scorer + ML classifier
│   ├── dashboard/          # Streamlit app
│   └── utils/              # Config loader, logger
├── data/
│   └── samples/            # Tiny fixture files only — git-tracked (< 10 KB)
│   # data/raw/, data/processed/, data/cache/ are git-IGNORED
├── docs/
│   ├── project_architecture.md   # Layer diagram + data flow
│   ├── data_sources.md           # NVD & CISA KEV API details
│   └── responsible_use.md        # Ethical use guidelines
├── reports/
│   └── figures/            # Generated plots (git-ignored except .gitkeep)
├── notebooks/              # Exploratory Jupyter notebooks
├── tests/                  # Pytest unit tests (no network required)
├── .github/workflows/      # GitHub Actions CI
├── config.yaml             # All tunable parameters
├── .env.example            # Template — copy to .env, never commit .env
├── requirements.txt
├── Dockerfile
├── .dockerignore
├── LICENSE
└── run_app.ps1             # One-command launch (Windows)
```

> **Storage policy:** `data/raw/`, `data/processed/`, `data/cache/`, and `reports/figures/` are all git-ignored.
> The project runs entirely from live API calls — **no dataset is ever downloaded locally**.

---

## Data sources

| Source | URL | How accessed |
|---|---|---|
| NVD CVE 2.0 API | https://nvd.nist.gov/developers/vulnerabilities | Live paginated HTTP |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Live JSON fetch |

Full details including field mapping and API key setup: [docs/data_sources.md](docs/data_sources.md)

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/project_architecture.md](docs/project_architecture.md) | Layer diagram, data flow, how to add a new source |
| [docs/data_sources.md](docs/data_sources.md) | NVD + CISA KEV API details, field mapping, storage policy |
| [docs/responsible_use.md](docs/responsible_use.md) | Ethical use, model disclaimer, API guidelines |

---

## Security notes

- **Never commit `.env`** — it is git-ignored.
- API keys are read from environment variables via `python-dotenv`.
- `data/raw/` and `data/processed/` are git-ignored.
- The CI workflow includes a basic secret scan on `.env.example`.

---

## License

[MIT](LICENSE)
