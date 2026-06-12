# CyberShield AI — Threat Prediction & Cyber Risk Intelligence Platform

[![Python CI](https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence/actions/workflows/python-ci.yml/badge.svg)](https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence/actions/workflows/python-ci.yml)

> API-first · storage-light · beginner-friendly · production-grade structure

CyberShield AI fetches vulnerability intelligence **live** from the NVD CVE API and the CISA Known Exploited Vulnerabilities (KEV) catalogue, scores each CVE with a risk model, and surfaces the results in an interactive Streamlit dashboard.
No full dataset is ever downloaded locally.

---

## Architecture overview

```
NVD API  ──► src/ingestion/nvd_client.py  ─┐
                                             ├─► src/features/ ─► src/models/ ─► src/recommendations/ ─► src/dashboard/
CISA KEV ──► src/ingestion/kev_client.py  ─┘
```

| Layer | What it does |
|---|---|
| **Ingestion** | Paginated live API calls — never stores raw data |
| **Features** | Parses CVE JSON → flat feature dict → Pandas DataFrame |
| **Models** | Rule-based scorer + scikit-learn baseline classifier (LogisticRegression / RandomForest) |
| **Recommendations** | Tier-based defensive mitigation guidance (CRITICAL/HIGH/MEDIUM/LOW priority) |
| **API** | FastAPI REST service — `/score` and `/recommend` endpoints, Pydantic validation |
| **Dashboard** | Streamlit app with live query, metrics, charts, and recommendations |

---

## Milestones

| # | Name | Status |
|---|---|---|
| 0 | Repo scaffold, config, CI, dashboard skeleton | ✅ Done |
| 1 | Repo hardening — docs, .gitignore, architecture guide | ✅ Done |
| 2 | Production NVD CVE ingestion — keyword, CVE ID, date range, pagination, error handling | ✅ Done |
| 3 | Production CISA KEV ingestion — typed exceptions, full entry metadata, dashboard date filters | ✅ Done |
| 4 | Feature engineering — normalized columns, age_days, severity/AV encoding, KEV flag, risk score | ✅ Done |
| 5 | Baseline ML classifier (scikit-learn) — high_risk label, LogisticRegression / RandomForest, F1 metrics | ✅ Done |
| 6 | Model evaluation & explainability — confusion matrix, class balance, permutation importance, misleading-accuracy detection | ✅ Done |
| 6.5 | ML performance hardening — balanced class weights (RF + LR), threshold sweep, recommended threshold (F1 / Recall), confusion matrix at chosen threshold | ✅ Done |
| 7 | Defensive mitigation recommendation layer — priority tiers, SLA guidance, CWE-aware remediation | ✅ Done |
| 8 | FastAPI defensive scoring API — /health, /version, /score, /recommend | ✅ Done |
| 9 | Docker and deployment hardening — Dockerfile, .dockerignore, deployment guide | ✅ Done |
| 10 | GitHub Actions CI/CD hardening — workflow, secret hygiene, Dockerfile check | ✅ Done |
| 11 | CVSS trend analysis & time-series plots | Planned |

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
│   ├── recommendations/    # Defensive mitigation guidance
│   ├── api/                # FastAPI REST API (M8)
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
| [docs/modeling.md](docs/modeling.md) | Baseline ML classifier — features, evaluation metrics, class imbalance, feature importance, limitations |
| [docs/api.md](docs/api.md) | FastAPI REST API — endpoints, request/response schemas, PowerShell examples |
| [docs/deployment_guide.md](docs/deployment_guide.md) | Docker build/run commands, local setup, troubleshooting, security notes |
| [docs/mitigation_guidance.md](docs/mitigation_guidance.md) | Defensive mitigation layer — priority tiers, CWE guidance, SLA recommendations |
| [docs/responsible_use.md](docs/responsible_use.md) | Ethical use, model disclaimer, API guidelines |
| [.github/workflows/python-ci.yml](.github/workflows/python-ci.yml) | GitHub Actions CI — test runner, secret hygiene, Dockerfile check |

---

## API usage (Milestone 8)

The FastAPI defensive scoring API runs alongside the dashboard and requires no dataset downloads.

### Start the API server

```powershell
python -m uvicorn src.api.main:app --reload
```

Interactive docs open at **http://127.0.0.1:8000/docs**

### Score a CVE (PowerShell)

```powershell
$body = @{
    cve_id        = "CVE-2024-12345"
    severity      = "HIGH"
    base_score    = 8.5
    attack_vector = "NETWORK"
    cwe           = "CWE-89"
    published     = "2023-06-01T00:00:00.000"
    in_kev        = $false
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/score" `
                  -Method POST `
                  -ContentType "application/json" `
                  -Body $body
```

### Get a mitigation recommendation (PowerShell)

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/recommend" `
                  -Method POST `
                  -ContentType "application/json" `
                  -Body $body
```

Full endpoint documentation: [docs/api.md](docs/api.md)

---

## Docker (Milestone 9)

### Build

```bash
docker build -t cybershield-ai .
```

### Run the Streamlit dashboard

```bash
docker run --rm -p 8501:8501 cybershield-ai
```

Open: **http://localhost:8501**

### Run the FastAPI API

```bash
docker run --rm -p 8000:8000 cybershield-ai \
  python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

Open: **http://localhost:8000/docs**

### Pass your NVD API key (optional)

```bash
docker run --rm -p 8501:8501 -e NVD_API_KEY=your-key-here cybershield-ai
```

Full deployment documentation: [docs/deployment_guide.md](docs/deployment_guide.md)

---

## CI/CD (Milestone 10)

GitHub Actions runs automatically on every push and pull request to `main`.

### What the pipeline checks

| Job | Description |
|---|---|
| **Test (Python 3.11)** | Installs dependencies and runs `pytest tests/ -v` — no real API calls, no dataset downloads |
| **Secret hygiene scan** | Verifies `.env` is not committed; scans tracked files for `KEY=<real-value>` patterns |
| **Dockerfile sanity check** | Confirms base image, ENV vars, port declarations, and layer order are correct |

Workflow file: [.github/workflows/python-ci.yml](.github/workflows/python-ci.yml)

Full details: [docs/deployment_guide.md](docs/deployment_guide.md)

---

## Security notes

- **Never commit `.env`** — it is git-ignored.
- API keys are read from environment variables via `python-dotenv`.
- `data/raw/` and `data/processed/` are git-ignored.
- The CI workflow includes a basic secret scan on `.env.example`.

---

## License

[MIT](LICENSE)
