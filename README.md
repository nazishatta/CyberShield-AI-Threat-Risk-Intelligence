# CyberShield AI — Defensive CVE Risk Intelligence Platform

[![Python CI](https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence/actions/workflows/python-ci.yml/badge.svg)](https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence/actions/workflows/python-ci.yml)

> API-first · storage-light · defensive CVE risk intelligence · 415 tests · Python 3.11

CyberShield AI is a **defensive CVE risk intelligence platform** built with **Streamlit**, **FastAPI**, **scikit-learn**, **Docker**, and **GitHub Actions**. It fetches vulnerability intelligence **live** from the NVD CVE API and the CISA Known Exploited Vulnerabilities (KEV) catalogue, scores each CVE with a rule-based and ML risk model, and surfaces defensive mitigation recommendations — all without downloading or storing any dataset locally.

**Defensive use only.** This tool helps security teams prioritise patching and understand risk exposure. It provides no exploit instructions, offensive scanning capabilities, or attack guidance of any kind.

---

## Project status

**v0.1.0 — Initial release.** All core milestones complete.

| Component | Status |
|---|---|
| NVD + CISA KEV live ingestion | ✅ Production-ready |
| Feature engineering + risk scorer | ✅ Production-ready |
| ML baseline classifier | ✅ Functional (synthetic training data) |
| Defensive mitigation recommendations | ✅ Production-ready |
| FastAPI REST API | ✅ Production-ready |
| Streamlit dashboard | ✅ Production-ready |
| Docker deployment | ✅ Production-ready |
| GitHub Actions CI | ✅ Active |
| Test suite | ✅ 415 tests · zero network calls |

---

## What this project is not

- It does **not** provide exploit code, PoC scripts, or attack instructions.
- It does **not** scan, probe, or interact with live systems.
- It does **not** download or store full CVE databases locally.
- It does **not** include RAG pipelines, LangChain, vector databases, or LLM agents.
- It does **not** replace professional security assessment — outputs are prioritisation signals that require human review.

---

## Architecture overview

```
NVD API  ──► src/ingestion/nvd_client.py  ─┐
                                             ├─► src/features/ ─► src/models/ ─► src/recommendations/ ─┬─► src/dashboard/
CISA KEV ──► src/ingestion/kev_client.py  ─┘                                                           └─► src/api/
```

| Layer | What it does |
|---|---|
| **Ingestion** | Paginated live API calls — never stores raw data |
| **Features** | Parses CVE JSON → flat feature dict → Pandas DataFrame |
| **Models** | Rule-based scorer + scikit-learn baseline classifier (LogisticRegression / RandomForest) |
| **Recommendations** | Tier-based defensive mitigation guidance (CRITICAL / HIGH / MEDIUM / LOW priority) |
| **API** | FastAPI REST service — `/score` and `/recommend` endpoints, Pydantic validation |
| **Dashboard** | Streamlit app with live query, metrics, charts, and defensive recommendations |

---

## Milestones

| # | Name | Status |
|---|---|---|
| 0 | Repo scaffold, config, CI, dashboard skeleton | ✅ Done |
| 1 | Repo hardening — docs, .gitignore, architecture guide | ✅ Done |
| 2 | Production NVD CVE ingestion — keyword, CVE ID, date range, pagination, error handling | ✅ Done |
| 3 | Production CISA KEV ingestion — typed exceptions, full entry metadata, dashboard date filters | ✅ Done |
| 4 | Feature engineering — normalised columns, age_days, severity/AV encoding, KEV flag, risk score | ✅ Done |
| 5 | Baseline ML classifier — high_risk label, LogisticRegression / RandomForest, F1 metrics | ✅ Done |
| 6 | Model evaluation & explainability — confusion matrix, class balance, permutation importance | ✅ Done |
| 6.5 | ML performance hardening — balanced class weights, threshold sweep, recommended threshold | ✅ Done |
| 7 | Defensive mitigation recommendation layer — priority tiers, SLA guidance, CWE-aware remediation | ✅ Done |
| 8 | FastAPI defensive scoring API — /health, /version, /score, /recommend | ✅ Done |
| 9 | Docker and deployment hardening — Dockerfile, .dockerignore, deployment guide | ✅ Done |
| 10 | GitHub Actions CI/CD hardening — workflow, secret hygiene, Dockerfile check | ✅ Done |
| 11 | Repository polish — governance files, issue templates, PR template, release notes | ✅ Done |
| 12 | CVSS trend analysis & time-series plots | Planned |

---

## Quick start

### 1 — Clone and create a virtual environment

```powershell
git clone https://github.com/<your-username>/CyberShield-AI-Threat-Risk-Intelligence.git
cd CyberShield-AI-Threat-Risk-Intelligence
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # Windows PowerShell
# source .venv/bin/activate         # macOS / Linux
pip install -r requirements.txt
```

### 2 — Configure environment variables

```powershell
Copy-Item .env.example .env
# Open .env and set NVD_API_KEY (optional — removes rate limiting)
```

### 3 — Run the Streamlit dashboard

```powershell
python -m streamlit run src/dashboard/app.py
```

Open: **http://localhost:8501**

Or use the one-command launcher (Windows):

```powershell
.\run_app.ps1
```

### 4 — Run the FastAPI scoring API

```powershell
python -m uvicorn src.api.main:app --reload
```

Open: **http://127.0.0.1:8000/docs**

### 5 — Run tests

```powershell
pytest tests/ -v
```

All 415 tests pass with no real network calls and no dataset downloads.

---

## Repository map

```
CyberShield-AI-Threat-Risk-Intelligence/
│
├── src/
│   ├── ingestion/          # Live API clients
│   │   ├── nvd_client.py   #   NVD CVE 2.0 — paginated fetch, rate-limit handling
│   │   └── kev_client.py   #   CISA KEV — single fetch, O(1) CVE ID lookup
│   ├── features/           # Feature engineering
│   │   ├── cve_parser.py   #   NVD JSON → flat feature dict (CVSS v3.1/v3.0/v2 fallback)
│   │   └── feature_engineering.py  #   list[dict] + KEV IDs → normalised DataFrame
│   ├── models/             # Risk scoring and ML
│   │   ├── risk_scorer.py  #   Rule-based 0–100 risk score
│   │   ├── classifier.py   #   scikit-learn LogisticRegression / RandomForest
│   │   └── evaluation.py   #   Confusion matrix, threshold sweep, feature importance
│   ├── recommendations/    # Defensive mitigation layer
│   │   └── mitigation.py   #   5-tier priority engine (CRITICAL/HIGH/MEDIUM/LOW)
│   ├── api/                # FastAPI REST service
│   │   └── main.py         #   /health  /version  /score  /recommend
│   ├── dashboard/          # Streamlit app
│   │   └── app.py          #   Live query UI, metrics, charts, recommendations
│   └── utils/              # Shared utilities
│       ├── config.py       #   config.yaml loader (lru_cache)
│       └── logger.py       #   Loguru setup
│
├── tests/                  # Pytest test suite (no network calls required)
│   ├── test_nvd_client.py
│   ├── test_kev_client.py
│   ├── test_cve_parser.py
│   ├── test_feature_engineering.py
│   ├── test_risk_scorer.py
│   ├── test_classifier.py
│   ├── test_evaluation.py
│   ├── test_mitigation.py
│   ├── test_api.py
│   ├── test_deployment_docs.py
│   ├── test_ci_config.py
│   ├── test_repo_polish.py
│   └── test_final_docs_polish.py
│
├── docs/
│   ├── project_architecture.md   # Layer diagram, data flow, configuration
│   ├── data_sources.md           # NVD + CISA KEV API details, field mapping
│   ├── modeling.md               # ML classifier, evaluation metrics, threshold tuning
│   ├── api.md                    # FastAPI endpoint reference, PowerShell examples
│   ├── deployment_guide.md       # Docker, local setup, CI, troubleshooting
│   ├── mitigation_guidance.md    # Priority tier logic, CWE guidance, SLA table
│   ├── responsible_use.md        # Ethical use policy, model disclaimer
│   ├── roadmap.md                # Completed milestones, future plans, excluded scope
│   ├── release_notes_v0.1.0.md   # v0.1.0 capabilities, limitations
│   └── final_review_checklist.md # Pre-release quality checklist
│
├── data/
│   └── samples/            # Tiny fixture files for offline tests (< 10 KB, git-tracked)
│   # data/raw/, data/processed/, data/cache/ are git-IGNORED — leave empty
│
├── .github/
│   ├── workflows/
│   │   └── python-ci.yml   # CI: test runner · secret hygiene · Dockerfile check
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── feature_request.md
│   │   └── documentation_update.md
│   └── pull_request_template.md
│
├── reports/figures/        # Generated plots — git-ignored (only .gitkeep tracked)
├── notebooks/              # Exploratory Jupyter notebooks
├── config.yaml             # All tunable parameters
├── .env.example            # Secrets template — copy to .env, never commit .env
├── requirements.txt        # Pinned Python dependencies
├── Dockerfile              # python:3.11-slim — supports Streamlit and FastAPI
├── .dockerignore
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
├── LICENSE
└── run_app.ps1             # One-command Streamlit launcher (Windows)
```

> **Storage policy:** `data/raw/`, `data/processed/`, `data/cache/`, and `reports/figures/` are all git-ignored.
> The project runs entirely from live API calls — **no full dataset is ever downloaded locally**.

---

## Data sources

| Source | URL | How accessed |
|---|---|---|
| NVD CVE 2.0 API | https://nvd.nist.gov/developers/vulnerabilities | Live paginated HTTP |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Live JSON fetch |

Full details including field mapping, rate limits, and storage design: [docs/data_sources.md](docs/data_sources.md)

---

## Documentation

| Doc | Contents |
|---|---|
| [docs/project_architecture.md](docs/project_architecture.md) | Layer diagram, data flow, configuration guide, how to add a new source |
| [docs/data_sources.md](docs/data_sources.md) | NVD + CISA KEV API details, field mapping, storage-light design |
| [docs/modeling.md](docs/modeling.md) | ML classifier — features, evaluation metrics, threshold tuning, class imbalance, limitations |
| [docs/api.md](docs/api.md) | FastAPI REST API — endpoints, request/response schemas, PowerShell examples |
| [docs/deployment_guide.md](docs/deployment_guide.md) | Docker build/run, local setup, GitHub Actions CI, troubleshooting |
| [docs/mitigation_guidance.md](docs/mitigation_guidance.md) | Defensive mitigation layer — priority tiers, CWE guidance, SLA table |
| [docs/responsible_use.md](docs/responsible_use.md) | Ethical use policy, model output disclaimer, API guidelines |
| [docs/roadmap.md](docs/roadmap.md) | Completed milestones, future plans, explicitly excluded scope |
| [docs/release_notes_v0.1.0.md](docs/release_notes_v0.1.0.md) | v0.1.0 release summary, capabilities, known limitations |

### Governance

| File | Contents |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup guide, defensive-use policy, PR checklist, out-of-scope table |
| [SECURITY.md](SECURITY.md) | Responsible disclosure policy, private reporting instructions |
| [CHANGELOG.md](CHANGELOG.md) | Milestone-by-milestone change history |

---

## API usage

The FastAPI defensive scoring API exposes the same risk scoring and mitigation logic as the dashboard via JSON REST endpoints. It makes no upstream API calls and downloads no data.

### Start the API server

```powershell
python -m uvicorn src.api.main:app --reload
```

Interactive Swagger docs: **http://127.0.0.1:8000/docs**

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

### Get a defensive mitigation recommendation (PowerShell)

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/recommend" `
                  -Method POST `
                  -ContentType "application/json" `
                  -Body $body
```

Full endpoint reference: [docs/api.md](docs/api.md)

---

## Docker

### Build

```bash
docker build -t cybershield-ai .
```

### Run the Streamlit dashboard

```bash
docker run --rm -p 8501:8501 cybershield-ai
```

Open: **http://localhost:8501**

### Run the FastAPI API (command override — same image)

```bash
docker run --rm -p 8000:8000 cybershield-ai \
  python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

Open: **http://localhost:8000/docs**

### Pass your NVD API key (optional)

```bash
docker run --rm -p 8501:8501 -e NVD_API_KEY=your-key-here cybershield-ai
```

Full deployment guide: [docs/deployment_guide.md](docs/deployment_guide.md)

---

## CI/CD

GitHub Actions runs automatically on every push and pull request to `main`.

| Job | What it checks |
|---|---|
| **Test (Python 3.11)** | `pytest tests/ -v` — no real API calls, no dataset downloads, `NVD_API_KEY` intentionally unset |
| **Secret hygiene scan** | Verifies `.env` is not committed; scans tracked files for `KEY=<real-value>` patterns |
| **Dockerfile sanity check** | Validates base image, ENV vars, port declarations, and layer order — no Docker daemon needed |

Workflow: [.github/workflows/python-ci.yml](.github/workflows/python-ci.yml)

---

## Security notes

- **Never commit `.env`** — it is git-ignored. Use `.env.example` as the template.
- API keys are read from environment variables via `python-dotenv`.
- `data/raw/` and `data/processed/` are git-ignored and excluded from the Docker image.
- The CI pipeline runs an automated secret hygiene scan on every push.
- To report a security vulnerability privately: [SECURITY.md](SECURITY.md).

---

## Contributing

Contributions are welcome for defensive features, documentation improvements, and test coverage. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the setup guide, coding guidelines, and PR checklist before opening a pull request.

Bug reports and feature requests: [GitHub Issues](https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence/issues)

Security vulnerabilities: see [SECURITY.md](SECURITY.md) — do not report them through public issues.

---

## Release notes

[v0.1.0 release notes](docs/release_notes_v0.1.0.md) — capabilities, run instructions, known limitations.

[Full changelog](CHANGELOG.md) — milestone-by-milestone history.

---

## License

[MIT](LICENSE)
