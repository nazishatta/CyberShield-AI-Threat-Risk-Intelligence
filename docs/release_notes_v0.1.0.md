# Release Notes — v0.1.0

**Release date:** 2026-06-11
**Branch:** `main`
**Status:** Initial public release

---

## Release summary

CyberShield AI v0.1.0 is the first complete release of the platform. It delivers
a full defensive CVE risk intelligence pipeline — from live API ingestion through
ML-assisted scoring, tier-based mitigation recommendations, a Streamlit dashboard,
a FastAPI REST API, Docker deployment, GitHub Actions CI, and a polished open-source
repository structure.

The platform is **API-first and storage-light**: no full CVE database is ever
downloaded or stored locally. All analysis runs in-memory from live API calls
or from values submitted directly to the REST API.

This is a **defensive security tool**. It helps security teams prioritise patching
and understand risk exposure. It does not provide exploit instructions, attack steps,
or offensive capabilities of any kind.

---

## Major capabilities

### Live CVE ingestion
- Fetches CVEs live from the [NVD CVE 2.0 API](https://nvd.nist.gov/developers/vulnerabilities) by keyword, CVE ID, or date range.
- Supports paginated queries with configurable page size and rate-limit handling.
- Fetches CISA [Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalogue for KEV membership checks.
- Zero datasets stored locally — all raw data is in-memory only.

### Feature engineering and risk scoring
- Parses CVSS v3.1, v3.0, and v2 fields from NVD JSON with fallback logic.
- Produces a normalised Pandas DataFrame with: `severity_numeric`, `attack_vector_numeric`, `age_days`, `in_kev`, `kev_numeric`, `risk_score`.
- Rule-based 0–100 risk score weighting CVSS severity, attack vector, KEV membership, and vulnerability age.

### Machine learning classifier
- scikit-learn baseline classifier (LogisticRegression / RandomForest, configurable).
- Target label: `high_risk` = `risk_score ≥ 70`.
- Balanced class weights to handle CVE dataset imbalance.
- F1, precision, recall, ROC-AUC, confusion matrix, and permutation feature importance.
- Optimal decision threshold identified via F1/Recall sweep.
- Model trained on-the-fly; no binary is saved to disk by default.

### Defensive mitigation recommendations
- Five-tier priority engine: **CRITICAL**, **HIGH**, **MEDIUM**, **LOW**, plus manual-review tier for unknown data.
- SLA guidance: 24–48 h (CRITICAL) → 30 days (LOW).
- CWE-aware defensive guidance covering the most common 10 weakness types.
- No exploit content — all guidance is oriented toward defensive actions (patch, isolate, apply compensating controls).

### Streamlit dashboard
- Live query controls: keyword search, CVE ID lookup, date range, max CVEs.
- Risk metrics, severity distribution chart, risk score histogram.
- ML classifier results with feature importance.
- "🛡️ Defensive Recommendations" panel with per-CVE expandable detail.

### FastAPI REST API
- `GET /health` — liveness check and defensive-use note.
- `GET /version` — project name, API version, storage policy.
- `POST /score` — risk score and normalised features for a single CVE input.
- `POST /recommend` — full tier-based defensive recommendation for a single CVE input.
- Pydantic validation: `base_score` validated 0.0–10.0; HTTP 422 on bad input.
- Interactive Swagger docs at `/docs`.

---

## How to run

### Prerequisites

- Python 3.11+
- (Optional) Docker 24+
- (Optional) NVD API key (free at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key)) to remove rate limits

### Local setup

```powershell
git clone https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence.git
cd CyberShield-AI-Threat-Risk-Intelligence

python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows
# source .venv/bin/activate    # macOS / Linux

pip install -r requirements.txt

Copy-Item .env.example .env    # then set NVD_API_KEY if you have one
```

### Run the Streamlit dashboard

```powershell
python -m streamlit run src/dashboard/app.py
```

Open: **http://localhost:8501**

### Run the FastAPI scoring API

```powershell
python -m uvicorn src.api.main:app --reload
```

Open: **http://127.0.0.1:8000/docs**

### Run the test suite

```powershell
pytest tests/ -v
```

All 327+ tests pass with no real network calls and no dataset downloads.

---

## Docker

```bash
# Build the image
docker build -t cybershield-ai .

# Run the Streamlit dashboard
docker run --rm -p 8501:8501 cybershield-ai

# Run the FastAPI API (command override — same image)
docker run --rm -p 8000:8000 cybershield-ai \
  python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Pass NVD API key (optional)
docker run --rm -p 8501:8501 -e NVD_API_KEY=your-key-here cybershield-ai
```

Full deployment guide: [docs/deployment_guide.md](deployment_guide.md)

---

## Known limitations

| Limitation | Detail |
|---|---|
| ML model trained on synthetic data | The classifier is trained on NVD samples fetched at query time. It has not been evaluated on a large held-out benchmark. Risk scores should be used as prioritisation signals, not certified assessments. |
| NVD rate limiting | Without an API key, NVD allows 5 requests per 30 seconds. Large queries will be slow. Get a free key at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key). |
| CVSS v2-only CVEs | Very old CVEs may only have CVSS v2 scores. The parser falls back gracefully, but v2 and v3 scores are not directly comparable. |
| No real-time KEV updates | KEV membership is checked at query time via a live HTTP fetch. The catalogue is updated by CISA regularly; there is no cache or local copy. |
| `sentence-transformers` dependency | Listed in `requirements.txt` for potential future NLP use. It pulls in PyTorch and makes `pip install` slow (~2–3 min first time). Not actively used in v0.1.0. |
| Windows-first run scripts | `run_app.ps1` is PowerShell-only. macOS/Linux users should use the manual `python -m streamlit run` command. |
| No authentication on the FastAPI API | The API is designed for local/internal use. Do not expose it on a public network without adding authentication. |

---

## Responsible use

CyberShield AI surfaces **publicly available government vulnerability data** to help
defenders prioritise their patching workload.

- Risk scores and recommendations are **estimates** based on public CVSS metadata — not certified security assessments.
- Always verify recommendations against your organisation's asset inventory, patch management process, and risk tolerance before acting.
- Do **not** use this tool to automate offensive security operations.
- Do **not** use API output as the sole basis for compliance, audit, or incident response decisions.

Full policy: [docs/responsible_use.md](responsible_use.md)

---

## Documentation

| Doc | Contents |
|---|---|
| [project_architecture.md](project_architecture.md) | Layer diagram, data flow, configuration guide |
| [data_sources.md](data_sources.md) | NVD and CISA KEV API details, field mapping |
| [modeling.md](modeling.md) | ML classifier, evaluation metrics, feature importance |
| [api.md](api.md) | FastAPI endpoints, request/response schemas, examples |
| [deployment_guide.md](deployment_guide.md) | Docker, local setup, CI, troubleshooting |
| [mitigation_guidance.md](mitigation_guidance.md) | Priority tier logic, CWE guidance, SLA table |
| [responsible_use.md](responsible_use.md) | Ethical use policy and API guidelines |
| [roadmap.md](roadmap.md) | Completed milestones, future plans, excluded scope |

---

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for the full milestone-by-milestone history.
