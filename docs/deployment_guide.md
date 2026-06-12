# Deployment Guide

## Purpose

This guide explains how to run CyberShield AI locally (Python) and inside Docker —
for both the **Streamlit dashboard** and the **FastAPI defensive scoring API**.

The project is **API-first and storage-light**: no full CVE datasets are downloaded
or stored. All analysis runs in-memory from live API calls or from values you submit
directly to the API.

---

## Prerequisites

| Tool | Version | Required for |
|---|---|---|
| Python | 3.11+ | Local development |
| pip | Any recent | Local development |
| Docker | 24+ | Containerised deployment |

---

## Local Python setup

```powershell
# 1. Clone the repo
git clone https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence.git
cd CyberShield-AI-Threat-Risk-Intelligence

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows PowerShell
# source .venv/bin/activate    # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Set your NVD API key to remove rate limits
Copy-Item .env.example .env
# Open .env and set:  NVD_API_KEY=your-key-here
```

---

## Running the Streamlit dashboard locally

```powershell
python -m streamlit run src/dashboard/app.py
```

Open: **http://localhost:8501**

---

## Running the FastAPI API locally

```powershell
python -m uvicorn src.api.main:app --reload
```

Open: **http://127.0.0.1:8000/docs** (interactive Swagger UI)

The API scores CVEs and returns defensive mitigation recommendations without making
any upstream NVD or CISA KEV calls. All scoring runs in-memory from the values you
submit in the request body.

---

## Docker

### Build the image

```bash
docker build -t cybershield-ai .
```

The image is based on `python:3.11-slim`. Build time is typically 2–5 minutes on
first run (downloading and installing dependencies). Subsequent builds are fast
because the `pip install` layer is cached.

### Run the Streamlit dashboard

```bash
docker run --rm -p 8501:8501 cybershield-ai
```

Open: **http://localhost:8501**

To pass an NVD API key (removes rate limiting):

```bash
docker run --rm -p 8501:8501 -e NVD_API_KEY=your-key-here cybershield-ai
```

### Run the FastAPI API (command override)

The same image supports FastAPI via a command override — no second Dockerfile needed:

```bash
docker run --rm -p 8000:8000 cybershield-ai \
  python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

Open: **http://localhost:8000/docs**

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `NVD_API_KEY` | Optional | Free NVD API key — removes the 6-second rate limit between pages. Without it the dashboard still works but fetches slowly. |

**`.env` is never copied into the Docker image.** Pass secrets as `-e VAR=value`
flags at `docker run` time, or use Docker secrets / environment injection in your
CI/CD pipeline.

---

## Storage-light policy

CyberShield AI is designed to never download or store full CVE databases:

- `data/raw/`, `data/processed/`, and `data/cache/` are **git-ignored** and
  **excluded from the Docker image** via `.dockerignore`.
- The only data files that belong in the repo are tiny fixture files in
  `data/samples/` (< 10 KB total, used for unit tests only).
- No model binaries (`.pkl`, `.joblib`, `.onnx`, etc.) are committed or copied
  into the image.
- `reports/figures/` screenshots are git-ignored and excluded from the image.

---

## Troubleshooting

### Port already in use

```
Error: address already in use (port 8501 or 8000)
```

Find and stop the conflicting process:

```powershell
# Windows — find what is using port 8501
netstat -ano | findstr :8501
# Then kill by PID:
taskkill /PID <pid> /F
```

Or run the container on a different host port:

```bash
docker run --rm -p 9501:8501 cybershield-ai
```

### API not reachable from host

Make sure you passed `--host 0.0.0.0` in the uvicorn command. The default
`127.0.0.1` binds only inside the container and is not accessible from the host.

### Streamlit ImportError inside Docker

If the container exits with an `ImportError`, the dependency was likely not installed:

```bash
# Rebuild with no cached layers to force a clean pip install
docker build --no-cache -t cybershield-ai .
```

### NVD rate limiting (HTTP 403)

Without an API key, NVD allows 5 requests per 30 seconds. When rate-limited you
will see a warning in the dashboard. Solutions:

1. Get a free API key at https://nvd.nist.gov/developers/request-an-api-key
2. Set `NVD_API_KEY` in your `.env` file (local) or as `-e NVD_API_KEY=...` (Docker)
3. Reduce "Max CVEs" in the sidebar to stay under the rate limit

### Docker build slow or image too large

- The first build downloads all pip packages — this is normal (2–5 min).
- Subsequent builds reuse the cached `pip install` layer if `requirements.txt`
  has not changed.
- If the image is larger than expected, verify that `.dockerignore` is present
  and that the `.venv/` directory is not being copied in.

---

## Security notes

- **Defensive use only.** This project surfaces public vulnerability metadata to
  help defenders prioritise patching. No exploit instructions or attack steps
  are provided by any endpoint or UI component.
- **Never commit `.env`** — it is git-ignored and excluded from the Docker image.
  Pass API keys as environment variables at runtime.
- **Validate before acting.** Risk scores and mitigation recommendations are
  derived from public CVSS metadata. Always verify against your organisation's
  asset inventory and risk tolerance before scheduling remediation.
- **No offensive scanning.** The tool does not probe, scan, or interact with any
  live systems — it only fetches metadata from public government feeds.

See [docs/responsible_use.md](responsible_use.md) for the full policy.

---

## GitHub Actions CI (Milestone 10)

Every push and pull request to `main` runs three automated jobs via
`.github/workflows/python-ci.yml`:

| Job | What it checks |
|---|---|
| **Test (Python 3.11)** | Installs all dependencies from `requirements.txt` and runs `pytest tests/ -v`. All tests use mocks and synthetic data — no real NVD or CISA API calls are made. `NVD_API_KEY` is intentionally not set. |
| **Secret hygiene scan** | Verifies `.env` is not tracked by git. Scans every tracked text file (skipping `.env.example`) for `KEY=<real-value>` patterns that resemble committed secrets. |
| **Dockerfile sanity check** | Confirms `Dockerfile` exists and contains the required base image, ENV vars, port declarations, and layer ordering — without needing Docker installed on the runner. |

### What CI does NOT do

- CI never downloads CVE datasets or calls `nvd.nist.gov` / `cisa.gov`.
- CI never uploads screenshots from `reports/figures/`.
- CI never requires a real `NVD_API_KEY` GitHub secret — the full test suite
  passes with zero network calls.

### Running CI checks locally

To replicate what CI runs before pushing:

```powershell
# Full test suite (matches CI Job 1)
pytest tests/ -v

# Quick secret scan (manual equivalent of CI Job 2)
git ls-files | ForEach-Object {
    if ($_ -ne ".env.example") {
        Select-String -Path $_ -Pattern "(NVD_API_KEY|API_KEY|SECRET|TOKEN)\s*=\s*\S" -SimpleMatch
    }
}
```

---

## Related files

| File | Role |
|---|---|
| `Dockerfile` | Single image supporting both Streamlit (default) and FastAPI (override) |
| `.dockerignore` | Excludes secrets, datasets, model artefacts, screenshots, caches |
| `.github/workflows/python-ci.yml` | GitHub Actions CI — tests, secret scan, Dockerfile check |
| `docs/api.md` | FastAPI endpoint reference with example requests |
| `docs/responsible_use.md` | Ethical use guidelines |
| `requirements.txt` | Pinned Python dependencies |
| `.env.example` | Template for secrets — copy to `.env`, never commit |
