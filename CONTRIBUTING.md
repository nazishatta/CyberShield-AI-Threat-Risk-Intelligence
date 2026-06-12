# Contributing to CyberShield AI

Thank you for your interest in contributing. This is a **defensive cybersecurity AI** project — it helps security teams prioritise patching and understand CVE risk exposure using publicly available data. All contributions must stay within that defensive scope.

---

## Project purpose

CyberShield AI fetches live vulnerability intelligence from the NVD CVE API and the CISA Known Exploited Vulnerabilities (KEV) catalogue, scores each CVE with a rule-based and ML risk model, and surfaces recommendations in a Streamlit dashboard and a FastAPI REST API.

It is:
- **API-first** — no full datasets are downloaded or stored locally.
- **Storage-light** — only tiny fixture files (< 10 KB) are git-tracked.
- **Defensive** — every output is oriented toward defenders prioritising patching.
- **Beginner-friendly** — clear structure, documented architecture, pinned dependencies.

---

## Defensive-use policy

By contributing to this project you agree that all submitted code, documentation, data, and configuration:

1. Does **not** include exploit code, proof-of-concept attack scripts, or step-by-step instructions for exploiting any vulnerability.
2. Does **not** include offensive scanning capabilities (port scanning, fuzzing, active enumeration).
3. Does **not** include real API keys, passwords, tokens, or personal data.
4. Does **not** download or bundle full CVE datasets or any large dataset locally.
5. Is consistent with the **defensive, educational, and analytical** purpose of this project.

Any pull request that violates these principles will be closed without merge.

---

## Development setup

### Prerequisites

- Python 3.11+
- `git`
- (Optional) Docker 24+ for container testing

### Steps

```powershell
# 1. Fork and clone the repository
git clone https://github.com/<your-username>/CyberShield-AI-Threat-Risk-Intelligence.git
cd CyberShield-AI-Threat-Risk-Intelligence

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1       # Windows PowerShell
# source .venv/bin/activate        # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables (optional — only needed for dashboard)
Copy-Item .env.example .env
# Open .env and set NVD_API_KEY if you have one (free at nvd.nist.gov)
```

---

## Running the tests

All tests are synthetic and make **no real network calls**.

```powershell
# Run the full suite
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=src --cov-report=term-missing

# Run a specific test file
pytest tests/test_api.py -v
```

Tests must pass before a pull request will be reviewed.

---

## Running the application locally

```powershell
# Streamlit dashboard
python -m streamlit run src/dashboard/app.py

# FastAPI scoring API
python -m uvicorn src.api.main:app --reload
# Interactive docs: http://127.0.0.1:8000/docs
```

---

## Branch naming suggestions

| Type | Example |
|---|---|
| Bug fix | `fix/nvd-pagination-edge-case` |
| New feature | `feature/cve-age-histogram` |
| Documentation | `docs/update-api-reference` |
| Refactor | `refactor/feature-engineering-cleanup` |
| CI / tooling | `ci/add-ruff-linting` |

Work from `main` as the base branch. Open pull requests against `main`.

---

## Pull request checklist

Before opening a PR, confirm:

- [ ] `pytest tests/ -v` passes locally with no failures.
- [ ] No real credentials, API keys, or `.env` file is committed.
- [ ] No full datasets (`data/raw/`, `data/processed/`, `data/cache/`) are added.
- [ ] No screenshot files are added to `reports/figures/` (git-ignored).
- [ ] No exploit instructions, attack steps, or offensive scanning code is included.
- [ ] Documentation is updated to reflect any new behaviour.
- [ ] CI is expected to pass (push to your fork branch and check Actions before opening the PR).

---

## What not to add

The following are **out of scope** for this project and will not be merged:

| Category | Examples |
|---|---|
| Exploit content | PoC scripts, shellcode, attack payloads |
| Offensive tooling | Port scanners, fuzzers, credential stuffers |
| Large data ingestion | Full NVD bulk feeds, CSV dataset downloads |
| Heavy ML frameworks | RAG pipelines, LangChain, vector databases, LLM agents |
| Model serialisation | Saving `.pkl` / `.joblib` files to the repository |
| Secrets | API keys, tokens, passwords in any tracked file |

---

## Code style

- Python 3.11 syntax.
- Follow the conventions already used in the codebase (snake_case, type hints where practical).
- Keep functions small and well-named — avoid multi-paragraph docstrings; a single clear function name is better.
- No comments that restate what the code does. Only add comments where the *why* is non-obvious.

---

## Questions and discussions

Open a [GitHub Issue](https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence/issues) with the `question` label. Please read the existing documentation before asking — [docs/project_architecture.md](docs/project_architecture.md) and [docs/responsible_use.md](docs/responsible_use.md) cover most design decisions.

---

## License

By contributing you agree your work is licensed under the [MIT License](LICENSE) that covers this project.
