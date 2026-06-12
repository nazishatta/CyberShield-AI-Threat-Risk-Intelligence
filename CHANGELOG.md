# Changelog

All notable changes to CyberShield AI are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses milestone-based versioning during its initial development phase.

> **Storage policy:** No full CVE datasets are ever downloaded, committed, or stored locally.
> The project is API-first — every analysis run fetches the minimum data needed via live HTTP calls.
>
> **Defensive use:** All features are oriented toward helping defenders prioritise patching and
> understand risk exposure. No exploit instructions, attack steps, or offensive capabilities
> are included in any release.

---

## [v0.1.0] — Initial Release

> Covers Milestones 0 through 11.

### Summary

First public release of CyberShield AI: a defensive cybersecurity intelligence platform
that fetches live CVE data from the NVD API and CISA KEV catalogue, scores risk,
generates defensive mitigation recommendations, and exposes a FastAPI REST API —
all without downloading or storing any full dataset locally.

---

### Added — Milestone 0: Repository scaffold

- Initial project layout: `src/`, `tests/`, `docs/`, `data/samples/`, `reports/figures/`.
- `config.yaml` for all tunable parameters.
- `.env.example` template for secrets.
- `run_app.ps1` one-command Windows launcher.
- Streamlit dashboard skeleton.
- Basic `pytest` test harness.

---

### Added — Milestone 1: Repository hardening

- `.gitignore` covering datasets, model artefacts, secrets, and OS noise.
- `docs/project_architecture.md` — layered ASCII diagram, data flow, configuration guide.
- `docs/data_sources.md` — NVD and CISA KEV API details.
- `docs/responsible_use.md` — ethical use guidelines.

---

### Added — Milestone 2: NVD CVE ingestion

- `src/ingestion/nvd_client.py` — paginated NVD CVE 2.0 REST API client.
  - `fetch_cves()` — single page fetch with keyword, CVE ID, and date range support.
  - `iter_cves()` — generator that paginates across all result pages with rate-limit sleep.
  - `fetch_cve_by_id()` — single CVE lookup.
- Typed exception hierarchy: `NVDAPIError`, `NVDRateLimitError`.
- All HTTP calls mocked in `tests/test_nvd_client.py`.

---

### Added — Milestone 3: CISA KEV ingestion

- `src/ingestion/kev_client.py` — single-fetch CISA KEV JSON catalogue client.
  - `fetch_kev()` — returns full KEV catalogue as a list of typed dicts.
  - `get_kev_cve_ids()` — returns a `set[str]` of CVE IDs for O(1) membership checks.
- Typed exception: `KEVAPIError`.
- Dashboard date-range filters.
- All HTTP calls mocked in `tests/test_kev_client.py`.

---

### Added — Milestone 4: Feature engineering

- `src/features/cve_parser.py` — NVD JSON → flat feature dict (CVSS v3.1 / v3.0 / v2 fallback).
- `src/features/feature_engineering.py` — `build_features()`: list of dicts + KEV IDs → normalised Pandas DataFrame.
  - Columns: `severity_numeric`, `attack_vector_numeric`, `age_days`, `in_kev`, `kev_numeric`, `risk_score`.
- `src/models/risk_scorer.py` — rule-based 0–100 risk score integrating CVSS, KEV membership, and age.
- `docs/data_sources.md` updated with field mapping.

---

### Added — Milestone 5: Baseline ML classifier

- `src/models/classifier.py` — scikit-learn baseline classifier.
  - `high_risk` label: `risk_score ≥ 70`.
  - Supports `LogisticRegression` and `RandomForest` via `config.yaml`.
  - Trained on-the-fly; no model binary is saved by default.
- F1, precision, recall, and ROC-AUC metrics.
- `docs/modeling.md` — feature table, evaluation metrics, class imbalance discussion.

---

### Added — Milestone 6: Model evaluation & explainability

- Confusion matrix generation.
- Class balance analysis.
- Permutation feature importance.
- Misleading-accuracy detection (warns when accuracy is deceptive under imbalance).

---

### Added — Milestone 6.5: ML performance hardening

- Balanced class weights for `RandomForest` and `LogisticRegression` (`class_weight="balanced"`).
- Threshold sweep: F1 and Recall plotted across decision thresholds.
- Recommended threshold selection (maximises F1 / Recall trade-off).
- Confusion matrix recalculated at the chosen threshold.

---

### Added — Milestone 7: Defensive mitigation recommendation layer

- `src/recommendations/mitigation.py`.
  - `recommend_mitigation(row)` — 5-tier priority logic (CRITICAL / HIGH / MEDIUM / LOW).
  - `build_recommendations(df)` — applies recommendations to a full DataFrame and sorts by priority.
  - CWE-aware guidance for 10 common weakness types (defensive descriptions only, no exploit steps).
- Dashboard section: "🛡️ Defensive Recommendations" with per-CVE expandable detail.
- `docs/mitigation_guidance.md` — full tier logic, SLA table, CWE guidance reference.

---

### Added — Milestone 8: FastAPI defensive scoring API

- `src/api/main.py` — FastAPI REST service.
  - `GET /health` — liveness check + defensive-use note.
  - `GET /version` — project name, API version, storage policy.
  - `POST /score` — risk score + normalised features for a single CVE.
  - `POST /recommend` — full defensive mitigation recommendation for a single CVE.
- Pydantic request/response models with `base_score` validated 0.0–10.0.
- Reuses existing `build_features()` and `recommend_mitigation()` — no duplicate logic.
- `docs/api.md` — full endpoint reference with PowerShell examples.
- Added `fastapi==0.115.5` and `uvicorn==0.32.1` to `requirements.txt`.

---

### Added — Milestone 9: Docker and deployment hardening

- `Dockerfile` (rewritten):
  - Base image: `python:3.11-slim`.
  - `PYTHONDONTWRITEBYTECODE`, `PYTHONUNBUFFERED`, `PIP_NO_CACHE_DIR` env vars.
  - `curl` installed for HEALTHCHECK.
  - `EXPOSE 8501` (Streamlit) and `EXPOSE 8000` (FastAPI).
  - Layer-cached pip install; `COPY . .` after dependency layer.
  - Default CMD runs Streamlit; FastAPI launched via command override.
- `.dockerignore` updated to exclude secrets, datasets, model artefacts, screenshots, caches, IDE files.
- `docs/deployment_guide.md` — local Python setup, Docker build/run commands for both services, NVD API key flag, troubleshooting, security notes.

---

### Added — Milestone 10: GitHub Actions CI/CD hardening

- `.github/workflows/python-ci.yml` — three-job CI pipeline.
  - **test**: installs dependencies, runs `pytest tests/ -v` without `NVD_API_KEY`.
  - **secret-hygiene**: verifies `.env` is not tracked; scans all tracked text files for committed secret patterns.
  - **dockerfile-check**: text-based Dockerfile validation (no Docker daemon required).
- Triggers on push and pull_request to `main`.
- `tests/test_ci_config.py` — 22 tests validating the workflow structure.

---

### Added — Milestone 11: Repository polish and professional release readiness

- `CONTRIBUTING.md` — setup guide, defensive-use policy, PR checklist, what not to add.
- `SECURITY.md` — responsible disclosure policy, supported versions, reporting instructions.
- `CHANGELOG.md` — this file.
- `docs/roadmap.md` — completed milestones, near-term and optional future work, explicitly excluded scope.
- `docs/release_notes_v0.1.0.md` — release summary, run instructions, limitations, responsible use.
- `.github/pull_request_template.md` — PR checklist template.
- `.github/ISSUE_TEMPLATE/bug_report.md` — structured bug report form.
- `.github/ISSUE_TEMPLATE/feature_request.md` — structured feature request form.
- `.github/ISSUE_TEMPLATE/documentation_update.md` — documentation improvement form.
- `tests/test_repo_polish.py` — governance file existence and content tests.
- `README.md` updated: governance links, project status section, "What this project is not" section, M11 milestone marked complete.

---

## Test coverage summary (v0.1.0)

| Test file | Tests |
|---|---|
| `test_cve_parser.py` | CVE JSON parsing, CVSS fallback |
| `test_feature_engineering.py` | Normalisation, KEV flag, age calculation |
| `test_risk_scorer.py` | Score range, KEV bonus, severity weighting |
| `test_nvd_client.py` | Pagination, rate-limit errors, mocked HTTP |
| `test_kev_client.py` | KEV fetch, CVE ID set, mocked HTTP |
| `test_classifier.py` | ML training, high_risk label, class balance |
| `test_evaluation.py` | Confusion matrix, permutation importance |
| `test_mitigation.py` | All 5 priority tiers, CWE hints, DataFrame sort |
| `test_api.py` | All 4 endpoints, Pydantic validation, TestClient |
| `test_deployment_docs.py` | Dockerfile, .dockerignore, deployment guide content |
| `test_ci_config.py` | Workflow triggers, jobs, security properties |
| `test_repo_polish.py` | Governance files, templates, README links |

All tests pass with zero real network calls and zero dataset downloads.
