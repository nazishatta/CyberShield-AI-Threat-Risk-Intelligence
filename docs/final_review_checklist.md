# Final Review Checklist

Use this checklist before pushing a release branch, merging a significant PR, or marking any milestone complete.
All items should be confirmed — no Docker daemon, no real API calls required for most checks.

---

## README clarity

- [ ] README title and first paragraph clearly identify the project as a **defensive CVE risk intelligence platform**.
- [ ] README mentions the technology stack (Streamlit, FastAPI, scikit-learn, Docker, GitHub Actions).
- [ ] README explicitly states that **no full dataset is downloaded locally** (storage-light).
- [ ] README architecture overview section (`## Architecture overview`) is present and intact.
- [ ] README contains the ASCII pipeline diagram with `NVD API` and `CISA KEV` inputs.
- [ ] README project status table has an accurate test count.
- [ ] README links to all major docs files (`project_architecture.md`, `api.md`, `deployment_guide.md`, etc.).
- [ ] README links to governance files (`CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`).
- [ ] README quick start commands are correct (Streamlit, FastAPI, tests, Docker).
- [ ] README milestone table is up to date.

---

## Defensive-use checks

- [ ] No file in the repository contains exploit code, attack payloads, or step-by-step offensive instructions.
- [ ] `docs/responsible_use.md` is present and states that model outputs are **prioritisation signals requiring human review**.
- [ ] `docs/responsible_use.md` explicitly requires **validation against asset inventory** before acting on recommendations.
- [ ] `docs/mitigation_guidance.md` contains no exploit steps — defensive actions only (patch, isolate, compensating controls).
- [ ] `docs/api.md` states **defensive use only** and **no exploit content**.
- [ ] `SECURITY.md` is present and states the project provides no exploit instructions.
- [ ] `CONTRIBUTING.md` explicitly prohibits exploit code and offensive scanning in contributions.
- [ ] `.github/ISSUE_TEMPLATE/feature_request.md` asks whether the request is within the defensive scope.

---

## Storage-light checks

- [ ] `data/raw/`, `data/processed/`, `data/cache/` are empty (git-ignored).
- [ ] `.gitignore` excludes `data/raw/`, `data/processed/`, `data/cache/`, `*.csv`, `*.parquet`.
- [ ] `.dockerignore` excludes `data/raw/`, `data/processed/`, model artefacts (`.pkl`, `.joblib`), and screenshots.
- [ ] No model binary files (`.pkl`, `.joblib`, `.h5`, `.pt`, `.onnx`) are committed.
- [ ] `docs/data_sources.md` explains the storage-light ingestion strategy.
- [ ] `docs/roadmap.md` lists "full CVE dataset downloads" in the explicitly excluded scope.

---

## Git hygiene checks

- [ ] `.env` is **not** tracked by git (`git ls-files .env` returns nothing).
- [ ] No API keys, tokens, or credentials appear in any tracked file.
- [ ] `reports/figures/` contains only `.gitkeep` — no PNG, SVG, PDF, or HTML files are committed.
- [ ] `notebooks/` does not contain large output cells or embedded binary data.
- [ ] No `.pyc` files, `__pycache__/` directories, or `.venv/` are tracked.

---

## Tests

- [ ] Run the full test suite:
  ```powershell
  pytest tests/ -v
  ```
  All tests pass with **zero failures**.
- [ ] All tests use mocks or synthetic data — no real NVD or CISA API calls.
- [ ] `NVD_API_KEY` is not required for any test to pass.
- [ ] Test count matches the figure stated in the README project status table.

---

## CI check

- [ ] `.github/workflows/python-ci.yml` is present.
- [ ] The workflow triggers on push and pull_request to `main`.
- [ ] All three CI jobs pass on the latest commit: **test**, **secret-hygiene**, **dockerfile-check**.
- [ ] No `NVD_API_KEY` GitHub secret is required for CI to pass.
- [ ] CI workflow does not call real external APIs or download datasets.

---

## Documentation consistency

- [ ] All docs use the term **"storage-light"** (not "lightweight storage" or "low storage").
- [ ] All docs use **"defensive CVE risk intelligence"** or **"defensive mitigation recommendations"**.
- [ ] All docs use **"live API calls"** (not "real-time" or "streaming").
- [ ] All docs use **"no full dataset downloads"** (not "no data stored" — be specific).
- [ ] File paths in docs match files that actually exist in the repository.
- [ ] Test counts in docs are consistent with the current suite output.

---

## Release readiness

- [ ] `CHANGELOG.md` has an entry for the current milestone.
- [ ] `docs/release_notes_v0.1.0.md` accurately describes the current capabilities.
- [ ] `docs/roadmap.md` completed milestones list is up to date.
- [ ] `SECURITY.md` lists the correct contact email for private vulnerability reports.
- [ ] `CONTRIBUTING.md` setup instructions match the current `requirements.txt`.
- [ ] `.env.example` contains only placeholder values — no real keys.

---

## Artefact safety

- [ ] No screenshot files (`.png`, `.jpg`, `.svg`, `.pdf`, `.html`) are in `reports/figures/` except `.gitkeep`.
- [ ] No local analysis output files are staged or committed.
- [ ] No notebook checkpoint files (`.ipynb_checkpoints/`) are tracked.
- [ ] No OS artefacts (`.DS_Store`, `Thumbs.db`) are tracked.

---

## Quick verification commands

```powershell
# Run all tests
pytest tests/ -v

# Check .env is not tracked
git ls-files .env

# Check no model artefacts are tracked
git ls-files "*.pkl" "*.joblib" "*.h5" "*.pt" "*.onnx"

# Check no screenshot files are tracked
git ls-files "reports/figures/*.png" "reports/figures/*.svg"

# Check no data files are tracked
git ls-files "data/raw/" "data/processed/"
```
