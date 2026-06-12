# Roadmap

CyberShield AI is a defensive cybersecurity intelligence platform. This document tracks
what has been built, what is planned, and — equally important — what is explicitly
**out of scope** for this project.

---

## Completed milestones

| Milestone | Description |
|---|---|
| **M0** | Repository scaffold — project layout, config, dashboard skeleton, test harness |
| **M1** | Repository hardening — `.gitignore`, architecture docs, responsible use guide |
| **M2** | NVD CVE ingestion — paginated live API client, typed exceptions, full mock test coverage |
| **M3** | CISA KEV ingestion — live JSON fetch, `get_kev_cve_ids()` set for O(1) lookup |
| **M4** | Feature engineering — CVSS normalisation, `age_days`, KEV flag, rule-based risk score |
| **M5** | Baseline ML classifier — scikit-learn LogisticRegression / RandomForest, F1 metrics |
| **M6** | Model evaluation — confusion matrix, class balance, permutation feature importance |
| **M6.5** | ML performance hardening — balanced class weights, threshold sweep, optimal threshold |
| **M7** | Defensive mitigation recommendation layer — 5-tier priority, CWE-aware guidance |
| **M8** | FastAPI defensive scoring API — `/health`, `/version`, `/score`, `/recommend` |
| **M9** | Docker and deployment hardening — Dockerfile, `.dockerignore`, deployment guide |
| **M10** | GitHub Actions CI/CD — test runner, secret hygiene scan, Dockerfile validation |
| **M11** | Repository polish — governance files, issue templates, PR template, release notes |

---

## Near-term future work

These are the most likely candidates for the next development phase.
None are committed; they depend on available time and community interest.

### CVSS trend analysis and time-series visualisation
- Plot risk score distributions over time (by `published` date or `age_days`).
- Identify months with spike in high-CVSS CVEs.
- Add a time-series chart to the Streamlit dashboard (Plotly, already a dependency).
- **Storage impact:** none — data is fetched live per query.

### Extended CWE coverage in the recommendation layer
- The current `_CWE_GUIDANCE` dict covers 10 weakness types.
- Extend to cover the full OWASP Top 10 and MITRE CWE Top 25 (defensive descriptions only).
- No new dependencies required.

### Configurable risk-score weights
- Expose CVSS weight, KEV bonus, and age penalty in `config.yaml`.
- Allow users to tune the rule-based scorer without editing source code.

### pytest-cov HTML report in CI
- Add `--cov=src --cov-report=html` to the CI test job.
- Upload as a GitHub Actions artefact (not committed to the repo).

### API pagination for `/score` and `/recommend`
- Accept a list of CVE inputs in a single POST request.
- Return a ranked list of scored / recommended CVEs.
- Useful for tooling that needs to batch-score a vulnerability scan output.

---

## Optional / longer-term ideas

These require more significant effort and are lower priority.

### GitHub Actions: dependency review
- Add the `dependency-review-action` to flag newly introduced vulnerable dependencies
  on pull requests.

### Alternative data sources
- NVD EPSS (Exploit Prediction Scoring System) integration as an additional feature column.
- CISA BOD 22-01 deadlines surfaced in recommendations.

### CLI interface
- A `cybershield score` / `cybershield recommend` command-line tool wrapping the API.
- Useful for piping CVE IDs from other security tools.

### Export to CSV / JSON (opt-in)
- Allow the dashboard to export the current result set as CSV for offline analysis.
- Data is ephemeral (from the live API query); nothing is stored by default.

---

## Explicitly excluded scope

The following will **never** be added to this project, regardless of requests:

| Category | Reason |
|---|---|
| Exploit code or PoC scripts | Violates the defensive-only mission of this project |
| Attack steps or offensive techniques | Same as above |
| Offensive scanning (port scanners, fuzzers) | Out of scope — this project analyses public metadata, not live systems |
| Full CVE dataset downloads | Violates the storage-light, API-first design principle |
| RAG (Retrieval-Augmented Generation) pipelines | Heavy dependency, out of scope for this data-engineering project |
| LangChain or similar LLM orchestration frameworks | Adds significant complexity and cost with no clear defensive benefit |
| Vector databases (Chroma, Pinecone, Weaviate, etc.) | Same as above |
| LLM-generated exploit suggestions or "what would an attacker do" prompts | Directly violates the defensive-only policy |
| Chatbot or conversational AI interfaces | Out of scope for a risk-scoring and recommendation tool |
| Model serialisation to disk (`.pkl`, `.joblib`) committed to the repo | Violates the storage-light policy and introduces supply-chain risk |
| Personal data collection or user tracking | This tool never handles personal or organisational data |

---

## Design principles (permanent)

These guide every decision in this project and will not change:

1. **Defensive only.** Every feature helps defenders — never attackers.
2. **API-first.** No full datasets are downloaded or stored locally.
3. **Storage-light.** Only tiny fixture files (< 10 KB) are git-tracked.
4. **Beginner-friendly.** Clear architecture, pinned dependencies, documented data flow.
5. **Production-grade structure.** Tests, CI, Docker, typed exceptions, Pydantic validation.

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for setup instructions, coding guidelines, and the PR checklist.
