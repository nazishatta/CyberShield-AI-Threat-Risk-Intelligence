# Responsible Use

CyberShield AI is a **defensive CVE risk intelligence tool**.
It surfaces publicly available vulnerability metadata to help security teams prioritise patching and understand risk exposure — and nothing more.

---

## Intended use cases

- Security operations teams triaging CVEs by exploitability and severity
- Researchers studying vulnerability trends and risk scoring methodologies
- Students learning about CVE data pipelines and applied ML in cybersecurity
- Integrating defensive CVE scoring into internal tooling via the REST API (`src/api/`)
- Understanding the design of a storage-light, API-first security data platform

---

## What this project does NOT do

- It does **not** provide exploit code or step-by-step attack instructions.
- It does **not** scan, probe, or interact with any live systems.
- It does **not** collect, store, or transmit any personal or organisational data.
- It does **not** download complete vulnerability databases locally.
- It does **not** replace a professional security assessment or penetration test.

All data displayed originates from **publicly available, government-maintained feeds** (NVD and CISA KEV).

---

## Model output disclaimer

Risk scores and high-risk predictions produced by this tool are:

- **Prioritisation signals, not final decisions.** Every score must be reviewed by a human security analyst before scheduling remediation.
- **Estimates, not certified assessments.** Scores are derived from public CVSS metadata — not from live exploit intelligence or your organisation's specific environment.
- **Asset-dependent.** A CRITICAL score for software your organisation does not run requires no action. Always validate model output against your asset inventory (CMDB or SBOM) before acting.
- **Not an independent signal.** The ML classifier is trained on the same CVSS features that generate the rule-based label — its output should be treated as a corroborating signal, not a second independent opinion.

**Human review is required before acting on any score or recommendation.**
Do not use model output as the sole basis for business, compliance, or incident response decisions.

---

## Defensive mitigation recommendations

The `src/recommendations/mitigation.py` module produces **defensive remediation guidance** based on CVSS metadata and CISA KEV membership. All recommendations are:

- Focused on **defensive actions** (patching, isolation, compensating controls).
- Free of exploit code, proof-of-concept steps, or attack instructions.
- Intended as **starting points for analyst review** — not final prescriptions.
- Dependent on asset context — verify against your environment before scheduling work.

See [docs/mitigation_guidance.md](mitigation_guidance.md) for the full tier logic, SLA table, and CWE guidance reference.

---

## REST API usage policy

The `src/api/` FastAPI service exposes the same defensive scoring and mitigation logic as the dashboard via HTTP endpoints. The same constraints apply:

- The API does **not** call the NVD API or CISA KEV API on your behalf.
- The API does **not** download or cache any CVE dataset.
- All scoring runs in-memory from the values you submit in the request body.
- Do not use the API to automate offensive security operations.
- Do not expose the API on a public network without adding authentication.

See [docs/api.md](api.md) for endpoint documentation and example requests.

---

## API usage guidelines

### NVD API
- Use a free API key to stay within the higher rate limit (50 req/30 s).
- Do not attempt to bulk-download the entire NVD database. This project intentionally avoids NVD bulk data files to stay storage-light.
- NVD terms of service: https://nvd.nist.gov/general/news/api-20-announcements

### CISA KEV
- The KEV catalogue is a public government dataset.
- Do not mirror or redistribute the full catalogue outside the scope of your authorised project.
- CISA KEV catalogue: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

## Secrets and credentials

- API keys must be stored in `.env` which is **git-ignored**.
- Never commit `.env`, credentials, or private keys to version control.
- `.env.example` contains only placeholder values — verify this before every commit.
- The CI workflow runs an automated secret hygiene scan on every push.

---

## Contributions

By contributing to this project, you agree that all submitted code and data:

1. Does not include exploit code, malware, or instructions for attacking systems.
2. Does not include real API keys, passwords, or personal data.
3. Is consistent with the defensive, educational, and analytical purpose of this project.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full contribution guide and PR checklist.
See the [MIT License](../LICENSE) for the legal terms.
