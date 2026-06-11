# Responsible Use

CyberShield AI is a **defensive security intelligence tool**.
It surfaces publicly available vulnerability data to help defenders prioritise patching and understand risk exposure.

---

## Intended use cases

- Security operations teams triaging CVEs by exploitability and severity
- Researchers studying vulnerability trends and risk scoring methodologies
- Students learning about CVE data pipelines and applied ML in cybersecurity
- Portfolio demonstration of API-first data engineering and ML practices

---

## What this project does NOT do

- It does **not** provide exploit code or step-by-step attack instructions.
- It does **not** scan, probe, or interact with any live systems.
- It does **not** collect, store, or transmit any personal or organisational data.
- It does **not** download complete vulnerability databases locally.

All data displayed originates from **publicly available, government-maintained feeds** (NVD and CISA KEV).

---

## API usage guidelines

### NVD API
- Use a free API key to respect the higher rate limit (50 req/30 s).
- Do not attempt to bulk-download the entire NVD database.
  The NVD provides bulk data files specifically for that purpose; this project intentionally avoids them to stay storage-light.
- NVD terms of service: https://nvd.nist.gov/general/news/api-20-announcements

### CISA KEV
- The KEV catalogue is a public government dataset.
- Do not mirror or redistribute the full catalogue outside the scope of your authorised project.
- CISA KEV catalogue page: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

## Model output disclaimer

Risk scores and exploit-likelihood predictions produced by this tool are:

- **Estimates only** — not certified security assessments.
- Based on publicly available metadata (CVSS, KEV membership, CWE) — not on live exploit intelligence.
- Intended to **assist** human security analysts, not replace their judgement.

Do not use model output as the sole basis for business, compliance, or incident response decisions.

---

## Secrets and credentials

- API keys must be stored in `.env` which is **git-ignored**.
- Never commit `.env`, credentials, or private keys to version control.
- `.env.example` contains only placeholder values — verify this before every commit.

---

## Contributions

By contributing to this project, you agree that all submitted code and data:

1. Does not include exploit code, malware, or instructions for attacking systems.
2. Does not include real API keys, passwords, or personal data.
3. Is consistent with the defensive, educational purpose of this project.

See the [MIT License](../LICENSE) for the full legal terms.
