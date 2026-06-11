# CyberShield AI — Defensive Scoring API

## Overview

The CyberShield AI API is a lightweight [FastAPI](https://fastapi.tiangolo.com/) service
that exposes the same rule-based CVE risk scoring and defensive mitigation logic used by
the Streamlit dashboard — as a JSON REST API.

**Defensive use only.** No exploit instructions, attack steps, or offensive scanning
capabilities are exposed. No full CVE datasets are downloaded or stored locally.

---

## Run locally

```powershell
# from the project root, with the virtual environment active
python -m uvicorn src.api.main:app --reload
```

Interactive Swagger docs: **http://127.0.0.1:8000/docs**
OpenAPI JSON schema:      **http://127.0.0.1:8000/openapi.json**

---

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Service liveness check + defensive-use note |
| `GET` | `/version` | Project name, API version, storage policy |
| `POST` | `/score` | Risk score + normalized features for a single CVE |
| `POST` | `/recommend` | Defensive mitigation recommendation for a single CVE |

---

## Request body (POST /score and POST /recommend)

Both POST endpoints accept the same JSON body:

| Field | Type | Required | Description |
|---|---|---|---|
| `cve_id` | string | ✅ | CVE identifier, e.g. `CVE-2024-12345` |
| `severity` | string | ✅ | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNKNOWN` |
| `base_score` | float | ✅ | CVSS base score **0.0 – 10.0** (validated; rejects values outside range) |
| `attack_vector` | string | optional | `NETWORK`, `ADJACENT`, `LOCAL`, `PHYSICAL`, or `UNKNOWN` |
| `cwe` | string | optional | e.g. `CWE-79`. Pass `UNKNOWN` if not available. |
| `published` | string | optional | ISO-8601 date, e.g. `2024-01-15T00:00:00.000`. Null if unknown. |
| `in_kev` | boolean | optional | `true` if listed in the CISA Known Exploited Vulnerabilities catalogue |

---

## Example request body

```json
{
  "cve_id": "CVE-2024-12345",
  "severity": "HIGH",
  "base_score": 8.5,
  "attack_vector": "NETWORK",
  "cwe": "CWE-89",
  "published": "2023-06-01T00:00:00.000",
  "in_kev": false
}
```

---

## Example responses

### GET /health

```json
{
  "status": "ok",
  "service": "CyberShield AI — Defensive Scoring API",
  "note": "This service provides defensive vulnerability scoring only. No exploit instructions, attack steps, or offensive scanning capabilities are exposed."
}
```

### POST /score

```json
{
  "cve_id": "CVE-2024-12345",
  "normalized_features": {
    "severity_numeric": 3,
    "base_score": 8.5,
    "attack_vector_numeric": 4,
    "age_days": 542,
    "kev_numeric": 0
  },
  "risk_score": 63.75,
  "risk_band": "MEDIUM",
  "defensive_interpretation": "Risk score 64/100. Strong exploitability indicators present — high CVSS base score, network-reachable attack vector, or both. Prioritise patching and assess exposed attack surface.",
  "responsible_use_note": "This score is derived from public CVE metadata (CVSS, CISA KEV) and is intended to assist defenders in prioritisation — it does not certify exploitability or replace professional security assessment."
}
```

### POST /recommend

```json
{
  "cve_id": "CVE-2024-12345",
  "risk_score": 63.75,
  "priority_level": "HIGH",
  "action_title": "Patch Externally-Exposed Assets",
  "recommendation": "Identify all internet-facing or network-accessible services running the affected software version. Prioritise patching for those assets. Apply network segmentation or temporary firewall rules if patching cannot be completed within the SLA.",
  "rationale": "CVE-2024-12345 is remotely exploitable (NETWORK attack vector) with a CVSS base score of 8.5/10. Network-reachable high-CVSS vulnerabilities have a significantly elevated likelihood of exploitation.",
  "suggested_sla": "72 hours",
  "escalation_required": false,
  "responsible_use_note": "This recommendation is generated from public CVE metadata and is intended to assist security analysts — not replace their judgement. Verify against your asset inventory and organisational risk tolerance before acting."
}
```

---

## PowerShell example (Invoke-RestMethod)

```powershell
$body = @{
    cve_id       = "CVE-2024-12345"
    severity     = "HIGH"
    base_score   = 8.5
    attack_vector = "NETWORK"
    cwe          = "CWE-89"
    published    = "2023-06-01T00:00:00.000"
    in_kev       = $false
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/score" `
                  -Method POST `
                  -ContentType "application/json" `
                  -Body $body
```

---

## Validation rules

- `base_score` must be between **0.0 and 10.0** inclusive. Requests outside this range receive HTTP 422.
- Unknown or empty `severity` and `attack_vector` values are silently normalised to `UNKNOWN` — the API never crashes on unfamiliar input.
- A null or missing `published` date causes `age_days` to return `-1` in the normalized features — this is expected and handled safely.

---

## Storage policy

This API is **API-first and storage-light**:

- It does **not** call the NVD API or CISA KEV API.
- It does **not** download any CVE dataset.
- All scoring and recommendation logic runs in-memory from the values you submit in the request body.
- No data is written to disk.

---

## Responsible use

- Output is based on public CVSS metadata — it is **not** a certified security assessment.
- Risk scores and recommendations are intended to **assist** security analysts, not replace their judgement.
- Always verify recommendations against your organisation's asset inventory and risk tolerance.
- This API must not be used to automate offensive security operations.

See [docs/responsible_use.md](responsible_use.md) for the full policy.

---

## Related files

| File | Role |
|---|---|
| `src/api/main.py` | FastAPI app — endpoints, Pydantic models, helpers |
| `src/features/feature_engineering.py` | Normalisation called by `/score` and `/recommend` |
| `src/models/risk_scorer.py` | Rule-based 0–100 score (called via `build_features`) |
| `src/recommendations/mitigation.py` | Tier-based mitigation logic called by `/recommend` |
| `tests/test_api.py` | API tests using FastAPI TestClient (no network calls) |
