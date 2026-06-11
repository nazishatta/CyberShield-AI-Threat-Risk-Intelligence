# Defensive Mitigation Guidance

## Purpose

The `src/recommendations/mitigation.py` module generates prioritised remediation
recommendations for each CVE retrieved from the NVD and CISA KEV feeds.

Its goal is to help security teams move from raw vulnerability data to
**actionable next steps** without requiring manual triage of every CVE.

---

## What it is NOT

- It does **not** provide exploit code or attack steps.
- It does **not** replace professional security assessment or penetration testing.
- It does **not** know your specific asset inventory, network topology, or
  installed software versions.
- It does **not** guarantee that a recommended action will fully mitigate risk.

These recommendations are a **starting point for analyst review**, not a
substitute for it.

---

## Priority tiers

The module evaluates each CVE against five tiers in sequence. The first matching
tier determines the output.

### CRITICAL — Immediate Remediation
**Triggered when:** The CVE is in the CISA Known Exploited Vulnerabilities (KEV)
catalogue AND has a calculated risk score ≥ 70.

Active exploitation has been confirmed by CISA. Recommended SLA: **24–48 hours**.
Escalation to a security manager or incident response team is required.

### HIGH — Patch Externally-Exposed Assets
**Triggered when:** The CVE has a NETWORK attack vector AND a CVSS base score ≥ 7.0
(and is not already CRITICAL).

Network-reachable vulnerabilities with high CVSS scores are disproportionately
targeted. Recommended SLA: **72 hours**. Escalation is required when risk score ≥ 70.

### MEDIUM — Manual Analyst Review
**Triggered when:** Severity, attack vector, or CVSS base score data is missing
or UNKNOWN.

Automated scoring cannot be trusted for incomplete records.
Recommended SLA: **5 business days**. No auto-escalation.

### HIGH / MEDIUM — Backlog Escalation
**Triggered when:** The CVE was published more than 365 days ago AND has a
risk score ≥ 50 (and was not caught by a higher tier).

Priority is HIGH when risk score ≥ 70, MEDIUM otherwise. Long-unpatched
vulnerabilities with elevated scores indicate a gap in patch management cycles.
Recommended SLA: **7 days**.

### MEDIUM / LOW — Scheduled Remediation
**Triggered for all remaining CVEs.**

Priority is MEDIUM for risk score ≥ 30, LOW otherwise.
Recommended SLA: **30 days**.

---

## CWE-aware guidance

When a CVE has a recognised CWE category, the recommendation text includes
CWE-specific defensive guidance — **without** exploit instructions or attack steps.

| CWE | Type | Defensive guidance focus |
|---|---|---|
| CWE-79 | Cross-Site Scripting | CSP headers, output encoding, input sanitisation |
| CWE-89 | SQL Injection | Parameterised queries, least-privilege DB accounts |
| CWE-20 | Improper Input Validation | Server-side validation at API boundaries |
| CWE-119 / CWE-787 / CWE-125 | Memory Safety | Patching, ASLR/DEP mitigations |
| CWE-22 | Path Traversal | File-system sandboxing, path normalisation |
| CWE-200 | Information Exposure | Access control audits |
| CWE-287 | Authentication Issues | MFA enforcement, flow audits |
| CWE-416 | Use-After-Free | Library updates, memory-safe build options |

---

## Responsible interpretation

1. **KEV is the authoritative source** — a CISA KEV entry confirms real-world
   exploitation. CRITICAL-priority recommendations for KEV CVEs should always
   be actioned, even if the risk score is borderline.

2. **SLAs are guidance, not mandates** — the suggested SLAs reflect common
   industry norms. Your organisation may have stricter requirements
   (e.g., PCI-DSS requires critical patches within 30 days; some frameworks
   require 24 hours for actively exploited CVEs).

3. **Escalation flags are conservative** — `escalation_required=True` is set
   whenever a CVE has a risk score ≥ 70 or is in the KEV catalogue. Organisations
   with mature patch workflows may lower this threshold.

4. **Asset inventory is essential** — a CRITICAL-priority CVE for software you
   do not run requires no action. Always cross-reference with your CMDB or SBOM
   before scheduling remediation.

---

## Related files

| File | Role |
|---|---|
| `src/recommendations/mitigation.py` | Recommendation engine |
| `src/models/risk_scorer.py` | Rule-based risk score (input to tier logic) |
| `src/features/feature_engineering.py` | Feature DataFrame produced upstream |
| `docs/responsible_use.md` | Project-wide ethical use guidelines |
| `docs/modeling.md` | ML classifier and scoring methodology |
