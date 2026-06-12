---
name: Feature request
about: Propose a new capability for this defensive cybersecurity AI project
title: "[FEATURE] "
labels: enhancement
assignees: ''
---

## Feature summary

<!-- One to two sentences describing the feature you are proposing. -->

---

## Defensive use case

<!-- Explain how this feature helps **defenders** (security teams, analysts, students).
     Features must be consistent with the defensive-only scope of this project.
     Requests for exploit generation, offensive scanning, or attack assistance
     will be closed without review. -->

**Who benefits:** <!-- e.g. SOC analyst triaging CVEs, student studying risk models -->

**What problem does it solve:**

---

## Expected behaviour

<!-- Describe what the feature should do. If this is a UI feature, describe what the user would see. If it is an API feature, describe the new endpoint or field. -->

---

## Storage and data impact

<!-- This project is API-first and storage-light — no full datasets should be downloaded or stored. -->

- [ ] This feature requires downloading a dataset locally → **If yes, explain why this is necessary and how it stays within the storage-light policy.**
- [ ] This feature adds a new dependency to `requirements.txt` → **If yes, list it below.**
- [ ] This feature only uses data already available from the NVD or CISA KEV APIs.
- [ ] This feature operates entirely in-memory or on values submitted by the user.

**New dependencies (if any):**

---

## New dependencies

<!-- Does this feature require adding a new package to requirements.txt?
     Heavy dependencies (LangChain, vector databases, PyTorch extras, etc.) are unlikely to be accepted. -->

- [ ] No new dependencies required.
- [ ] Requires a new dependency: <!-- name and justification -->

---

## Out-of-scope check

<!-- Confirm this request does not fall into the explicitly excluded categories. -->

- [ ] This request does **not** involve exploit code or attack instructions.
- [ ] This request does **not** involve offensive scanning (port scanners, fuzzers, active probing).
- [ ] This request does **not** require downloading a full CVE database locally.
- [ ] This request does **not** involve RAG, LangChain, vector databases, or LLM agents.

---

## Additional context

<!-- Mockups, links to related standards, or other supporting information. -->
