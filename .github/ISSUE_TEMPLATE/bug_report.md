---
name: Bug report
about: Report a reproducible defect in the application, API, or tests
title: "[BUG] "
labels: bug
assignees: ''
---

## Bug description

<!-- A clear, concise description of what the bug is. -->

---

## Environment

| Field | Value |
|---|---|
| OS | <!-- e.g. Windows 11, Ubuntu 22.04, macOS 14 --> |
| Python version | <!-- e.g. 3.11.9 --> |
| Branch / commit | <!-- e.g. main @ abc1234 --> |
| Running in Docker | <!-- Yes / No --> |
| Component affected | <!-- Dashboard / FastAPI / Ingestion / Feature engineering / Tests / CI --> |

---

## Steps to reproduce

<!-- Provide the exact steps needed to reproduce the bug. -->

1.
2.
3.

---

## Expected behaviour

<!-- What did you expect to happen? -->

---

## Actual behaviour

<!-- What actually happened? Include error messages, stack traces, or unexpected output. -->

```
# Paste error output here
```

---

## Logs

<!-- Paste any relevant log output. Remove or redact any real API keys, tokens, or credentials before posting. -->

```
# Paste logs here
```

---

## Real external API involvement

<!-- Does this bug only appear when calling the real NVD or CISA KEV APIs?
     If yes, describe the query parameters used (but do NOT paste your NVD_API_KEY). -->

- [ ] Yes — involves a real NVD or CISA API call
- [ ] No — reproducible with mocked data / tests only

---

## Additional context

<!-- Any other context that might help diagnose the issue. -->
