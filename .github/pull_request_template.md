## Summary

<!-- Describe what this PR changes and why. One to three sentences. -->

## Type of change

<!-- Check the boxes that apply. -->

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactor / code quality
- [ ] CI / tooling
- [ ] Other: <!-- describe -->

## Related issues

<!-- Link any related issues, e.g. Closes #123 -->

---

## Pre-merge checklist

Please confirm all of the following before requesting review:

### Tests
- [ ] `pytest tests/ -v` passes locally with no failures.
- [ ] New or changed logic is covered by tests in `tests/`.
- [ ] Tests use mocks or synthetic data — no real NVD or CISA API calls.

### Secrets and data
- [ ] No real API keys, tokens, passwords, or credentials are committed.
- [ ] `.env` is not included — only `.env.example` (with placeholder values) if needed.
- [ ] No full CVE datasets (`data/raw/`, `data/processed/`, `data/cache/`) are added.
- [ ] No screenshot or generated figure files are added to `reports/figures/`.

### Defensive scope
- [ ] This PR does not include exploit code, attack steps, or offensive techniques.
- [ ] This PR does not add offensive scanning capabilities.
- [ ] All new functionality is oriented toward **defensive** use (patching prioritisation, risk scoring, remediation guidance).

### Documentation
- [ ] Relevant `docs/` files are updated to reflect any behaviour changes.
- [ ] `CHANGELOG.md` is updated if this is a notable change.
- [ ] `README.md` is updated if new features or run commands are added.

### CI
- [ ] CI is expected to pass. Push to your fork branch and check GitHub Actions before opening this PR.

---

## Notes for reviewers

<!-- Anything reviewers should pay particular attention to, or context that is not obvious from the diff. -->
