"""
CI configuration tests — Milestone 10.

Validates that .github/workflows/python-ci.yml is well-formed and implements
the required checks for a defensive cybersecurity project.

No network calls. No Docker required.
"""

from __future__ import annotations

import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).parent.parent
_CI_WORKFLOW = ROOT / ".github" / "workflows" / "python-ci.yml"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read() -> str:
    return _CI_WORKFLOW.read_text(encoding="utf-8")


def _load() -> dict:
    return yaml.safe_load(_read())


def _on(wf: dict) -> dict:
    # PyYAML 5+ parses bare 'on' as Python True (YAML 1.1 boolean).
    return wf.get(True, wf.get("on", {})) or {}


# ── File existence ────────────────────────────────────────────────────────────

def test_workflow_file_exists():
    assert _CI_WORKFLOW.exists(), (
        "python-ci.yml not found — expected at .github/workflows/python-ci.yml"
    )


def test_workflow_is_valid_yaml():
    wf = _load()
    assert isinstance(wf, dict), "python-ci.yml is not a valid YAML mapping"


# ── Trigger configuration ─────────────────────────────────────────────────────

def test_triggers_on_push_to_main():
    wf = _load()
    push_branches = _on(wf).get("push", {}).get("branches", [])
    assert "main" in push_branches, "CI must trigger on push to main"


def test_triggers_on_pull_request_to_main():
    wf = _load()
    pr_branches = _on(wf).get("pull_request", {}).get("branches", [])
    assert "main" in pr_branches, "CI must trigger on pull_request to main"


def test_triggers_do_not_require_feature_branches_only():
    """main must be explicitly listed so every merged PR is tested."""
    wf = _load()
    push_branches = _on(wf).get("push", {}).get("branches", [])
    assert any("main" in b for b in push_branches), (
        "push trigger must include main"
    )


# ── Python version ────────────────────────────────────────────────────────────

def test_workflow_uses_python_311():
    assert "3.11" in _read(), "CI workflow must reference Python 3.11"


def test_workflow_uses_actions_setup_python():
    assert "setup-python" in _read(), "CI workflow must use actions/setup-python"


# ── Test runner ───────────────────────────────────────────────────────────────

def test_workflow_runs_pytest():
    assert "pytest" in _read(), "CI workflow must run pytest"


def test_workflow_targets_tests_directory():
    assert "tests/" in _read(), "CI workflow must target the tests/ directory"


def test_workflow_installs_requirements():
    assert "requirements.txt" in _read(), (
        "CI workflow must install from requirements.txt"
    )


# ── Jobs structure ────────────────────────────────────────────────────────────

def test_workflow_defines_at_least_one_job():
    wf = _load()
    jobs = wf.get("jobs", {})
    assert len(jobs) >= 1, "CI workflow must define at least one job"


def test_all_jobs_run_on_ubuntu():
    wf = _load()
    for name, job in wf.get("jobs", {}).items():
        runs_on = str(job.get("runs-on", "")).lower()
        assert "ubuntu" in runs_on, f"Job '{name}' should run on ubuntu-latest"


def test_workflow_uses_actions_checkout():
    assert "actions/checkout" in _read(), (
        "CI workflow must use actions/checkout"
    )


# ── Security: no hardcoded secrets ───────────────────────────────────────────

def test_workflow_contains_no_hardcoded_api_key_values():
    """The workflow file itself must not contain real API key values."""
    text = _read()
    matches = re.findall(
        r'(NVD_API_KEY|API_KEY|SECRET|TOKEN)\s*=\s*([A-Za-z0-9+/_-]{8,})',
        text,
    )
    real = [
        m for m in matches
        if not any(
            p in m[1].lower()
            for p in ("your_", "here", "example", "placeholder", "xxx", "test", "fake", "dummy")
        )
    ]
    assert not real, f"Workflow file appears to contain real secret values: {real}"


def test_workflow_does_not_require_nvd_api_key_secret():
    """CI must not gate on a GitHub repository secret for NVD_API_KEY.
    All tests must pass without any real API keys."""
    assert "secrets.NVD_API_KEY" not in _read(), (
        "CI must not require NVD_API_KEY — tests must pass without real API keys"
    )


def test_workflow_does_not_call_real_nvd_api():
    text = _read()
    assert "nvd.nist.gov" not in text, "CI must not reference the real NVD API"


def test_workflow_does_not_call_real_cisa_api():
    text = _read()
    assert "cisa.gov" not in text, "CI must not reference the real CISA KEV API"


# ── Security checks in workflow ───────────────────────────────────────────────

def test_workflow_includes_secret_hygiene_check():
    text = _read().lower()
    assert any(kw in text for kw in ("secret", "hygiene", ".env")), (
        "CI workflow should include a secret hygiene check step"
    )


def test_workflow_includes_dockerfile_check():
    assert "dockerfile" in _read().lower(), (
        "CI workflow should include a Dockerfile validation step"
    )


# ── Storage-light policy ──────────────────────────────────────────────────────

def test_workflow_does_not_download_datasets():
    """No curl/wget calls to NVD or CISA bulk-data endpoints."""
    text = _read().lower()
    # Check for patterns that would indicate actual bulk-dataset download commands.
    # The word "dataset" may appear in comments explaining the policy — that is fine.
    bad_endpoints = ["nvdcve", "nvd_cve", "nvd/feeds", "cisa.gov/sites", "/bulk"]
    for endpoint in bad_endpoints:
        assert endpoint not in text, (
            f"CI must not reference bulk-dataset download endpoint: {endpoint}"
        )


def test_workflow_does_not_upload_screenshots():
    text = _read().lower()
    assert "reports/figures" not in text, (
        "CI must not upload screenshot artefacts from reports/figures/"
    )


# ── Defensive use note ────────────────────────────────────────────────────────

def test_workflow_mentions_defensive_or_mock_intent():
    """Workflow comments should indicate tests use mocks, not real APIs."""
    text = _read().lower()
    assert any(kw in text for kw in ("mock", "synthetic", "defensive", "no network")), (
        "Workflow should document that tests use mocks/synthetic data, not real APIs"
    )
