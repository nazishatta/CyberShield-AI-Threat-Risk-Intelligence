"""
Final documentation polish tests.

Validates that README.md, docs/final_review_checklist.md, and the overall
documentation set meet the quality bar required for public release.

No network calls. No Docker daemon required.
"""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).parent.parent

_README    = ROOT / "README.md"
_CHECKLIST = ROOT / "docs" / "final_review_checklist.md"
_ARCH_DOC  = ROOT / "docs" / "project_architecture.md"
_API_DOC   = ROOT / "docs" / "api.md"
_RESP_USE  = ROOT / "docs" / "responsible_use.md"
_ROADMAP   = ROOT / "docs" / "roadmap.md"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


# ── README: structural preservation ──────────────────────────────────────────

def test_readme_contains_architecture_overview_section():
    """The Architecture overview heading must never be removed."""
    assert "## Architecture overview" in _read(_README), (
        "README.md must contain the '## Architecture overview' section"
    )


def test_readme_contains_nvd_api_in_diagram():
    """The ASCII pipeline diagram must include NVD API as an input."""
    assert "NVD API" in _read(_README), (
        "README.md must contain 'NVD API' in the architecture diagram"
    )


def test_readme_contains_cisa_kev_in_diagram():
    """The ASCII pipeline diagram must include CISA KEV as an input."""
    assert "CISA KEV" in _read(_README), (
        "README.md must contain 'CISA KEV' in the architecture diagram"
    )


def test_readme_ascii_diagram_has_ingestion_arrow():
    """The ASCII diagram must show the pipeline flow (►)."""
    assert "──►" in _read(_README) or "─►" in _read(_README), (
        "README.md architecture diagram should contain the ──► arrow characters"
    )


# ── README: first-impression clarity ─────────────────────────────────────────

def test_readme_title_mentions_defensive_or_cvss_or_risk():
    text = _read(_README).lower()
    assert any(kw in text[:500] for kw in ("defensive", "cve", "risk")), (
        "README.md opening should mention 'defensive', 'CVE', or 'risk' within the first 500 chars"
    )


def test_readme_mentions_streamlit():
    assert "streamlit" in _read(_README).lower(), (
        "README.md should mention Streamlit as a technology"
    )


def test_readme_mentions_fastapi():
    assert "fastapi" in _read(_README).lower(), (
        "README.md should mention FastAPI as a technology"
    )


def test_readme_mentions_no_full_dataset_downloads():
    text = _read(_README).lower()
    assert any(kw in text for kw in ("no full dataset", "no dataset", "never downloaded", "no full")), (
        "README.md should state that no full dataset is downloaded locally"
    )


def test_readme_mentions_defensive_use():
    assert "defensive" in _read(_README).lower(), (
        "README.md should mention the defensive-use purpose"
    )


def test_readme_mentions_storage_light():
    assert "storage-light" in _read(_README).lower() or "storage light" in _read(_README).lower(), (
        "README.md should mention 'storage-light'"
    )


# ── README: links to major documentation ─────────────────────────────────────

def test_readme_links_to_project_architecture():
    assert "project_architecture" in _read(_README), (
        "README.md should link to docs/project_architecture.md"
    )


def test_readme_links_to_api_doc():
    assert "docs/api.md" in _read(_README) or "api.md" in _read(_README), (
        "README.md should link to docs/api.md"
    )


def test_readme_links_to_deployment_guide():
    assert "deployment_guide" in _read(_README), (
        "README.md should link to docs/deployment_guide.md"
    )


def test_readme_links_to_responsible_use():
    assert "responsible_use" in _read(_README), (
        "README.md should link to docs/responsible_use.md"
    )


def test_readme_links_to_roadmap():
    assert "roadmap" in _read(_README).lower(), (
        "README.md should link to docs/roadmap.md"
    )


def test_readme_links_to_contributing():
    assert "CONTRIBUTING" in _read(_README), (
        "README.md should link to CONTRIBUTING.md"
    )


def test_readme_links_to_security():
    assert "SECURITY" in _read(_README), (
        "README.md should link to SECURITY.md"
    )


def test_readme_links_to_changelog():
    assert "CHANGELOG" in _read(_README), (
        "README.md should link to CHANGELOG.md"
    )


# ── Final review checklist: existence and content ────────────────────────────

def test_final_review_checklist_exists():
    assert _CHECKLIST.exists(), "docs/final_review_checklist.md not found"


def test_final_checklist_mentions_tests():
    text = _read(_CHECKLIST).lower()
    assert "pytest" in text or "test" in text, (
        "final_review_checklist.md should include a test-runner check"
    )


def test_final_checklist_mentions_ci():
    text = _read(_CHECKLIST).lower()
    assert any(kw in text for kw in ("ci", "github actions", "workflow")), (
        "final_review_checklist.md should include a CI check"
    )


def test_final_checklist_mentions_no_screenshots():
    text = _read(_CHECKLIST).lower()
    assert any(kw in text for kw in ("screenshot", "png", "figures", "reports/figures")), (
        "final_review_checklist.md should remind reviewers not to commit screenshots"
    )


def test_final_checklist_mentions_no_local_artifacts():
    text = _read(_CHECKLIST).lower()
    assert any(kw in text for kw in ("artifact", "artefact", "pkl", "data/raw", "dataset")), (
        "final_review_checklist.md should remind reviewers not to commit local artefacts"
    )


def test_final_checklist_mentions_defensive_use():
    assert "defensive" in _read(_CHECKLIST).lower(), (
        "final_review_checklist.md should include a defensive-use check"
    )


def test_final_checklist_mentions_storage_light():
    text = _read(_CHECKLIST).lower()
    assert "storage" in text or "dataset" in text, (
        "final_review_checklist.md should include a storage-light check"
    )


def test_final_checklist_mentions_git_hygiene():
    text = _read(_CHECKLIST).lower()
    assert any(kw in text for kw in ("git", ".env", "secret", "credential")), (
        "final_review_checklist.md should include a git hygiene check"
    )


# ── docs consistency spot checks ─────────────────────────────────────────────

def test_responsible_use_mentions_human_review():
    text = _read(_RESP_USE).lower()
    assert "human" in text and "review" in text, (
        "responsible_use.md should state that human review is required"
    )


def test_responsible_use_mentions_asset_inventory():
    text = _read(_RESP_USE).lower()
    assert any(kw in text for kw in ("asset inventory", "asset", "cmdb", "sbom")), (
        "responsible_use.md should mention validating against asset inventory"
    )


def test_responsible_use_calls_scores_prioritisation_signals():
    text = _read(_RESP_USE).lower()
    assert "prioriti" in text, (
        "responsible_use.md should describe scores as prioritisation signals"
    )


def test_architecture_doc_mentions_storage_light():
    text = _read(_ARCH_DOC).lower()
    assert "storage" in text or "never" in text, (
        "project_architecture.md should explain the storage-light design"
    )


def test_api_doc_states_defensive_use():
    assert "defensive" in _read(_API_DOC).lower(), (
        "docs/api.md should state the API is for defensive use only"
    )


def test_roadmap_explicitly_excludes_rag():
    assert "rag" in _read(_ROADMAP).lower(), (
        "docs/roadmap.md should explicitly exclude RAG from scope"
    )


def test_roadmap_explicitly_excludes_full_datasets():
    text = _read(_ROADMAP).lower()
    assert any(kw in text for kw in ("full cve dataset", "dataset download", "bulk")), (
        "docs/roadmap.md should explicitly exclude full dataset downloads from scope"
    )
