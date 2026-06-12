"""
Repository polish tests — Milestone 11.

Validates that all governance files, GitHub community templates, and
documentation exist and contain the expected content markers.

No network calls. No Docker required.
"""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).parent.parent

# ── Path constants ────────────────────────────────────────────────────────────
_CONTRIBUTING  = ROOT / "CONTRIBUTING.md"
_SECURITY      = ROOT / "SECURITY.md"
_CHANGELOG     = ROOT / "CHANGELOG.md"
_ROADMAP       = ROOT / "docs" / "roadmap.md"
_RELEASE_NOTES = ROOT / "docs" / "release_notes_v0.1.0.md"
_PR_TEMPLATE   = ROOT / ".github" / "pull_request_template.md"
_BUG_REPORT    = ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.md"
_FEATURE_REQ   = ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.md"
_DOCS_UPDATE   = ROOT / ".github" / "ISSUE_TEMPLATE" / "documentation_update.md"
_README        = ROOT / "README.md"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


# ── Governance files: existence ───────────────────────────────────────────────

def test_contributing_exists():
    assert _CONTRIBUTING.exists(), "CONTRIBUTING.md not found at project root"


def test_security_exists():
    assert _SECURITY.exists(), "SECURITY.md not found at project root"


def test_changelog_exists():
    assert _CHANGELOG.exists(), "CHANGELOG.md not found at project root"


def test_roadmap_exists():
    assert _ROADMAP.exists(), "docs/roadmap.md not found"


def test_release_notes_exist():
    assert _RELEASE_NOTES.exists(), "docs/release_notes_v0.1.0.md not found"


# ── GitHub templates: existence ───────────────────────────────────────────────

def test_pr_template_exists():
    assert _PR_TEMPLATE.exists(), ".github/pull_request_template.md not found"


def test_bug_report_template_exists():
    assert _BUG_REPORT.exists(), ".github/ISSUE_TEMPLATE/bug_report.md not found"


def test_feature_request_template_exists():
    assert _FEATURE_REQ.exists(), ".github/ISSUE_TEMPLATE/feature_request.md not found"


def test_documentation_update_template_exists():
    assert _DOCS_UPDATE.exists(), ".github/ISSUE_TEMPLATE/documentation_update.md not found"


# ── SECURITY.md content ───────────────────────────────────────────────────────

def test_security_mentions_responsible_disclosure():
    text = _read(_SECURITY).lower()
    assert "responsible disclosure" in text or "disclosure" in text, (
        "SECURITY.md should describe a responsible disclosure process"
    )


def test_security_mentions_reporting_instructions():
    text = _read(_SECURITY).lower()
    assert any(kw in text for kw in ("email", "report", "contact")), (
        "SECURITY.md should explain how to report a security issue"
    )


def test_security_does_not_include_exploit_instructions():
    # "exploit code" legitimately appears in prohibition statements ("does not provide exploit code").
    # These phrases would only appear if SECURITY.md were actually providing offensive content.
    text = _read(_SECURITY).lower()
    bad_phrases = ["shellcode", "msfconsole", "bind shell", "reverse shell payload", "here is how to exploit"]
    for phrase in bad_phrases:
        assert phrase not in text, (
            f"SECURITY.md must not contain offensive exploit content (found: '{phrase}')"
        )


def test_security_states_no_exploit_content():
    text = _read(_SECURITY).lower()
    assert "exploit" in text, (
        "SECURITY.md should explicitly state the project provides no exploit instructions"
    )
    assert "defensive" in text, (
        "SECURITY.md should mention the project's defensive scope"
    )


def test_security_mentions_supported_versions():
    text = _read(_SECURITY).lower()
    assert any(kw in text for kw in ("version", "supported", "main")), (
        "SECURITY.md should describe which versions are supported"
    )


# ── CONTRIBUTING.md content ───────────────────────────────────────────────────

def test_contributing_mentions_defensive_use():
    text = _read(_CONTRIBUTING).lower()
    assert "defensive" in text, (
        "CONTRIBUTING.md should mention the defensive-use policy"
    )


def test_contributing_mentions_no_exploit_code():
    text = _read(_CONTRIBUTING).lower()
    assert "exploit" in text, (
        "CONTRIBUTING.md should explicitly prohibit exploit code in contributions"
    )


def test_contributing_mentions_no_dataset_downloads():
    text = _read(_CONTRIBUTING).lower()
    assert any(kw in text for kw in ("dataset", "data/raw", "download")), (
        "CONTRIBUTING.md should address the no-dataset-download constraint"
    )


def test_contributing_mentions_no_secrets():
    text = _read(_CONTRIBUTING).lower()
    assert any(kw in text for kw in ("secret", "credential", "api key", ".env")), (
        "CONTRIBUTING.md should address the no-committed-secrets rule"
    )


def test_contributing_mentions_running_tests():
    text = _read(_CONTRIBUTING).lower()
    assert "pytest" in text, (
        "CONTRIBUTING.md should explain how to run the test suite"
    )


def test_contributing_mentions_setup():
    text = _read(_CONTRIBUTING).lower()
    assert any(kw in text for kw in ("pip install", "venv", "requirements")), (
        "CONTRIBUTING.md should include development setup instructions"
    )


def test_contributing_does_not_include_exploit_instructions():
    # "exploit code" and "shellcode" legitimately appear in the prohibited-items table.
    # Use phrases that would only appear if CONTRIBUTING.md were actually providing
    # offensive content, not just listing what is forbidden.
    text = _read(_CONTRIBUTING).lower()
    bad_phrases = ["msfconsole", "bind shell", "reverse shell payload", "here is how to exploit"]
    for phrase in bad_phrases:
        assert phrase not in text, (
            f"CONTRIBUTING.md must not contain offensive exploit content (found: '{phrase}')"
        )


# ── CHANGELOG.md content ──────────────────────────────────────────────────────

def test_changelog_mentions_v010():
    assert "v0.1.0" in _read(_CHANGELOG), (
        "CHANGELOG.md must contain a v0.1.0 section"
    )


def test_changelog_mentions_storage_light():
    text = _read(_CHANGELOG).lower()
    assert any(kw in text for kw in ("storage-light", "storage light", "api-first", "api first")), (
        "CHANGELOG.md should mention the storage-light, API-first architecture"
    )


def test_changelog_mentions_defensive():
    assert "defensive" in _read(_CHANGELOG).lower(), (
        "CHANGELOG.md should note the defensive-use policy"
    )


# ── docs/roadmap.md content ───────────────────────────────────────────────────

def test_roadmap_mentions_no_full_dataset_downloads():
    text = _read(_ROADMAP).lower()
    assert any(kw in text for kw in ("dataset", "data/raw", "full cve")), (
        "roadmap.md should mention that full dataset downloads are excluded"
    )


def test_roadmap_mentions_excluded_scope():
    text = _read(_ROADMAP).lower()
    excluded = ["rag", "langchain", "vector database", "exploit", "offensive"]
    found = [kw for kw in excluded if kw in text]
    assert found, (
        "roadmap.md should explicitly list excluded scope items (RAG, LangChain, exploit gen, etc.)"
    )


def test_roadmap_mentions_completed_milestones():
    text = _read(_ROADMAP).lower()
    assert any(kw in text for kw in ("milestone", "completed", "done")), (
        "roadmap.md should list completed milestones"
    )


def test_roadmap_mentions_future_work():
    text = _read(_ROADMAP).lower()
    assert any(kw in text for kw in ("future", "planned", "near-term", "next")), (
        "roadmap.md should describe future planned work"
    )


# ── docs/release_notes_v0.1.0.md content ─────────────────────────────────────

def test_release_notes_mention_streamlit():
    assert "streamlit" in _read(_RELEASE_NOTES).lower()


def test_release_notes_mention_fastapi():
    assert "fastapi" in _read(_RELEASE_NOTES).lower()


def test_release_notes_mention_how_to_run_tests():
    text = _read(_RELEASE_NOTES).lower()
    assert "pytest" in text, "Release notes should include how to run tests"


def test_release_notes_mention_docker():
    assert "docker" in _read(_RELEASE_NOTES).lower()


def test_release_notes_mention_limitations():
    text = _read(_RELEASE_NOTES).lower()
    assert any(kw in text for kw in ("limitation", "known", "caveat")), (
        "Release notes should include a limitations section"
    )


def test_release_notes_mention_responsible_use():
    assert "responsible" in _read(_RELEASE_NOTES).lower()


# ── Pull request template content ────────────────────────────────────────────

def test_pr_template_has_tests_checklist_item():
    text = _read(_PR_TEMPLATE).lower()
    assert "pytest" in text or "test" in text, (
        "PR template should include a checklist item for passing tests"
    )


def test_pr_template_has_no_secrets_checklist_item():
    text = _read(_PR_TEMPLATE).lower()
    assert any(kw in text for kw in ("secret", "credential", "api key", ".env")), (
        "PR template should include a checklist item about not committing secrets"
    )


def test_pr_template_has_no_datasets_checklist_item():
    text = _read(_PR_TEMPLATE).lower()
    assert any(kw in text for kw in ("dataset", "data/raw", "data/processed")), (
        "PR template should include a checklist item about not adding full datasets"
    )


def test_pr_template_mentions_defensive_scope():
    text = _read(_PR_TEMPLATE).lower()
    assert "offensive" in text or "defensive" in text or "exploit" in text, (
        "PR template should include a check for defensive scope"
    )


def test_pr_template_mentions_ci():
    text = _read(_PR_TEMPLATE).lower()
    assert any(kw in text for kw in ("ci", "github actions", "pipeline")), (
        "PR template should mention CI passing"
    )


def test_pr_template_does_not_contain_exploit_instructions():
    # "exploit code" appears in the defensive checklist item ("does not include exploit code").
    # These phrases would only appear if the template were providing offensive guidance.
    text = _read(_PR_TEMPLATE).lower()
    bad_phrases = ["shellcode", "msfconsole", "bind shell", "here is how to exploit"]
    for phrase in bad_phrases:
        assert phrase not in text, (
            f"PR template must not contain offensive exploit content (found: '{phrase}')"
        )


# ── Issue templates content ───────────────────────────────────────────────────

def test_bug_report_asks_about_external_apis():
    text = _read(_BUG_REPORT).lower()
    assert any(kw in text for kw in ("nvd", "cisa", "external api", "api call")), (
        "Bug report template should ask whether the issue involves real external APIs"
    )


def test_bug_report_asks_for_steps_to_reproduce():
    text = _read(_BUG_REPORT).lower()
    assert "steps" in text or "reproduce" in text, (
        "Bug report template should ask for steps to reproduce"
    )


def test_feature_request_asks_about_defensive_use():
    text = _read(_FEATURE_REQ).lower()
    assert "defensive" in text, (
        "Feature request template should ask for the defensive use case"
    )


def test_feature_request_asks_about_storage_impact():
    text = _read(_FEATURE_REQ).lower()
    assert any(kw in text for kw in ("storage", "dataset", "download")), (
        "Feature request template should ask about storage and data download impact"
    )


def test_feature_request_asks_about_new_dependencies():
    text = _read(_FEATURE_REQ).lower()
    assert any(kw in text for kw in ("depend", "package", "requirements")), (
        "Feature request template should ask whether new dependencies are required"
    )


def test_feature_request_does_not_contain_exploit_instructions():
    # "exploit code" appears in the out-of-scope checklist ("does not involve exploit code").
    # These phrases would only appear if the template were providing offensive guidance.
    text = _read(_FEATURE_REQ).lower()
    bad_phrases = ["shellcode", "msfconsole", "bind shell", "here is how to exploit"]
    for phrase in bad_phrases:
        assert phrase not in text, (
            f"Feature request template must not contain offensive exploit content (found: '{phrase}')"
        )


def test_docs_update_template_asks_which_file():
    text = _read(_DOCS_UPDATE).lower()
    assert any(kw in text for kw in ("file", "page", "doc")), (
        "Documentation update template should ask which file needs updating"
    )


def test_docs_update_template_asks_what_clarification_needed():
    text = _read(_DOCS_UPDATE).lower()
    assert any(kw in text for kw in ("clarif", "incorrect", "unclear", "missing")), (
        "Documentation update template should ask what clarification is needed"
    )


# ── README links to governance files ─────────────────────────────────────────

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


def test_readme_links_to_roadmap():
    assert "roadmap" in _read(_README).lower(), (
        "README.md should link to docs/roadmap.md"
    )


def test_readme_has_project_status_section():
    text = _read(_README).lower()
    assert any(kw in text for kw in ("project status", "status")), (
        "README.md should include a project status section"
    )


def test_readme_has_what_this_is_not_section():
    text = _read(_README).lower()
    assert any(kw in text for kw in ("what this project is not", "not", "scope")), (
        "README.md should include a 'What this project is not' or equivalent section"
    )


def test_readme_milestone_11_complete():
    text = _read(_README)
    assert "11" in text and "Done" in text, (
        "README.md should mark Milestone 11 as complete"
    )
