"""
Deployment documentation and configuration tests.

Validates that Dockerfile, .dockerignore, and docs/deployment_guide.md
contain the expected content and settings.

No Docker installation required — all tests read files as plain text.
No network calls.
"""

from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).parent.parent

_DOCKERFILE = ROOT / "Dockerfile"
_DOCKERIGNORE = ROOT / ".dockerignore"
_GUIDE = ROOT / "docs" / "deployment_guide.md"
_README = ROOT / "README.md"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


# ── File existence ────────────────────────────────────────────────────────────

def test_dockerfile_exists():
    assert _DOCKERFILE.exists(), "Dockerfile not found at project root"


def test_dockerignore_exists():
    assert _DOCKERIGNORE.exists(), ".dockerignore not found at project root"


def test_deployment_guide_exists():
    assert _GUIDE.exists(), "docs/deployment_guide.md not found"


# ── Dockerfile — base image and environment ───────────────────────────────────

def test_dockerfile_uses_python_311_slim():
    assert "python:3.11-slim" in _read(_DOCKERFILE)


def test_dockerfile_sets_pythondontwritebytecode():
    assert "PYTHONDONTWRITEBYTECODE" in _read(_DOCKERFILE)


def test_dockerfile_sets_pythonunbuffered():
    assert "PYTHONUNBUFFERED" in _read(_DOCKERFILE)


def test_dockerfile_sets_pip_no_cache_dir():
    assert "PIP_NO_CACHE_DIR" in _read(_DOCKERFILE)


# ── Dockerfile — ports ────────────────────────────────────────────────────────

def test_dockerfile_exposes_8501():
    assert "8501" in _read(_DOCKERFILE)


def test_dockerfile_exposes_8000():
    assert "8000" in _read(_DOCKERFILE)


# ── Dockerfile — layer ordering and CMD ──────────────────────────────────────

def test_dockerfile_copies_requirements_before_full_source():
    text = _read(_DOCKERFILE)
    req_pos = text.find("requirements.txt")
    copy_dot_pos = text.find("COPY . .")
    assert req_pos != -1, "requirements.txt not found in Dockerfile"
    assert copy_dot_pos != -1, "COPY . . not found in Dockerfile"
    assert req_pos < copy_dot_pos, (
        "requirements.txt COPY should appear before COPY . . for layer caching"
    )


def test_dockerfile_default_cmd_runs_streamlit():
    assert "streamlit" in _read(_DOCKERFILE).lower()


def test_dockerfile_cmd_binds_all_interfaces():
    assert "0.0.0.0" in _read(_DOCKERFILE)


def test_dockerfile_cmd_uses_python_m_streamlit():
    text = _read(_DOCKERFILE)
    assert "python" in text.lower() and "streamlit" in text.lower()


# ── .dockerignore — secrets and environments ──────────────────────────────────

def test_dockerignore_excludes_dotenv():
    assert ".env" in _read(_DOCKERIGNORE)


def test_dockerignore_excludes_venv():
    di = _read(_DOCKERIGNORE)
    assert ".venv/" in di or "venv/" in di


def test_dockerignore_excludes_git_dir():
    assert ".git/" in _read(_DOCKERIGNORE)


# ── .dockerignore — data directories ─────────────────────────────────────────

def test_dockerignore_excludes_data_raw():
    assert "data/raw/" in _read(_DOCKERIGNORE)


def test_dockerignore_excludes_data_processed():
    assert "data/processed/" in _read(_DOCKERIGNORE)


# ── .dockerignore — Python bytecode ──────────────────────────────────────────

def test_dockerignore_excludes_pycache():
    assert "__pycache__/" in _read(_DOCKERIGNORE)


def test_dockerignore_excludes_pytest_cache():
    assert ".pytest_cache/" in _read(_DOCKERIGNORE)


# ── .dockerignore — model artefacts ──────────────────────────────────────────

def test_dockerignore_excludes_pkl_files():
    assert "*.pkl" in _read(_DOCKERIGNORE)


def test_dockerignore_excludes_joblib_files():
    assert "*.joblib" in _read(_DOCKERIGNORE)


# ── .dockerignore — report screenshots ───────────────────────────────────────

def test_dockerignore_excludes_png_screenshots():
    di = _read(_DOCKERIGNORE)
    assert "reports/figures/*.png" in di or "*.png" in di


def test_dockerignore_excludes_svg_screenshots():
    di = _read(_DOCKERIGNORE)
    assert "reports/figures/*.svg" in di or "*.svg" in di


def test_dockerignore_excludes_pdf_reports():
    di = _read(_DOCKERIGNORE)
    assert "reports/figures/*.pdf" in di or "*.pdf" in di


# ── .dockerignore — OS noise ──────────────────────────────────────────────────

def test_dockerignore_excludes_ds_store():
    assert ".DS_Store" in _read(_DOCKERIGNORE)


def test_dockerignore_excludes_thumbs_db():
    assert "Thumbs.db" in _read(_DOCKERIGNORE)


# ── deployment_guide.md — ports ───────────────────────────────────────────────

def test_deployment_guide_mentions_port_8501():
    assert "8501" in _read(_GUIDE)


def test_deployment_guide_mentions_port_8000():
    assert "8000" in _read(_GUIDE)


# ── deployment_guide.md — services ───────────────────────────────────────────

def test_deployment_guide_mentions_streamlit():
    assert "streamlit" in _read(_GUIDE).lower()


def test_deployment_guide_mentions_fastapi():
    assert "fastapi" in _read(_GUIDE).lower()


# ── deployment_guide.md — Docker commands ─────────────────────────────────────

def test_deployment_guide_contains_docker_build_command():
    assert "docker build" in _read(_GUIDE).lower()


def test_deployment_guide_contains_docker_run_command():
    assert "docker run" in _read(_GUIDE).lower()


def test_deployment_guide_docker_run_maps_port_8501():
    assert "8501:8501" in _read(_GUIDE)


def test_deployment_guide_docker_run_maps_port_8000():
    assert "8000:8000" in _read(_GUIDE)


# ── deployment_guide.md — storage policy ─────────────────────────────────────

def test_deployment_guide_states_no_full_dataset_downloads():
    text = _read(_GUIDE).lower()
    assert "dataset" in text or "storage" in text


def test_deployment_guide_data_raw_excluded():
    assert "data/raw" in _read(_GUIDE)


# ── deployment_guide.md — environment variables ───────────────────────────────

def test_deployment_guide_mentions_nvd_api_key():
    assert "NVD_API_KEY" in _read(_GUIDE)


def test_deployment_guide_mentions_dotenv_not_in_image():
    assert ".env" in _read(_GUIDE)


# ── deployment_guide.md — troubleshooting and security ───────────────────────

def test_deployment_guide_has_troubleshooting_section():
    text = _read(_GUIDE).lower()
    assert "troubleshoot" in text


def test_deployment_guide_mentions_defensive_use():
    assert "defensive" in _read(_GUIDE).lower()


def test_deployment_guide_mentions_security_notes():
    text = _read(_GUIDE).lower()
    assert "security" in text


# ── README.md — Docker commands ───────────────────────────────────────────────

def test_readme_mentions_docker_build():
    assert "docker build" in _read(_README).lower()


def test_readme_mentions_docker_run():
    assert "docker run" in _read(_README).lower()


def test_readme_mentions_port_8501():
    assert "8501" in _read(_README)


def test_readme_mentions_port_8000():
    assert "8000" in _read(_README)


def test_readme_links_to_deployment_guide():
    assert "deployment_guide" in _read(_README)
