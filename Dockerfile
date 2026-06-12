FROM python:3.11-slim

# ── Build-time environment ────────────────────────────────────────────────────
# Prevent .pyc files and enable unbuffered stdout/stderr for clean log streaming
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# ── OS-level dependencies ─────────────────────────────────────────────────────
# build-essential: needed for some Python wheel builds (e.g. scikit-learn extras)
# curl: needed for the HEALTHCHECK command below
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
# Copy requirements.txt first so this layer is cached unless dependencies change
COPY requirements.txt .
RUN pip install -r requirements.txt

# ── Project source ────────────────────────────────────────────────────────────
# .dockerignore excludes: .env, .venv/, data/raw/, data/processed/, model
# artefacts, reports/figures screenshots, __pycache__, .git, and other noise
COPY . .

# ── Ports ─────────────────────────────────────────────────────────────────────
# 8501 — Streamlit dashboard (default CMD)
# 8000 — FastAPI API (override CMD to use)
EXPOSE 8501
EXPOSE 8000

# ── Health check (Streamlit) ──────────────────────────────────────────────────
# Only applies when running the default Streamlit command.
# Override or disable when running FastAPI.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# ── Default command: Streamlit dashboard ─────────────────────────────────────
# To run the FastAPI API instead, override the command:
#   docker run --rm -p 8000:8000 cybershield-ai \
#     python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
CMD ["python", "-m", "streamlit", "run", "src/dashboard/app.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true"]
