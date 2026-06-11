# run_app.ps1 — start the CyberShield AI dashboard (Windows PowerShell)
# Usage:  .\run_app.ps1

param(
    [string]$Port = "8501"
)

$ErrorActionPreference = "Stop"

# Activate virtual environment if present
if (Test-Path ".\.venv\Scripts\Activate.ps1") {
    . .\.venv\Scripts\Activate.ps1
    Write-Host "[run_app] Virtual environment activated." -ForegroundColor Green
} else {
    Write-Host "[run_app] No .venv found — using system Python." -ForegroundColor Yellow
}

# Copy .env.example to .env if .env does not exist yet
if (-not (Test-Path ".\.env")) {
    Copy-Item ".\.env.example" ".\.env"
    Write-Host "[run_app] Created .env from .env.example — add your API keys." -ForegroundColor Cyan
}

Write-Host "[run_app] Starting Streamlit on http://localhost:$Port" -ForegroundColor Green
streamlit run src\dashboard\app.py `
    --server.port $Port `
    --server.headless false
