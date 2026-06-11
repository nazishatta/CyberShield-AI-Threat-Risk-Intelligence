"""
CyberShield AI — FastAPI defensive scoring API.

Exposes rule-based CVE risk scoring and mitigation recommendation endpoints.
All output is defensive guidance only — no exploit instructions are provided.
Run:  python -m uvicorn src.api.main:app --reload
Docs: http://127.0.0.1:8000/docs
"""

from __future__ import annotations

from typing import Optional

import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel, Field

from src.features.feature_engineering import build_features
from src.recommendations.mitigation import recommend_mitigation

_API_VERSION = "1.0.0"
_MILESTONE = "8"
_PROJECT = "CyberShield-AI-Threat-Risk-Intelligence"

_RESPONSIBLE_USE_NOTE = (
    "This score is derived from public CVE metadata (CVSS, CISA KEV) and is "
    "intended to assist defenders in prioritisation — it does not certify "
    "exploitability or replace professional security assessment."
)

_STORAGE_POLICY = (
    "API-first, storage-light. No full CVE datasets are downloaded or stored "
    "locally. All scoring runs in-memory from the values you submit."
)

# ── Pydantic request / response models ───────────────────────────────────────

class CVEInput(BaseModel):
    """CVE metadata submitted for scoring or recommendation."""

    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")
    severity: str = Field(
        default="UNKNOWN",
        description="CVSS severity label: CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN",
    )
    base_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="CVSS base score between 0.0 and 10.0",
    )
    attack_vector: str = Field(
        default="UNKNOWN",
        description="CVSS attack vector: NETWORK, ADJACENT, LOCAL, PHYSICAL, or UNKNOWN",
    )
    cwe: str = Field(
        default="UNKNOWN",
        description="CWE identifier, e.g. CWE-79. Pass UNKNOWN if not available.",
    )
    published: Optional[str] = Field(
        default=None,
        description="ISO-8601 publication date, e.g. 2024-01-15T00:00:00.000. "
                    "Omit or pass null if unknown.",
    )
    in_kev: bool = Field(
        default=False,
        description="True if this CVE appears in the CISA Known Exploited Vulnerabilities catalogue.",
    )

    model_config = {"json_schema_extra": {
        "example": {
            "cve_id": "CVE-2024-12345",
            "severity": "HIGH",
            "base_score": 8.5,
            "attack_vector": "NETWORK",
            "cwe": "CWE-89",
            "published": "2023-06-01T00:00:00.000",
            "in_kev": False,
        }
    }}


class NormalizedFeatures(BaseModel):
    """Ordinal-encoded features used by the risk scorer."""

    severity_numeric: int = Field(description="0 (UNKNOWN/NONE) … 4 (CRITICAL)")
    base_score: float = Field(description="CVSS base score 0.0–10.0")
    attack_vector_numeric: int = Field(description="0 (UNKNOWN) … 4 (NETWORK)")
    age_days: int = Field(description="Days since CVE publication; -1 if unknown")
    kev_numeric: int = Field(description="1 if in CISA KEV, else 0")


class ScoreResponse(BaseModel):
    """Risk scoring result for a single CVE."""

    cve_id: str
    normalized_features: NormalizedFeatures
    risk_score: float = Field(description="Composite 0–100 risk score")
    risk_band: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW")
    defensive_interpretation: str = Field(
        description="Plain-English summary of what this score means for defenders"
    )
    responsible_use_note: str


class RecommendResponse(BaseModel):
    """Defensive mitigation recommendation for a single CVE."""

    cve_id: str
    risk_score: float
    priority_level: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW")
    action_title: str
    recommendation: str = Field(
        description="Defensive remediation steps. No exploit instructions."
    )
    rationale: str
    suggested_sla: str
    escalation_required: bool
    responsible_use_note: str


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="CyberShield AI — Defensive Scoring API",
    description=(
        "Rule-based CVE risk scoring and defensive mitigation recommendations "
        "derived from public NVD CVSS metadata and CISA KEV status. "
        "**Defensive use only.** No exploit instructions are provided. "
        "No full vulnerability datasets are downloaded or stored."
    ),
    version=_API_VERSION,
    contact={"name": "CyberShield AI", "url": "https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence"},
    license_info={"name": "MIT"},
)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _build_feature_row(inp: CVEInput) -> pd.Series:
    """Convert a CVEInput into a single-row feature Series via build_features()."""
    record = {
        "cve_id": inp.cve_id,
        "severity": (inp.severity or "UNKNOWN").strip().upper() or "UNKNOWN",
        "base_score": inp.base_score,
        "attack_vector": (inp.attack_vector or "UNKNOWN").strip().upper() or "UNKNOWN",
        "cwe": inp.cwe or "UNKNOWN",
        "published": inp.published or "",
    }
    kev_ids = {inp.cve_id} if inp.in_kev else set()
    df = build_features([record], kev_ids=kev_ids)
    return df.iloc[0]


def _risk_band(risk_score: float, in_kev: bool) -> str:
    if in_kev and risk_score >= 70.0:
        return "CRITICAL"
    if risk_score >= 70.0:
        return "HIGH"
    if risk_score >= 40.0:
        return "MEDIUM"
    return "LOW"


def _defensive_interpretation(band: str, risk_score: float) -> str:
    rs = f"{risk_score:.0f}/100"
    if band == "CRITICAL":
        return (
            f"Risk score {rs}. This CVE is listed in the CISA Known Exploited "
            "Vulnerabilities (KEV) catalogue with a high composite score, indicating "
            "confirmed active exploitation. Immediate remediation is required."
        )
    if band == "HIGH":
        return (
            f"Risk score {rs}. Strong exploitability indicators present — high CVSS "
            "base score, network-reachable attack vector, or both. Prioritise patching "
            "and assess exposed attack surface."
        )
    if band == "MEDIUM":
        return (
            f"Risk score {rs}. Moderate risk indicators. Schedule remediation within "
            "your standard patch management cycle and consider compensating controls."
        )
    return (
        f"Risk score {rs}. Low risk based on current CVSS characteristics. "
        "Include in routine patch management."
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", summary="Service health check")
def health() -> dict:
    """Returns service liveness status and a defensive-use note."""
    return {
        "status": "ok",
        "service": "CyberShield AI — Defensive Scoring API",
        "note": (
            "This service provides defensive vulnerability scoring only. "
            "No exploit instructions, attack steps, or offensive scanning "
            "capabilities are exposed."
        ),
    }


@app.get("/version", summary="API version and storage policy")
def version() -> dict:
    """Returns project name, API version, milestone, and storage-light statement."""
    return {
        "project": _PROJECT,
        "api_version": _API_VERSION,
        "milestone": _MILESTONE,
        "storage_policy": _STORAGE_POLICY,
    }


@app.post(
    "/score",
    response_model=ScoreResponse,
    summary="Score a CVE for defensive risk prioritisation",
)
def score(inp: CVEInput) -> ScoreResponse:
    """
    Accepts CVE metadata and returns a normalized feature set, a 0–100 risk
    score, a risk band (CRITICAL/HIGH/MEDIUM/LOW), a plain-English defensive
    interpretation, and a responsible-use note.

    **No exploit instructions are included in the response.**
    """
    row = _build_feature_row(inp)
    rs = float(row["risk_score"])
    band = _risk_band(rs, inp.in_kev)
    return ScoreResponse(
        cve_id=inp.cve_id,
        normalized_features=NormalizedFeatures(
            severity_numeric=int(row["severity_numeric"]),
            base_score=float(row["base_score"]),
            attack_vector_numeric=int(row["attack_vector_numeric"]),
            age_days=int(row["age_days"]),
            kev_numeric=int(row["kev_numeric"]),
        ),
        risk_score=rs,
        risk_band=band,
        defensive_interpretation=_defensive_interpretation(band, rs),
        responsible_use_note=_RESPONSIBLE_USE_NOTE,
    )


@app.post(
    "/recommend",
    response_model=RecommendResponse,
    summary="Get a defensive mitigation recommendation for a CVE",
)
def recommend(inp: CVEInput) -> RecommendResponse:
    """
    Accepts CVE metadata and returns a prioritised defensive remediation
    recommendation including action title, rationale, suggested SLA, and
    escalation flag.

    Guidance is based on public CVSS metadata and CISA KEV status.
    **No exploit instructions or attack steps are included.**
    """
    row = _build_feature_row(inp)
    rec = recommend_mitigation(row)
    return RecommendResponse(
        cve_id=inp.cve_id,
        risk_score=float(row["risk_score"]),
        priority_level=rec["priority_level"],
        action_title=rec["action_title"],
        recommendation=rec["recommendation"],
        rationale=rec["rationale"],
        suggested_sla=rec["suggested_sla"],
        escalation_required=bool(rec["escalation_required"]),
        responsible_use_note=rec["responsible_use_note"],
    )
