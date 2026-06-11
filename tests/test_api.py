"""
Tests for src/api/main.py (FastAPI defensive scoring API).
Uses FastAPI TestClient only — no network calls, no NVD/CISA requests,
no dataset downloads.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.main import app

client = TestClient(app)

# ── Shared test fixtures ──────────────────────────────────────────────────────

_BASIC_INPUT = {
    "cve_id": "CVE-2024-TEST01",
    "severity": "HIGH",
    "base_score": 8.5,
    "attack_vector": "NETWORK",
    "cwe": "CWE-89",
    "published": "2023-01-15T00:00:00.000",
    "in_kev": False,
}

_KEV_INPUT = {
    "cve_id": "CVE-2024-KEV01",
    "severity": "CRITICAL",
    "base_score": 9.8,
    "attack_vector": "NETWORK",
    "cwe": "CWE-20",
    "published": "2023-01-15T00:00:00.000",
    "in_kev": True,
}

_LOW_RISK_INPUT = {
    "cve_id": "CVE-2024-LOW01",
    "severity": "LOW",
    "base_score": 2.0,
    "attack_vector": "LOCAL",
    "cwe": "UNKNOWN",
    "published": "2024-03-01T00:00:00.000",
    "in_kev": False,
}

_UNKNOWN_INPUT = {
    "cve_id": "CVE-2024-UNK01",
    "severity": "UNKNOWN",
    "base_score": 5.0,
    "attack_vector": "UNKNOWN",
    "cwe": "UNKNOWN",
    "published": None,
    "in_kev": False,
}

# ── /health ───────────────────────────────────────────────────────────────────

def test_health_returns_200():
    assert client.get("/health").status_code == 200


def test_health_status_is_ok():
    assert client.get("/health").json()["status"] == "ok"


def test_health_has_service_name():
    assert "service" in client.get("/health").json()


def test_health_has_defensive_use_note():
    data = client.get("/health").json()
    assert "note" in data
    note_lower = data["note"].lower()
    assert "defensive" in note_lower or "exploit" in note_lower


# ── /version ─────────────────────────────────────────────────────────────────

def test_version_returns_200():
    assert client.get("/version").status_code == 200


def test_version_has_project_name():
    assert "project" in client.get("/version").json()


def test_version_has_api_version():
    assert "api_version" in client.get("/version").json()


def test_version_has_milestone():
    assert "milestone" in client.get("/version").json()


def test_version_storage_policy_mentions_datasets():
    data = client.get("/version").json()
    assert "storage_policy" in data
    policy = data["storage_policy"].lower()
    assert "dataset" in policy or "storage" in policy


# ── /score — happy path ───────────────────────────────────────────────────────

def test_score_returns_200():
    assert client.post("/score", json=_BASIC_INPUT).status_code == 200


def test_score_returns_risk_score_in_valid_range():
    data = client.post("/score", json=_BASIC_INPUT).json()
    assert "risk_score" in data
    assert 0.0 <= data["risk_score"] <= 100.0


def test_score_returns_normalized_features_with_all_keys():
    data = client.post("/score", json=_BASIC_INPUT).json()
    nf = data["normalized_features"]
    for key in ("severity_numeric", "base_score", "attack_vector_numeric", "age_days", "kev_numeric"):
        assert key in nf, f"normalized_features missing key: {key}"


def test_score_returns_valid_risk_band():
    data = client.post("/score", json=_BASIC_INPUT).json()
    assert data["risk_band"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_score_returns_defensive_interpretation():
    data = client.post("/score", json=_BASIC_INPUT).json()
    assert "defensive_interpretation" in data
    assert len(data["defensive_interpretation"]) > 10


def test_score_returns_responsible_use_note():
    data = client.post("/score", json=_BASIC_INPUT).json()
    assert "responsible_use_note" in data
    assert len(data["responsible_use_note"]) > 10


def test_score_cve_id_preserved_in_response():
    data = client.post("/score", json=_BASIC_INPUT).json()
    assert data["cve_id"] == _BASIC_INPUT["cve_id"]


# ── /score — KEV input ────────────────────────────────────────────────────────

def test_score_kev_input_risk_score_above_70():
    data = client.post("/score", json=_KEV_INPUT).json()
    assert data["risk_score"] > 70.0


def test_score_kev_input_risk_band_critical():
    data = client.post("/score", json=_KEV_INPUT).json()
    assert data["risk_band"] == "CRITICAL"


def test_score_kev_numeric_is_1_for_kev_input():
    data = client.post("/score", json=_KEV_INPUT).json()
    assert data["normalized_features"]["kev_numeric"] == 1


# ── /score — edge cases and safety ───────────────────────────────────────────

def test_score_handles_unknown_severity_without_error():
    assert client.post("/score", json=_UNKNOWN_INPUT).status_code == 200


def test_score_handles_null_published_date():
    inp = dict(_BASIC_INPUT)
    inp["published"] = None
    assert client.post("/score", json=inp).status_code == 200


def test_score_handles_missing_published_field():
    inp = {k: v for k, v in _BASIC_INPUT.items() if k != "published"}
    assert client.post("/score", json=inp).status_code == 200


def test_score_rejects_base_score_above_10():
    inp = dict(_BASIC_INPUT)
    inp["base_score"] = 10.1
    assert client.post("/score", json=inp).status_code == 422


def test_score_rejects_base_score_below_0():
    inp = dict(_BASIC_INPUT)
    inp["base_score"] = -0.1
    assert client.post("/score", json=inp).status_code == 422


def test_score_accepts_base_score_at_boundary_zero():
    inp = dict(_BASIC_INPUT)
    inp["base_score"] = 0.0
    assert client.post("/score", json=inp).status_code == 200


def test_score_accepts_base_score_at_boundary_ten():
    inp = dict(_BASIC_INPUT)
    inp["base_score"] = 10.0
    assert client.post("/score", json=inp).status_code == 200


def test_score_low_risk_band_for_low_risk_input():
    data = client.post("/score", json=_LOW_RISK_INPUT).json()
    assert data["risk_band"] in ("LOW", "MEDIUM")


# ── /score — no offensive content ────────────────────────────────────────────

def test_score_response_contains_no_exploit_instructions():
    text = str(client.post("/score", json=_BASIC_INPUT).json()).lower()
    for term in ("exploit code", "shellcode", "payload", "reverse shell", "metasploit", "attack step"):
        assert term not in text, f"Offensive term found in response: '{term}'"


# ── /recommend — happy path ───────────────────────────────────────────────────

def test_recommend_returns_200():
    assert client.post("/recommend", json=_BASIC_INPUT).status_code == 200


def test_recommend_has_all_required_fields():
    data = client.post("/recommend", json=_BASIC_INPUT).json()
    for key in (
        "cve_id", "risk_score", "priority_level", "action_title",
        "recommendation", "rationale", "suggested_sla",
        "escalation_required", "responsible_use_note",
    ):
        assert key in data, f"Response missing field: {key}"


def test_recommend_priority_level_is_valid():
    data = client.post("/recommend", json=_BASIC_INPUT).json()
    assert data["priority_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_recommend_risk_score_in_valid_range():
    data = client.post("/recommend", json=_BASIC_INPUT).json()
    assert 0.0 <= data["risk_score"] <= 100.0


def test_recommend_cve_id_preserved():
    data = client.post("/recommend", json=_BASIC_INPUT).json()
    assert data["cve_id"] == _BASIC_INPUT["cve_id"]


# ── /recommend — KEV input ────────────────────────────────────────────────────

def test_recommend_kev_high_risk_escalation_required():
    data = client.post("/recommend", json=_KEV_INPUT).json()
    assert data["escalation_required"] is True


def test_recommend_kev_high_risk_priority_critical():
    data = client.post("/recommend", json=_KEV_INPUT).json()
    assert data["priority_level"] == "CRITICAL"


# ── /recommend — low risk input ───────────────────────────────────────────────

def test_recommend_low_risk_escalation_not_required():
    data = client.post("/recommend", json=_LOW_RISK_INPUT).json()
    assert data["escalation_required"] is False


def test_recommend_low_risk_priority_not_critical():
    data = client.post("/recommend", json=_LOW_RISK_INPUT).json()
    assert data["priority_level"] != "CRITICAL"


# ── /recommend — responsible use ─────────────────────────────────────────────

def test_recommend_includes_responsible_use_note():
    data = client.post("/recommend", json=_BASIC_INPUT).json()
    assert len(data["responsible_use_note"]) > 10


def test_recommend_response_contains_no_exploit_instructions():
    text = str(client.post("/recommend", json=_BASIC_INPUT).json()).lower()
    for term in ("exploit code", "shellcode", "payload", "reverse shell", "metasploit", "attack step"):
        assert term not in text, f"Offensive term found in response: '{term}'"


# ── /recommend — edge cases ───────────────────────────────────────────────────

def test_recommend_handles_unknown_severity():
    assert client.post("/recommend", json=_UNKNOWN_INPUT).status_code == 200


def test_recommend_handles_null_published():
    inp = dict(_BASIC_INPUT)
    inp["published"] = None
    assert client.post("/recommend", json=inp).status_code == 200


def test_recommend_rejects_base_score_above_10():
    inp = dict(_BASIC_INPUT)
    inp["base_score"] = 11.0
    assert client.post("/recommend", json=inp).status_code == 422
