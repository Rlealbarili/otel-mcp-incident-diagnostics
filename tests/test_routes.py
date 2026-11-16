"""
Unit & Integration Tests for backend/routes/health_routes.py, backend/routes/patient_routes.py, and backend/main.py
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_main_root_endpoint():
    """Verifies GET / root endpoint on main app."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "health-observability-backend"
    assert data["status"] == "operational"


def test_get_health_status():
    """Verifies GET /api/v1/health-status returns system readiness and telemetry trace IDs."""
    response = client.get("/api/v1/health-status")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "health-observability-backend"
    assert "checks" in data
    assert data["checks"]["loki_collector"] == "connected"
    assert "telemetry" in data
    assert "trace_id" in data["telemetry"]


def test_ingest_health_event():
    """Verifies POST /api/v1/health-events ingests telemetry event and returns HTTP 202 Accepted."""
    payload = {
        "patient_hash": "patient_hash_0123456789abcdef",
        "event_type": "vital_sign_alert",
        "payload": {
            "heart_rate": 110,
            "spo2": 94,
            "notes": "Patient CPF 123.456.789-00 elevated heart rate",
        },
        "source": "icu_monitor",
    }
    response = client.post("/api/v1/health-events", json=payload)
    assert response.status_code == 202
    data = response.json()

    assert data["status"] == "accepted"
    assert "event_id" in data
    assert "trace_id" in data


def test_get_patient_status_success():
    """Verifies GET /api/v1/patients/{patient_hash}/status returns patient vital signs for valid hash."""
    patient_hash = "patient_hash_abcdef0123456789"
    response = client.get(f"/api/v1/patients/{patient_hash}/status")
    assert response.status_code == 200
    data = response.json()

    assert data["patient_hash"] == patient_hash
    assert data["risk_level"] == "NORMAL"
    assert "latest_vital_signs" in data


def test_get_patient_status_rejects_raw_phi_in_path():
    """Verifies GET /api/v1/patients/{patient_hash}/status rejects raw CPF in path parameter with HTTP 400."""
    raw_cpf = "123.456.789-00"
    response = client.get(f"/api/v1/patients/{raw_cpf}/status")
    assert response.status_code == 400
    data = response.json()
    assert "Raw PHI/PII is prohibited" in data["detail"]


def test_query_diagnostic_ai_success():
    """Verifies POST /api/v1/patients/query-diagnostic executes diagnostic AI reasoning."""
    payload = {
        "patient_hash": "patient_hash_abcdef0123456789",
        "clinical_question": "Does the patient show signs of acute arrhythmia given SpO2 99% and HR 74?",
        "diagnostic_model": "medlm-large",
    }
    response = client.post("/api/v1/patients/query-diagnostic", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["patient_hash"] == payload["patient_hash"]
    assert data["model_used"] == "medlm-large"
    assert "usage" in data
    assert data["usage"]["prompt_tokens"] == 340
    assert data["usage"]["completion_tokens"] == 120
    assert data["usage"]["total_tokens"] == 460


def test_query_diagnostic_ai_rejects_raw_phi_in_body():
    """Verifies POST /api/v1/patients/query-diagnostic fails validation if question contains raw CPF."""
    payload = {
        "patient_hash": "patient_hash_abcdef0123456789",
        "clinical_question": "Patient CPF 123.456.789-00 needs diagnostic review.",
        "diagnostic_model": "medlm-large",
    }
    response = client.post("/api/v1/patients/query-diagnostic", json=payload)
    assert response.status_code == 422
