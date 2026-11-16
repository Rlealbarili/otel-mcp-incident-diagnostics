"""
Adversarial PHI/PII Redaction & Anonymization Test Harness (Milestone 3 Challenge)

Empirically tests edge-case payloads, obfuscated patterns, nested structures,
unformatted identifiers, patient names, dates of birth, fail-closed mechanics,
and zero-leakage assertions across:
- backend/middleware/sanitize.py (sanitize_payload)
- backend/workers/health_ingestion.py (anonymize_patient_id, stream ingestion)
- backend/middleware/telemetry.py (StructuredJSONLogFormatter, TelemetryMiddleware)
- backend/routes/patient_routes.py (GET /status, POST /query-diagnostic)
- backend/routes/health_routes.py (POST /health-events)
"""

import io
import json
import logging
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.middleware.sanitize import (
    sanitize_payload,
    REDACTED_TOKEN,
    REGEX_CPF,
    REGEX_SSN,
    REGEX_EMAIL,
)
from backend.workers.health_ingestion import anonymize_patient_id, HealthIngestionWorker
from backend.middleware.telemetry import StructuredJSONLogFormatter

client = TestClient(app)


# Strict helper assertion: checks for presence of any known PHI/PII string in output
def assert_string_does_not_contain(text: str, forbidden_strings: list):
    for forbidden in forbidden_strings:
        assert forbidden not in text, f"PHI/PII LEAK DETECTED: Found forbidden string '{forbidden}' in text: {text}"


# ============================================================================
# 1. EDGE-CASE & OBFUSCATED PAYLOAD SANITIZATION TESTS
# ============================================================================

def test_formatted_cpf_redaction():
    """Formatted CPF 123.456.789-00 must be redacted."""
    raw = "Patient CPF 123.456.789-00 admitted"
    result = sanitize_payload(raw)
    assert REDACTED_TOKEN in result
    assert "123.456.789-00" not in result


def test_unformatted_cpf_redaction_failure():
    """EMPIRICAL CHALLENGE: Unformatted CPF 12345678900 (11 raw digits)."""
    raw = "Patient CPF 12345678900 admitted"
    result = sanitize_payload(raw)
    # Check if unformatted CPF is leaked
    is_redacted = ("12345678900" not in result)
    print(f"\n[EMPIRICAL TEST] Unformatted CPF ('12345678900'): Redacted? {is_redacted} | Result: '{result}'")
    assert is_redacted, f"FAILURE: Unformatted CPF 12345678900 leaked through sanitize_payload! Result: '{result}'"


def test_cpf_alternative_delimiters():
    """EMPIRICAL CHALLENGE: CPF with spaces or slashes (e.g. 123 456 789 00 or 123/456/789-00)."""
    raw_space = "CPF 123 456 789 00 report"
    raw_slash = "CPF 123/456/789-00 report"
    res_space = sanitize_payload(raw_space)
    res_slash = sanitize_payload(raw_slash)

    print(f"\n[EMPIRICAL TEST] Space-delimited CPF: Leaked? {'123 456 789 00' in res_space}")
    print(f"[EMPIRICAL TEST] Slash-delimited CPF: Leaked? {'123/456/789-00' in res_slash}")

    assert "123 456 789 00" not in res_space, f"FAILURE: Space-delimited CPF leaked! Result: '{res_space}'"
    assert "123/456/789-00" not in res_slash, f"FAILURE: Slash-delimited CPF leaked! Result: '{res_slash}'"


def test_formatted_ssn_redaction():
    """Formatted SSN 123-45-6789 must be redacted."""
    raw = "SSN 123-45-6789 recorded"
    result = sanitize_payload(raw)
    assert REDACTED_TOKEN in result
    assert "123-45-6789" not in result


def test_unformatted_ssn_redaction_failure():
    """EMPIRICAL CHALLENGE: Unformatted SSN 123456789 (9 raw digits)."""
    raw = "SSN 123456789 recorded"
    result = sanitize_payload(raw)
    is_redacted = ("123456789" not in result)
    print(f"\n[EMPIRICAL TEST] Unformatted SSN ('123456789'): Redacted? {is_redacted} | Result: '{result}'")
    assert is_redacted, f"FAILURE: Unformatted SSN 123456789 leaked through sanitize_payload! Result: '{result}'"


def test_ssn_mixed_punctuation():
    """EMPIRICAL CHALLENGE: SSN with spaces, dots, or underscores (123.45.6789 or 123_45_6789)."""
    raw_dot = "SSN 123.45.6789 recorded"
    raw_underscore = "SSN 123_45_6789 recorded"
    res_dot = sanitize_payload(raw_dot)
    res_und = sanitize_payload(raw_underscore)

    assert "123.45.6789" not in res_dot, f"FAILURE: Dot-delimited SSN leaked! Result: '{res_dot}'"
    assert "123_45_6789" not in res_und, f"FAILURE: Underscore-delimited SSN leaked! Result: '{res_und}'"


def test_email_in_nested_json_string():
    """Email address in JSON string representation."""
    raw_json = json.dumps({"user": {"email": "patient.doe@hospital.org", "id": 42}})
    result = sanitize_payload(raw_json)
    assert "patient.doe@hospital.org" not in result, f"FAILURE: Email leaked in nested JSON string! Result: '{result}'"


def test_lab_result_notes_with_patient_names_and_dob():
    """EMPIRICAL CHALLENGE: Lab result text notes containing Patient Names and DOB."""
    raw_note = "Lab Note: Patient Maria Silva, DOB 1985-04-12, tested positive for Glucose elevation."
    result = sanitize_payload(raw_note)

    name_leaked = "Maria Silva" in result
    dob_leaked = "1985-04-12" in result

    print(f"\n[EMPIRICAL TEST] Patient Name ('Maria Silva') Leaked? {name_leaked}")
    print(f"[EMPIRICAL TEST] Date of Birth ('1985-04-12') Leaked? {dob_leaked}")

    assert not name_leaked, f"FAILURE: Patient Name 'Maria Silva' leaked in sanitized text! Result: '{result}'"
    assert not dob_leaked, f"FAILURE: DOB '1985-04-12' leaked in sanitized text! Result: '{result}'"


def test_non_string_dict_payload_sanitization():
    """EMPIRICAL CHALLENGE: Dictionary passed directly to sanitize_payload()."""
    dict_payload = {"patient_name": "Maria Silva", "cpf": "123.456.789-00"}
    result = sanitize_payload(dict_payload)

    print(f"\n[EMPIRICAL TEST] Dict payload passed to sanitize_payload: Returned type {type(result)} | Value: '{result}'")
    # Non-string input returns REDACTED_TOKEN string
    assert result == REDACTED_TOKEN


# ============================================================================
# 2. PATIENT ID ANONYMIZATION TESTS
# ============================================================================

def test_anonymize_patient_id_unformatted_cpf():
    """EMPIRICAL CHALLENGE: Passing unformatted CPF to anonymize_patient_id()."""
    unformatted_cpf = "12345678900"
    patient_hash = anonymize_patient_id(unformatted_cpf)

    print(f"\n[EMPIRICAL TEST] anonymize_patient_id('12345678900') -> '{patient_hash}'")
    assert patient_hash.startswith("patient_hash_")
    # Ensure raw CPF is not plaintext in hash
    assert "12345678900" not in patient_hash


def test_anonymize_patient_id_empty_or_none():
    """Empty or None input to anonymize_patient_id."""
    assert anonymize_patient_id("") == "patient_hash_unknown"
    assert anonymize_patient_id(None) == "patient_hash_unknown"


# ============================================================================
# 3. ROUTE GUARDRAILS & HTTP RESPONSE BODY LEAKAGE TESTS
# ============================================================================

def test_get_patient_status_unformatted_cpf_in_path():
    """
    EMPIRICAL CHALLENGE: GET /api/v1/patients/12345678900/status
    Unformatted CPF supplied in path parameter.
    Should be rejected with HTTP 400.
    """
    unformatted_cpf = "12345678900"
    response = client.get(f"/api/v1/patients/{unformatted_cpf}/status")

    print(f"\n[EMPIRICAL TEST] GET /patients/{unformatted_cpf}/status -> Status Code: {response.status_code}")
    print(f"[EMPIRICAL TEST] Response Body: {response.text}")

    assert response.status_code == 400, (
        f"FAILURE: Unformatted CPF in path parameter was NOT rejected with HTTP 400! "
        f"Status: {response.status_code}, Body: {response.text}"
    )


def test_get_patient_status_unformatted_ssn_in_path():
    """
    EMPIRICAL CHALLENGE: GET /api/v1/patients/123456789/status
    Unformatted SSN supplied in path parameter.
    Should be rejected with HTTP 400.
    """
    unformatted_ssn = "123456789"
    response = client.get(f"/api/v1/patients/{unformatted_ssn}/status")

    print(f"\n[EMPIRICAL TEST] GET /patients/{unformatted_ssn}/status -> Status Code: {response.status_code}")
    print(f"[EMPIRICAL TEST] Response Body: {response.text}")

    assert response.status_code == 400, (
        f"FAILURE: Unformatted SSN in path parameter was NOT rejected with HTTP 400! "
        f"Status: {response.status_code}, Body: {response.text}"
    )


def test_query_diagnostic_ai_unformatted_cpf_in_question():
    """
    EMPIRICAL CHALLENGE: POST /api/v1/patients/query-diagnostic
    Question body containing unformatted CPF 12345678900.
    Should fail validation with HTTP 422 or be sanitized.
    """
    payload = {
        "patient_hash": "patient_hash_abcdef0123456789",
        "clinical_question": "Patient with CPF 12345678900 has persistent tachycardia.",
        "diagnostic_model": "medlm-large",
    }
    response = client.post("/api/v1/patients/query-diagnostic", json=payload)

    print(f"\n[EMPIRICAL TEST] POST /query-diagnostic (Unformatted CPF) -> Status Code: {response.status_code}")
    print(f"[EMPIRICAL TEST] Response Body: {response.text}")

    if response.status_code == 200:
        data = response.json()
        question_evaluated = data.get("question_evaluated", "")
        assert "12345678900" not in question_evaluated, (
            f"FAILURE: Unformatted CPF leaked in question_evaluated response body! Body: {data}"
        )
    else:
        assert response.status_code == 422, f"Expected 422 validation error, got {response.status_code}"


def test_query_diagnostic_ai_patient_name_in_question():
    """
    EMPIRICAL CHALLENGE: POST /api/v1/patients/query-diagnostic
    Question body containing Patient Name 'João da Silva' and DOB '1975-11-20'.
    Should fail validation or sanitize PHI.
    """
    payload = {
        "patient_hash": "patient_hash_abcdef0123456789",
        "clinical_question": "Patient João da Silva born 1975-11-20 presents with acute dyspnea.",
        "diagnostic_model": "medlm-large",
    }
    response = client.post("/api/v1/patients/query-diagnostic", json=payload)

    print(f"\n[EMPIRICAL TEST] POST /query-diagnostic (Name/DOB) -> Status Code: {response.status_code}")
    print(f"[EMPIRICAL TEST] Response Body: {response.text}")

    if response.status_code == 200:
        data = response.json()
        question_evaluated = data.get("question_evaluated", "")
        assert "João da Silva" not in question_evaluated, (
            f"FAILURE: Patient Name 'João da Silva' leaked in response body! Body: {data}"
        )
        assert "1975-11-20" not in question_evaluated, (
            f"FAILURE: DOB '1975-11-20' leaked in response body! Body: {data}"
        )
    else:
        assert response.status_code == 422


def test_ingest_health_event_unformatted_phi():
    """
    EMPIRICAL CHALLENGE: POST /api/v1/health-events
    Ingests event payload with unformatted CPF and patient name.
    """
    payload = {
        "patient_hash": "patient_hash_0123456789abcdef",
        "event_type": "vital_sign_alert",
        "payload": {
            "heart_rate": 125,
            "notes": "Patient Carlos Santos CPF 98765432100 elevated heart rate",
        },
        "source": "icu_monitor",
    }
    response = client.post("/api/v1/health-events", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"


# ============================================================================
# 4. LOGGING & TRACE SENSITIVE DATA EMISSION TESTS
# ============================================================================

def test_structured_logging_unformatted_phi_leakage():
    """
    EMPIRICAL CHALLENGE: Verify StructuredJSONLogFormatter on log messages containing unformatted PHI.
    """
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    formatter = StructuredJSONLogFormatter(service_name="test-service")
    handler.setFormatter(formatter)

    logger = logging.getLogger("test_logger_unformatted")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    raw_msg = "Event for patient Maria Oliveira CPF 98765432100 SSN 987654321"
    logger.info(raw_msg)

    log_output = log_capture.getvalue().strip()
    data = json.loads(log_output)
    msg = data["message"]

    print(f"\n[EMPIRICAL TEST] Log message formatted: '{msg}'")

    assert "98765432100" not in msg, f"FAILURE: Unformatted CPF leaked into log message! Log: {msg}"
    assert "987654321" not in msg, f"FAILURE: Unformatted SSN leaked into log message! Log: {msg}"
    assert "Maria Oliveira" not in msg, f"FAILURE: Patient Name leaked into log message! Log: {msg}"

