"""
Test Fail-Closed PHI/PII Redaction & Zero Leakage Guarantee

Verifies regex patterns, boundary conditions, malformed payload fallbacks,
and zero-leakage assertions across application middleware and OTel Collector specs.
"""

import re
from pathlib import Path
import pytest
import yaml

from backend.middleware.sanitize import (
    sanitize_payload,
    REDACTED_TOKEN,
    REGEX_CPF,
    REGEX_SSN,
    REGEX_EMAIL,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OTEL_COLLECTOR_PATH = PROJECT_ROOT / "scripts" / "otel-collector.yaml"


def assert_zero_phi_leakage(text: str):
    """Strict assertion helper: ensures NO unredacted PHI/PII pattern exists in output."""
    assert not REGEX_CPF.search(text), f"PHI LEAK DETECTED: CPF found in '{text}'"
    assert not REGEX_SSN.search(text), f"PHI LEAK DETECTED: SSN found in '{text}'"
    assert not REGEX_EMAIL.search(text), f"PII LEAK DETECTED: Email found in '{text}'"


# ============================================================================
# 1. INDIVIDUAL PATTERN REDACTION TESTS
# ============================================================================

@pytest.mark.parametrize("raw_cpf, expected_substring", [
    ("Paciente CPF 123.456.789-00 admitido na UTI", REDACTED_TOKEN),
    ("CPF: 000.111.222-33 com resultado de exame positivo", REDACTED_TOKEN),
    ("Identificador 999.888.777-66 em observacao", REDACTED_TOKEN),
    ("Paciente com cpf: 12345678901 cadastrado", REDACTED_TOKEN),
    ("patient_cpf=98765432100", REDACTED_TOKEN),
])
def test_cpf_pattern_redaction(raw_cpf, expected_substring):
    """Validates Brazilian CPF regex matching and sanitization."""
    result = sanitize_payload(raw_cpf)
    assert expected_substring in result
    assert_zero_phi_leakage(result)


@pytest.mark.parametrize("raw_ssn, expected_substring", [
    ("Patient SSN 123-45-6789 registered", REDACTED_TOKEN),
    ("SSN: 987-65-4321 clinical log", REDACTED_TOKEN),
    ("patient_ssn: 123456789 registered", REDACTED_TOKEN),
    ("ssn=987654321", REDACTED_TOKEN),
])
def test_ssn_pattern_redaction(raw_ssn, expected_substring):
    """Validates US SSN regex matching and sanitization."""
    result = sanitize_payload(raw_ssn)
    assert expected_substring in result
    assert_zero_phi_leakage(result)


@pytest.mark.parametrize("telemetry_metric", [
    "total_requests=12345678901",
    "bytes_sent=123456789",
    "process_memory_bytes=17179869184",
    "timestamp_ms=1700000000000",
    "network_packets_in=12345678901 network_packets_out=123456789",
])
def test_telemetry_9_and_11_digit_metrics_pass_through(telemetry_metric):
    """Verifies that 9-digit and 11-digit telemetry metrics pass through unredacted."""
    result = sanitize_payload(telemetry_metric)
    assert result == telemetry_metric
    assert REDACTED_TOKEN not in result


@pytest.mark.parametrize("raw_email, expected_substring", [
    ("Contact physician at doctor.smith@hospital.org immediately", REDACTED_TOKEN),
    ("Patient user_123@healthcare-provider.com requested record", REDACTED_TOKEN),
])
def test_email_pattern_redaction(raw_email, expected_substring):
    """Validates Email address regex matching and sanitization."""
    result = sanitize_payload(raw_email)
    assert expected_substring in result
    assert_zero_phi_leakage(result)


# ============================================================================
# 2. FAIL-CLOSED MECHANICS & EDGE CASES
# ============================================================================

def test_fail_closed_non_string_input():
    """Confirms non-string or corrupted inputs fail-closed to [REDACTED_FAIL_CLOSED]."""
    assert sanitize_payload(None) == REDACTED_TOKEN
    assert sanitize_payload(12345) == REDACTED_TOKEN
    assert sanitize_payload(["list", "input"]) == REDACTED_TOKEN
    assert sanitize_payload({"key": "val"}) == REDACTED_TOKEN


def test_mixed_phi_payload():
    """Validates redaction on complex payloads containing multiple PHI/PII entities."""
    raw_log = "Dr. Alice (alice@hospital.org) treated patient 123.456.789-00 (SSN: 987-65-4321)"
    result = sanitize_payload(raw_log)
    
    assert REDACTED_TOKEN in result
    assert_zero_phi_leakage(result)


# ============================================================================
# 3. OTEL COLLECTOR REDACTOR CONFIGURATION SYNTAX CHECK
# ============================================================================

def test_otel_collector_redactor_config_validity():
    """Validates that scripts/otel-collector.yaml configures fail-closed redaction regexes."""
    assert OTEL_COLLECTOR_PATH.exists()
    with open(OTEL_COLLECTOR_PATH, "r", encoding="utf-8") as f:
        content = yaml.safe_load(f)
        
    processors = content.get("processors", {})
    redact_procs = [
        p_cfg for p_name, p_cfg in processors.items()
        if "transform" in p_name or "redact" in p_name or "sanitize" in p_name
    ]
    
    assert len(redact_procs) > 0, "otel-collector.yaml MUST configure a transform/redact processor"
    
    redact_cfg = redact_procs[0]
    log_statements = redact_cfg.get("log_statements", [])
    assert len(log_statements) > 0, "Transform redactor must configure log_statements"
    
    stmt_str = str(log_statements)
    assert "d{3}" in stmt_str, "CPF/SSN regex missing from OTel config"
    assert "d{2}" in stmt_str, "CPF/SSN regex missing from OTel config"
    assert "[REDACTED_FAIL_CLOSED]" in stmt_str, "Token [REDACTED_FAIL_CLOSED] missing from OTel config"
