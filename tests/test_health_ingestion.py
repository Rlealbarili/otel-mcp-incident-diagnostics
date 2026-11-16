"""
Unit Tests for backend/workers/health_ingestion.py
"""

import pytest
import asyncio

from backend.middleware.sanitize import REGEX_CPF, REGEX_SSN, REGEX_EMAIL
from backend.workers.health_ingestion import (
    anonymize_patient_id,
    init_telemetry,
    HealthIngestionWorker,
)


def assert_zero_phi_leakage(text: str):
    """Strict assertion helper: ensures NO unredacted PHI/PII pattern exists in output."""
    assert not REGEX_CPF.search(text), f"PHI LEAK DETECTED: CPF found in '{text}'"
    assert not REGEX_SSN.search(text), f"PHI LEAK DETECTED: SSN found in '{text}'"
    assert not REGEX_EMAIL.search(text), f"PII LEAK DETECTED: Email found in '{text}'"


def test_anonymize_patient_id_consistency_and_format():
    """Verifies that anonymize_patient_id creates salted hash token without leaking raw ID."""
    raw_id = "PATIENT-1234-CPF-123.456.789-00"
    patient_hash = anonymize_patient_id(raw_id)
    
    assert patient_hash.startswith("patient_hash_")
    assert len(patient_hash) == 29  # "patient_hash_" + 16 hex chars
    assert "123.456.789-00" not in patient_hash
    assert_zero_phi_leakage(patient_hash)


def test_ingest_lab_results_success():
    """Validates lab results ingestion stream and span attribute compliance."""
    worker = HealthIngestionWorker()
    payload = {
        "test_code": "LAB_CBC_001",
        "category": "hematology",
        "specimen_type": "whole_blood",
        "batch_size": 3,
        "patient_id": "PATIENT-9999",
    }
    res = asyncio.run(worker.ingest_lab_results(payload))
    assert res["status"] == "success"
    assert res["stream"] == "lab_results"
    assert res["test_code"] == "LAB_CBC_001"
    assert res["patient_hash"].startswith("patient_hash_")
    assert_zero_phi_leakage(str(res))


def test_ingest_iot_telemetry_success():
    """Validates IoT medical sensors ingestion stream."""
    worker = HealthIngestionWorker()
    payload = {
        "device_type": "pulse_oximeter",
        "device_id": "DEV-OX-9812",
        "firmware_version": "v2.1.0",
        "metric_type": "spo2",
        "unit": "percent",
        "sample_count": 60,
        "is_anomaly": False,
        "patient_id": "PATIENT-8888",
    }
    res = asyncio.run(worker.ingest_iot_telemetry(payload))
    assert res["status"] == "success"
    assert res["stream"] == "iot_sensors"
    assert res["device_id"] == "DEV-OX-9812"
    assert_zero_phi_leakage(str(res))


def test_ingest_ehr_records_success():
    """Validates EHR records ingestion stream."""
    worker = HealthIngestionWorker()
    payload = {
        "event_type": "ADMISSION",
        "department": "ICU",
        "icd10_code": "I21.9",
        "record_count": 1,
        "patient_id": "PATIENT-7777",
    }
    res = asyncio.run(worker.ingest_ehr_records(payload))
    assert res["status"] == "success"
    assert res["stream"] == "ehr_processing"
    assert res["event_type"] == "ADMISSION"
    assert res["department"] == "ICU"
    assert_zero_phi_leakage(str(res))


def test_ingestion_error_handling_and_fail_closed():
    """Validates exception recording and fail-closed sanitization on simulated errors."""
    worker = HealthIngestionWorker()
    
    # Lab error with raw CPF in simulated exception
    payload_lab = {
        "test_code": "LAB_FAIL",
        "patient_id": "123.456.789-00",
        "simulate_error": True,
    }
    res_lab = asyncio.run(worker.ingest_lab_results(payload_lab))
    assert res_lab["status"] == "error"
    assert_zero_phi_leakage(str(res_lab))

    # IoT error with SSN
    payload_iot = {
        "device_id": "DEV-ERR",
        "patient_id": "987-65-4321",
        "simulate_error": True,
    }
    res_iot = asyncio.run(worker.ingest_iot_telemetry(payload_iot))
    assert res_iot["status"] == "error"
    assert_zero_phi_leakage(str(res_iot))

    # EHR error with Email
    payload_ehr = {
        "department": "EMERGENCY",
        "patient_id": "doctor@hospital.org",
        "simulate_error": True,
    }
    res_ehr = asyncio.run(worker.ingest_ehr_records(payload_ehr))
    assert res_ehr["status"] == "error"
    assert_zero_phi_leakage(str(res_ehr))
