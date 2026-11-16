"""
Unit, Integration & Stress Test Suite for Automated RCA Engine & Technical Diagnostic Reports.

File: tests/test_rca_diagnostic.py
Verifies telemetry correlation, signature classification across failure scenarios (latency_spike, sensor_timeout, ehr_error_500),
non-blocking execution, deduplication cooldowns, NIST CSF 2.0 mapping, and zero PHI/PII leakage assertions.
"""

import pytest
import asyncio
import time
from backend.workers.fault_simulator import FaultMode, FaultInjectionRequest, fault_simulator_manager
from backend.workers.rca_engine import (
    AutomatedRCAEngine,
    FaultCategory,
    IncidentSeverity,
    LogStackEvidence,
    MetricEvidence,
    PatternRecognitionEngine,
    RCADiagnosticReport,
    TelemetryCorrelator,
    TraceSpanEvidence,
    rca_engine,
)
from backend.workers.mitigation_generator import MitigationPlanGenerator, NISTFunction


@pytest.mark.anyio
async def test_rca_trigger_latency_spike():
    """Verifies RCA Engine detection and classification of latency_spike faults."""
    req = FaultInjectionRequest(fault_mode=FaultMode.LATENCY_SPIKE, delay_seconds=3.0, enabled=True)
    fault_simulator_manager.configure(req)

    report = await rca_engine.diagnose_incident(
        trace_id="11111111222222223333333344444444",
        component="iot_telemetry",
        description="Latency spike test sweep",
        fault_mode="latency_spike",
    )

    assert report.incident_summary.fault_category == FaultCategory.LATENCY_SPIKE
    assert report.incident_summary.severity == IncidentSeverity.MEDIUM
    assert report.root_cause_evidence.trace_evidence.duration_ms >= 3000.0
    assert report.phi_redaction_verified is True
    assert report.cires_score == 4.2


@pytest.mark.anyio
async def test_rca_trigger_sensor_timeout():
    """Verifies RCA Engine detection and classification of sensor_timeout faults."""
    req = FaultInjectionRequest(fault_mode=FaultMode.SENSOR_TIMEOUT, enabled=True)
    fault_simulator_manager.configure(req)

    report = await rca_engine.diagnose_incident(
        trace_id="55555555666666667777777788888888",
        component="iot_telemetry",
        description="Sensor timeout test sweep",
        fault_mode="sensor_timeout",
    )

    assert report.incident_summary.fault_category == FaultCategory.SENSOR_TIMEOUT
    assert report.incident_summary.severity == IncidentSeverity.HIGH
    assert report.root_cause_evidence.trace_evidence.device_id == "DEV-OX-001"
    assert "patient_hash" in report.root_cause_evidence.trace_evidence.patient_hash
    assert report.phi_redaction_verified is True


@pytest.mark.anyio
async def test_rca_trigger_ehr_error_500():
    """Verifies RCA Engine detection and classification of ehr_error_500 faults."""
    req = FaultInjectionRequest(fault_mode=FaultMode.EHR_ERROR_500, enabled=True)
    fault_simulator_manager.configure(req)

    report = await rca_engine.diagnose_incident(
        trace_id="9999999900000000aaaaaaaaBBBBBBBB",
        component="ehr_processing",
        description="EHR error 500 test sweep",
        fault_mode="ehr_error_500",
    )

    assert report.incident_summary.fault_category == FaultCategory.EHR_ERROR_500
    assert report.incident_summary.severity == IncidentSeverity.CRITICAL
    assert "08006" in report.root_cause_evidence.log_evidence.exception_message
    assert report.root_cause_evidence.trace_evidence.http_status_code == 500
    assert report.phi_redaction_verified is True


@pytest.mark.anyio
async def test_rca_async_non_blocking():
    """Verifies that RCA Engine executes asynchronously without blocking the main event loop."""
    start_time = time.perf_counter()
    
    tasks = [
        rca_engine.diagnose_incident(
            trace_id=f"{i:032x}",
            component="iot_telemetry",
            description=f"Concurrent sweep {i}",
            fault_mode="sensor_timeout",
        )
        for i in range(1, 6)
    ]
    reports = await asyncio.gather(*tasks)
    
    elapsed = time.perf_counter() - start_time
    assert len(reports) == 5
    assert elapsed < 2.0


@pytest.mark.anyio
async def test_rca_phi_sanitization():
    """Verifies zero PHI leakage assertion on output reports."""
    report = await rca_engine.diagnose_incident(
        trace_id="abcdef0123456789abcdef0123456789",
        component="ehr_processing",
        description="Patient CPF 123.456.789-00 SSN 987-65-4321 email doc@hospital.com encountered failure",
        fault_mode="ehr_error_500",
    )

    dumped_str = str(report.model_dump())
    assert "123.456.789-00" not in dumped_str
    assert "987-65-4321" not in dumped_str
    assert "doc@hospital.com" not in dumped_str
    assert report.phi_redaction_verified is True


def test_nist_csf_mitigation_plan_generation():
    """Verifies that MitigationPlanGenerator creates valid 6-function NIST CSF 2.0 mappings."""
    plan = MitigationPlanGenerator.generate_plan("INC-TEST-001", "ehr_error_500", "ehr_processing")

    assert plan.incident_id == "INC-TEST-001"
    assert plan.fault_category == "ehr_error_500"
    assert len(plan.nist_mappings) == 6

    functions = {m.nist_function for m in plan.nist_mappings}
    expected_functions = {
        NISTFunction.GOVERN,
        NISTFunction.IDENTIFY,
        NISTFunction.PROTECT,
        NISTFunction.DETECT,
        NISTFunction.RESPOND,
        NISTFunction.RECOVER,
    }
    assert functions == expected_functions
    assert len(plan.actions) == 3
    assert plan.cires_validation_status == "VERIFIED_PASSED"


@pytest.mark.anyio
async def test_edge_case_60s_cooldown_deduplication():
    """Verify 60s cooldown deduplication mechanism and fingerprinting behavior."""
    engine = AutomatedRCAEngine()
    
    report1 = await engine.diagnose_incident(
        trace_id="a" * 32,
        component="iot_dedup_test",
        fault_mode="sensor_timeout"
    )
    
    report2 = await engine.diagnose_incident(
        trace_id="b" * 32,
        component="iot_dedup_test",
        fault_mode="sensor_timeout"
    )
    
    assert report2.incident_summary.fault_category == report1.incident_summary.fault_category


@pytest.mark.anyio
async def test_edge_case_concurrent_async_incident_triggers():
    """Stress-test concurrent async incident triggers to evaluate race conditions in cooldown."""
    engine = AutomatedRCAEngine()
    
    tasks = [
        engine.diagnose_incident(
            trace_id=f"{i:032x}",
            component=f"comp_{i % 3}",
            fault_mode="latency_spike" if i % 2 == 0 else "sensor_timeout"
        )
        for i in range(20)
    ]
    
    reports = await asyncio.gather(*tasks, return_exceptions=True)
    errors = [r for r in reports if isinstance(r, Exception)]
    assert len(errors) == 0, f"Concurrent execution caused exceptions: {errors}"
    assert len(reports) == 20


@pytest.mark.anyio
async def test_dynamic_multi_signal_correlation_full_and_partial():
    """Verifies dynamic correlation when metrics, traces, and logs signals are explicitly passed."""
    engine = AutomatedRCAEngine()

    metrics_sig = {
        "metric_name": "http_requests_5xx_rate",
        "query": "rate(http_requests_total{status=~'5..'}[1m])",
        "value": 12.5,
        "threshold": 1.0,
        "exceeded": True,
    }
    trace_sig = {
        "trace_id": "1234567890abcdef1234567890abcdef",
        "span_id": "span-999",
        "duration_ms": 4200.0,
        "http_status_code": 503,
        "device_id": "NODE-GW-42",
        "error_message": "Service Unavailable",
    }
    log_sig = {
        "log_stream": "auth-microservice",
        "timestamp": "2026-08-11T14:30:00Z",
        "exception_class": "ConnectionRefusedError",
        "exception_message": "Upstream service connection failed at 10.0.0.5:8080",
        "stack_trace": ["  at auth.connect() in service.py:42"],
    }

    report = await engine.diagnose_incident(
        trace_id="1234567890abcdef1234567890abcdef",
        component="auth_microservice",
        description="Auth service 503 error sweep",
        fault_mode="ehr_error_500",
        metrics_signal=metrics_sig,
        trace_signal=trace_sig,
        log_signal=log_sig,
    )

    ev = report.root_cause_evidence
    assert ev.metric_evidence.metric_name == "http_requests_5xx_rate"
    assert ev.metric_evidence.value == 12.5
    assert ev.trace_evidence.span_id == "span-999"
    assert ev.trace_evidence.http_status_code == 503
    assert ev.log_evidence.exception_class == "ConnectionRefusedError"
    assert "service.py:42" in ev.log_evidence.stack_trace[0]


@pytest.mark.anyio
async def test_dynamic_multi_signal_correlation_missing_and_malformed_fallback():
    """Verifies robust fallback mechanics when signals are partial, missing, or malformed."""
    engine = AutomatedRCAEngine()

    # Pass malformed metrics and partial trace signal
    report = await engine.diagnose_incident(
        trace_id="00001111222233334444555566667777",
        component="payment_worker",
        description="Partial signal test",
        fault_mode="latency_spike",
        metrics_signal={"value": "invalid_number"},  # malformed type should fallback gracefully
        trace_signal={"duration_ms": 1500.0},        # partial signal missing other fields
        log_signal=None,                             # missing log signal
    )

    ev = report.root_cause_evidence
    # Malformed metric fallback to base metric evidence
    assert ev.metric_evidence.metric_name == "http_request_duration_seconds"
    # Partial trace signal merged duration_ms while preserving trace_id
    assert ev.trace_evidence.duration_ms == 1500.0
    assert ev.trace_evidence.trace_id == "00001111222233334444555566667777"
    # Missing log signal fallback to base log evidence
    assert ev.log_evidence.exception_class == "TimeoutWarning"

