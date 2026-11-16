"""
Test Suite for Fault Simulator & Resilience Integration.

Validates REST control endpoints, fault mode execution (latency_spike, sensor_timeout, ehr_error_500),
OpenTelemetry exception recording, trace context correlation, and graceful degradation (CIRES-R).
"""

import time
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.workers.fault_simulator import (
    FaultMode,
    FaultInjectionRequest,
    FaultSimulatorManager,
    SensorTimeoutError,
    EHRDatabaseConnectionError,
    fault_simulator_manager,
    execute_fault_injection_sync,
    execute_fault_injection_async,
    safe_execute_fault_injection,
    record_fault_exception_on_span,
    router as fault_router,
)


class DummySpan:
    def __init__(self):
        self.recorded_exceptions = []
        self.status = None
        self.attributes = {}

    def record_exception(self, exc):
        self.recorded_exceptions.append(exc)

    def set_status(self, status):
        self.status = status

    def set_attribute(self, key, value):
        self.attributes[key] = value


@pytest.fixture(autouse=True)
def reset_fault_simulator_state():
    """Resets fault simulator state before and after each test."""
    fault_simulator_manager.configure(
        FaultInjectionRequest(fault_mode=FaultMode.NONE, enabled=False)
    )
    fault_simulator_manager.reset_metrics()
    yield
    fault_simulator_manager.configure(
        FaultInjectionRequest(fault_mode=FaultMode.NONE, enabled=False)
    )


# ============================================================================
# 1. STATE MANAGER & REST ENDPOINT TESTS
# ============================================================================

def test_fault_simulator_singleton():
    """Verifies that FaultSimulatorManager operates as a thread-safe singleton."""
    mgr1 = FaultSimulatorManager()
    mgr2 = FaultSimulatorManager()
    assert mgr1 is mgr2


def test_fault_injection_activation_and_deactivation():
    """Verifies dynamic activation and deactivation of fault scenarios."""
    req = FaultInjectionRequest(
        fault_mode=FaultMode.LATENCY_SPIKE,
        enabled=True,
        delay_seconds=1.5,
        probability=1.0,
    )
    status_dict = fault_simulator_manager.configure(req)
    assert status_dict["enabled"] is True
    assert status_dict["fault_mode"] == "latency_spike"
    assert status_dict["delay_seconds"] == 1.5

    # Deactivate
    deact_req = FaultInjectionRequest(fault_mode=FaultMode.NONE, enabled=False)
    deact_status = fault_simulator_manager.configure(deact_req)
    assert deact_status["enabled"] is False
    assert deact_status["fault_mode"] == "none"


def test_fault_injection_auto_expiration():
    """Verifies that auto-expiration deactivates fault scenario after duration_seconds."""
    req = FaultInjectionRequest(
        fault_mode=FaultMode.SENSOR_TIMEOUT,
        enabled=True,
        duration_seconds=1,
    )
    fault_simulator_manager.configure(req)
    assert fault_simulator_manager.get_status_dict()["enabled"] is True

    time.sleep(1.1)
    status_dict = fault_simulator_manager.get_status_dict()
    assert status_dict["enabled"] is False
    assert status_dict["fault_mode"] == "none"


# ============================================================================
# 2. FAULT MODE EXECUTION TESTS
# ============================================================================

def test_execute_latency_spike():
    """Verifies latency_spike mode introduces configured processing delay."""
    delay = 0.2
    req = FaultInjectionRequest(
        fault_mode=FaultMode.LATENCY_SPIKE,
        enabled=True,
        delay_seconds=delay,
        probability=1.0,
    )
    fault_simulator_manager.configure(req)

    start_time = time.time()
    execute_fault_injection_sync("lab_ingestion")
    elapsed = time.time() - start_time

    assert elapsed >= delay, f"Expected delay >= {delay}s, got {elapsed:.3f}s"
    assert fault_simulator_manager.total_injections == 1


def test_execute_sensor_timeout():
    """Verifies sensor_timeout mode raises SensorTimeoutError exception."""
    req = FaultInjectionRequest(
        fault_mode=FaultMode.SENSOR_TIMEOUT,
        enabled=True,
        probability=1.0,
    )
    fault_simulator_manager.configure(req)

    with pytest.raises(SensorTimeoutError) as exc_info:
        execute_fault_injection_sync("iot_telemetry")

    assert "IoT telemetry frame reception timed out" in str(exc_info.value)
    assert fault_simulator_manager.injections_by_mode["sensor_timeout"] == 1


def test_execute_ehr_error_500():
    """Verifies ehr_error_500 mode raises EHRDatabaseConnectionError exception."""
    req = FaultInjectionRequest(
        fault_mode=FaultMode.EHR_ERROR_500,
        enabled=True,
        probability=1.0,
    )
    fault_simulator_manager.configure(req)

    with pytest.raises(EHRDatabaseConnectionError) as exc_info:
        execute_fault_injection_sync("ehr_processing")

    assert "Database connection lost" in str(exc_info.value)
    assert fault_simulator_manager.injections_by_mode["ehr_error_500"] == 1


@pytest.mark.anyio
async def test_execute_async_fault_injection():
    """Verifies asynchronous fault injection handler."""
    req = FaultInjectionRequest(
        fault_mode=FaultMode.LATENCY_SPIKE,
        enabled=True,
        delay_seconds=0.1,
    )
    fault_simulator_manager.configure(req)

    start_time = time.time()
    await execute_fault_injection_async("lab_ingestion")
    elapsed = time.time() - start_time

    assert elapsed >= 0.1


# ============================================================================
# 3. OPENTELEMETRY SPAN & EXCEPTION RECORDING TESTS
# ============================================================================

def test_record_fault_exception_on_span():
    """Verifies that fault exceptions correctly populate span attributes and record_exception."""
    dummy_span = DummySpan()
    exc = SensorTimeoutError("Simulated sensor timeout test")

    record_fault_exception_on_span(dummy_span, exc, FaultMode.SENSOR_TIMEOUT, "iot_telemetry")

    assert len(dummy_span.recorded_exceptions) == 1
    assert dummy_span.recorded_exceptions[0] is exc
    assert dummy_span.attributes.get("fault.injected") is True
    assert dummy_span.attributes.get("fault.mode") == "sensor_timeout"
    assert dummy_span.attributes.get("fault.component") == "iot_telemetry"
    assert dummy_span.attributes.get("error.type") == "SensorTimeoutError"


# ============================================================================
# 4. CIRES-R GRACEFUL DEGRADATION & SAFETY TESTS
# ============================================================================

def test_safe_execute_fault_injection_suppresses_unexpected_errors():
    """Verifies safe_execute_fault_injection suppresses unexpected simulator errors without crashing."""
    fault_simulator_manager.enabled = True
    fault_simulator_manager.fault_mode = "invalid_unsupported_mode"

    # Should not raise exception
    safe_execute_fault_injection("test_service")


# ============================================================================
# 5. REST CONTROL API ENDPOINT TESTS
# ============================================================================

def test_rest_fault_injection_endpoints():
    """Verifies POST /api/v1/fault-injection and GET /api/v1/fault-injection/status endpoints."""
    app = FastAPI()
    app.include_router(fault_router)
    client = TestClient(app)

    # 1. Activate fault via POST
    payload = {
        "fault_mode": "latency_spike",
        "enabled": True,
        "delay_seconds": 0.5,
        "probability": 1.0,
    }
    post_res = client.post("/api/v1/fault-injection", json=payload)
    assert post_res.status_code == 200
    post_data = post_res.json()
    assert post_data["active_config"]["fault_mode"] == "latency_spike"

    # 2. Query status via GET
    get_res = client.get("/api/v1/fault-injection/status")
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["status"] == "active"
    assert get_data["active_fault"]["fault_mode"] == "latency_spike"
    assert "metrics" in get_data
