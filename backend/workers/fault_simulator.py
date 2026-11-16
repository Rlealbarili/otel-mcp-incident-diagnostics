"""
Fault Simulator Worker Module.

Provides programmable isolated health fault simulation (latency_spike, sensor_timeout, ehr_error_500),
OpenTelemetry exception recording, correlated Loki error logging, and dynamic REST state management.
"""

import asyncio
from enum import Enum
import logging
import random
import threading
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

# OpenTelemetry imports with graceful fallback handling
try:
    from opentelemetry import trace
    from opentelemetry.trace import Span, Status, StatusCode
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None
    Status = None
    StatusCode = None

from backend.middleware.sanitize import sanitize_payload

logger = logging.getLogger("health-fault-simulator")
tracer = trace.get_tracer(__name__, "1.0.0") if OTEL_AVAILABLE else None


# ============================================================================
# 1. FAULT DOMAIN EXCEPTIONS & ENUMS
# ============================================================================

class FaultMode(str, Enum):
    """Supported health telemetry fault simulation modes."""
    NONE = "none"
    OFF = "off"
    LATENCY_SPIKE = "latency_spike"
    SENSOR_TIMEOUT = "sensor_timeout"
    EHR_ERROR_500 = "ehr_error_500"


class HealthTelemetryFaultException(Exception):
    """Base exception for injected health telemetry faults."""
    pass


class SensorTimeoutError(HealthTelemetryFaultException):
    """Simulates connection drops / missing data frames in IoT medical telemetry."""
    pass


class EHRDatabaseConnectionError(HealthTelemetryFaultException):
    """Simulates database failure / 500 status code in EHR record processing."""
    pass


# ============================================================================
# 2. FAULT CONFIGURATION PYDANTIC SCHEMAS
# ============================================================================

class FaultInjectionRequest(BaseModel):
    """Pydantic model for REST POST /api/v1/fault-injection activation payload."""
    fault_mode: FaultMode = Field(..., description="Target fault scenario mode")
    enabled: bool = Field(default=True, description="Master enable toggle for fault injection")
    probability: float = Field(default=1.0, ge=0.0, le=1.0, description="Injection probability rate (0.0 to 1.0)")
    delay_seconds: float = Field(default=3.0, ge=0.0, le=30.0, description="Delay duration for latency_spike mode")
    duration_seconds: Optional[int] = Field(default=None, ge=1, description="Auto-expiration duration in seconds")
    target_service: Optional[str] = Field(default="all", description="Target service scope ('lab_ingestion', 'iot_telemetry', 'ehr_processing', 'all')")

    @field_validator("fault_mode", mode="before")
    @classmethod
    def normalize_mode(cls, v: Any) -> Any:
        if isinstance(v, str):
            v_lower = v.lower()
            if v_lower in ("none", "off", "disabled"):
                return FaultMode.NONE
            return v_lower
        return v


class FaultStatusResponse(BaseModel):
    """Pydantic model for REST GET /api/v1/fault-injection/status response."""
    status: str
    active_fault: Dict[str, Any]
    metrics: Dict[str, Any]
    timestamp: str


# ============================================================================
# 3. THREAD-SAFE FAULT SIMULATOR MANAGER (SINGLETON)
# ============================================================================

class FaultSimulatorManager:
    """
    Thread-safe state manager for programmable fault scenarios.
    Controls dynamic REST updates, probability evaluation, auto-expiration, and statistics.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_state()
            return cls._instance

    def _init_state(self) -> None:
        self.state_lock = threading.RLock()
        self.enabled: bool = False
        self.fault_mode: FaultMode = FaultMode.NONE
        self.probability: float = 1.0
        self.delay_seconds: float = 3.0
        self.duration_seconds: Optional[int] = None
        self.target_service: str = "all"
        self.activated_at: Optional[float] = None
        
        # Operational counters
        self.total_evaluations: int = 0
        self.total_injections: int = 0
        self.injections_by_mode: Dict[str, int] = {
            FaultMode.LATENCY_SPIKE.value: 0,
            FaultMode.SENSOR_TIMEOUT.value: 0,
            FaultMode.EHR_ERROR_500.value: 0,
        }

    def _get_status_dict_unlocked(self) -> Dict[str, Any]:
        """Internal unlocked helper returning current configuration and operational status."""
        self._check_expiration_unlocked()

        time_remaining = None
        if self.enabled and self.duration_seconds and self.activated_at:
            elapsed = time.time() - self.activated_at
            time_remaining = max(0.0, self.duration_seconds - elapsed)

        return {
            "enabled": self.enabled,
            "fault_mode": self.fault_mode.value,
            "probability": self.probability,
            "delay_seconds": self.delay_seconds,
            "duration_seconds": self.duration_seconds,
            "time_remaining_seconds": round(time_remaining, 2) if time_remaining is not None else None,
            "target_service": self.target_service,
            "activated_at": datetime.fromtimestamp(self.activated_at, tz=timezone.utc).isoformat() if self.activated_at else None,
        }

    def configure(self, req: FaultInjectionRequest) -> Dict[str, Any]:
        """Dynamically updates active fault scenario parameters."""
        with self.state_lock:
            if req.fault_mode in (FaultMode.NONE, FaultMode.OFF) or not req.enabled:
                self.enabled = False
                self.fault_mode = FaultMode.NONE
                self.activated_at = None
                logger.info("Fault simulator deactivated (mode: NONE/OFF)")
            else:
                self.enabled = True
                self.fault_mode = req.fault_mode
                self.probability = req.probability
                self.delay_seconds = req.delay_seconds
                self.duration_seconds = req.duration_seconds
                self.target_service = req.target_service or "all"
                self.activated_at = time.time()
                logger.warning(
                    f"Fault simulator ACTIVATED: mode={self.fault_mode.value}, "
                    f"prob={self.probability}, delay={self.delay_seconds}s, "
                    f"duration={self.duration_seconds}s, service={self.target_service}"
                )

            return self._get_status_dict_unlocked()

    def get_status_dict(self) -> Dict[str, Any]:
        """Returns current configuration and operational status dictionary."""
        with self.state_lock:
            return self._get_status_dict_unlocked()

    def _check_expiration_unlocked(self) -> None:
        """Internal helper to check if auto-expiration duration has elapsed."""
        if self.enabled and self.duration_seconds and self.activated_at:
            if time.time() - self.activated_at >= self.duration_seconds:
                logger.info(f"Fault injection duration ({self.duration_seconds}s) expired. Deactivating fault simulator.")
                self.enabled = False
                self.fault_mode = FaultMode.NONE
                self.activated_at = None

    def should_inject(self, service_name: str = "all") -> Tuple[bool, FaultMode, float]:
        """
        Determines whether a fault should be injected based on active mode,
        service scope matching, auto-expiration, and probability rate.
        """
        with self.state_lock:
            self.total_evaluations += 1
            self._check_expiration_unlocked()

            if not self.enabled or self.fault_mode == FaultMode.NONE:
                return False, FaultMode.NONE, 0.0

            if self.target_service != "all" and service_name != "all" and self.target_service != service_name:
                return False, FaultMode.NONE, 0.0

            if self.probability < 1.0 and random.random() > self.probability:
                return False, FaultMode.NONE, 0.0

            self.total_injections += 1
            self.injections_by_mode[self.fault_mode.value] = self.injections_by_mode.get(self.fault_mode.value, 0) + 1

            return True, self.fault_mode, self.delay_seconds

    def reset_metrics(self) -> None:
        """Resets evaluation and injection counters."""
        with self.state_lock:
            self.total_evaluations = 0
            self.total_injections = 0
            self.injections_by_mode = {
                FaultMode.LATENCY_SPIKE.value: 0,
                FaultMode.SENSOR_TIMEOUT.value: 0,
                FaultMode.EHR_ERROR_500.value: 0,
            }


fault_simulator_manager = FaultSimulatorManager()


# ============================================================================
# 4. FAULT EXECUTION & TELEMETRY INSTRUMENTATION ENGINE
# ============================================================================

def record_fault_exception_on_span(
    span: Optional[Any],
    exception: Exception,
    fault_mode: FaultMode,
    component: str,
) -> None:
    """
    Attaches OpenTelemetry exception record, sets STATUS_CODE_ERROR,
    and populates fault attribution attributes on the current span.
    """
    if not span:
        return

    try:
        if hasattr(span, "record_exception"):
            span.record_exception(exception)

        if OTEL_AVAILABLE and StatusCode and Status:
            span.set_status(Status(StatusCode.ERROR, str(exception)))

        if hasattr(span, "set_attribute"):
            span.set_attribute("fault.injected", True)
            span.set_attribute("fault.mode", fault_mode.value)
            span.set_attribute("fault.component", component)
            span.set_attribute("error.type", exception.__class__.__name__)
            span.set_attribute("error.message", sanitize_payload(str(exception)))
    except Exception as otel_err:
        logger.warning(f"Failed to record fault exception on OTel span: {otel_err}")


def emit_correlated_fault_log(
    exception: Exception,
    fault_mode: FaultMode,
    component: str,
    extra_context: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Emits a structured error log entry correlated with OpenTelemetry trace_id and span_id.
    Passes stack trace and message through sanitize_payload() for PHI/PII protection.
    """
    try:
        trace_id = "0" * 32
        span_id = "0" * 16

        if OTEL_AVAILABLE and trace:
            current_span = trace.get_current_span()
            if current_span:
                sc = current_span.get_span_context()
                if sc and getattr(sc, "is_valid", False):
                    trace_id = f"{sc.trace_id:032x}"
                    span_id = f"{sc.span_id:016x}"

        raw_tb = traceback.format_exc()
        sanitized_tb = sanitize_payload(raw_tb)
        sanitized_msg = sanitize_payload(str(exception))

        log_payload = {
            "fault_event": "INJECTED_FAULT_TRIGGERED",
            "fault_mode": fault_mode.value,
            "component": component,
            "trace_id": trace_id,
            "span_id": span_id,
            "exception_type": exception.__class__.__name__,
            "exception_message": sanitized_msg,
            "stack_trace": sanitized_tb[:1000],
        }
        if extra_context:
            log_payload.update(extra_context)

        logger.error(
            f"Fault Injected [{fault_mode.value}] in {component}: {sanitized_msg}",
            extra={"fault_payload": log_payload},
        )
    except Exception as log_err:
        logger.warning(f"Failed to emit correlated fault log: {log_err}")


def execute_fault_injection_sync(service_name: str = "all") -> None:
    """
    Synchronous fault injection handler for non-async background workers or route pipelines.
    Evaluates state manager, injects latency or raises fault exception with OTel trace instrumentation.
    """
    should_inject, mode, delay_sec = fault_simulator_manager.should_inject(service_name)
    if not should_inject:
        return

    current_span = trace.get_current_span() if (OTEL_AVAILABLE and trace) else None

    if mode == FaultMode.LATENCY_SPIKE:
        if current_span and hasattr(current_span, "set_attribute"):
            current_span.set_attribute("fault.injected", True)
            current_span.set_attribute("fault.mode", mode.value)
            current_span.set_attribute("fault.delay_seconds", delay_sec)

        logger.warning(f"Injecting synchronous latency spike ({delay_sec}s) for service {service_name}")
        time.sleep(delay_sec)

    elif mode == FaultMode.SENSOR_TIMEOUT:
        exc = SensorTimeoutError(f"IoT telemetry frame reception timed out after {int(delay_sec * 1000)}ms")
        record_fault_exception_on_span(current_span, exc, mode, service_name)
        emit_correlated_fault_log(exc, mode, service_name)
        raise exc

    elif mode == FaultMode.EHR_ERROR_500:
        exc = EHRDatabaseConnectionError("Database connection lost: SQL state 08006 / HTTP 500 internal error")
        record_fault_exception_on_span(current_span, exc, mode, service_name)
        emit_correlated_fault_log(exc, mode, service_name)
        raise exc


async def execute_fault_injection_async(service_name: str = "all") -> None:
    """
    Asynchronous fault injection handler for FastAPI endpoints and async ingestion routines.
    Executes non-blocking asyncio.sleep for latency_spike or raises fault exceptions.
    """
    should_inject, mode, delay_sec = fault_simulator_manager.should_inject(service_name)
    if not should_inject:
        return

    current_span = trace.get_current_span() if (OTEL_AVAILABLE and trace) else None

    if mode == FaultMode.LATENCY_SPIKE:
        if current_span and hasattr(current_span, "set_attribute"):
            current_span.set_attribute("fault.injected", True)
            current_span.set_attribute("fault.mode", mode.value)
            current_span.set_attribute("fault.delay_seconds", delay_sec)

        logger.warning(f"Injecting asynchronous latency spike ({delay_sec}s) for service {service_name}")
        try:
            import anyio
            await anyio.sleep(delay_sec)
        except ImportError:
            await asyncio.sleep(delay_sec)

    elif mode == FaultMode.SENSOR_TIMEOUT:
        exc = SensorTimeoutError(f"IoT telemetry frame reception timed out after {int(delay_sec * 1000)}ms")
        record_fault_exception_on_span(current_span, exc, mode, service_name)
        emit_correlated_fault_log(exc, mode, service_name)
        raise exc

    elif mode == FaultMode.EHR_ERROR_500:
        exc = EHRDatabaseConnectionError("Database connection lost: SQL state 08006 / HTTP 500 internal error")
        record_fault_exception_on_span(current_span, exc, mode, service_name)
        emit_correlated_fault_log(exc, mode, service_name)
        raise exc


def safe_execute_fault_injection(service_name: str = "all") -> None:
    """
    Graceful degradation wrapper (CIRES-R compliance guarantee).
    Wraps fault injection execution so that unexpected simulator errors never crash application logic.
    """
    try:
        execute_fault_injection_sync(service_name)
    except HealthTelemetryFaultException:
        raise
    except Exception as unexpected_err:
        logger.error(f"Unexpected fault simulator error safely suppressed: {unexpected_err}")


# ============================================================================
# 5. REST ROUTER FOR FAULT INJECTION CONTROL
# ============================================================================

router = APIRouter(prefix="/api/v1", tags=["Fault Simulator & Resilience"])


@router.post("/fault-injection", status_code=status.HTTP_200_OK)
async def activate_fault_injection(payload: FaultInjectionRequest) -> Dict[str, Any]:
    """
    Activates, updates, or deactivates fault injection scenarios dynamically.
    """
    try:
        updated_status = fault_simulator_manager.configure(payload)
        return {
            "message": "Fault injection scenario updated successfully",
            "active_config": updated_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to configure fault injection scenario: {str(exc)}",
        )


@router.get("/fault-injection/status", response_model=FaultStatusResponse, status_code=status.HTTP_200_OK)
async def get_fault_injection_status() -> Dict[str, Any]:
    """
    Returns current active fault injection configuration and execution metrics.
    """
    status_dict = fault_simulator_manager.get_status_dict()
    return {
        "status": "active" if status_dict["enabled"] else "idle",
        "active_fault": status_dict,
        "metrics": {
            "total_evaluations": fault_simulator_manager.total_evaluations,
            "total_injections": fault_simulator_manager.total_injections,
            "injections_by_mode": fault_simulator_manager.injections_by_mode,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
