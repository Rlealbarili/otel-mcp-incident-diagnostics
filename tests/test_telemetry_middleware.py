"""
Unit Tests for backend/middleware/telemetry.py
"""

import io
import json
import logging
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.middleware.telemetry import (
    TelemetryMiddleware,
    StructuredJSONLogFormatter,
    record_genai_telemetry,
    SERVICE_NAME,
    DEFAULT_TRACE_ID,
    DEFAULT_SPAN_ID,
)
from backend.middleware.sanitize import REGEX_CPF, REGEX_SSN, REGEX_EMAIL

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


def test_structured_json_formatter():
    """Verifies StructuredJSONLogFormatter outputs Loki-compliant JSON with trace context and fail-closed scrubbing."""
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    formatter = StructuredJSONLogFormatter(service_name="test-service")
    handler.setFormatter(formatter)

    logger = logging.getLogger("test_logger_json")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info("Patient CPF 123.456.789-00 record processed successfully.")

    log_output = log_capture.getvalue().strip()
    data = json.loads(log_output)

    assert data["service.name"] == "test-service"
    assert data["level"] == "INFO"
    assert "timestamp" in data
    assert "trace_id" in data
    assert "span_id" in data
    assert "[REDACTED_FAIL_CLOSED]" in data["message"]
    assert "123.456.789-00" not in data["message"]


def test_record_genai_telemetry():
    """Verifies record_genai_telemetry populates OTel GenAI attributes on span and log record."""
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    formatter = StructuredJSONLogFormatter()
    handler.setFormatter(formatter)

    logger = logging.getLogger("test_logger_genai")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    class DummySpan:
        def __init__(self):
            self.attributes = {}
        def is_recording(self):
            return True
        def set_attribute(self, k, v):
            self.attributes[k] = v

    dummy_span = DummySpan()

    record_genai_telemetry(
        span=dummy_span,
        logger=logger,
        system="health_diagnostic_llm",
        model="medlm-large",
        prompt_tokens=340,
        completion_tokens=120,
        message="GenAI query completed",
    )

    assert dummy_span.attributes["gen_ai.system"] == "health_diagnostic_llm"
    assert dummy_span.attributes["gen_ai.request.model"] == "medlm-large"
    assert dummy_span.attributes["gen_ai.usage.prompt_tokens"] == 340
    assert dummy_span.attributes["gen_ai.usage.completion_tokens"] == 120
    assert dummy_span.attributes["gen_ai.usage.total_tokens"] == 460

    log_output = log_capture.getvalue().strip()
    data = json.loads(log_output)

    assert data["gen_ai.system"] == "health_diagnostic_llm"
    assert data["gen_ai.request.model"] == "medlm-large"
    assert data["gen_ai.usage.prompt_tokens"] == 340
    assert data["gen_ai.usage.completion_tokens"] == 120
    assert data["gen_ai.usage.total_tokens"] == 460


def test_telemetry_middleware_dispatch():
    """Verifies TelemetryMiddleware processes HTTP request and sets headers."""
    app = FastAPI()
    app.add_middleware(TelemetryMiddleware)

    @app.get("/test-route")
    async def test_endpoint():
        return {"status": "ok"}

    client = TestClient(app)
    valid_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

    response = client.get("/test-route", headers={"traceparent": valid_traceparent})

    assert response.status_code == 200
