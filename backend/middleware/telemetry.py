"""
Telemetry Middleware for FastAPI / ASGI Applications.

Provides W3C TraceContext propagation, structured JSON logging with OTel correlation,
GenAI semantic attribute helpers, and fail-closed PHI/PII sanitization.
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# OpenTelemetry imports with fallback handling
try:
    from opentelemetry import trace
    from opentelemetry.trace import Span, SpanKind, Status, StatusCode, Context
    from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None
    Span = None
    SpanKind = None
    Status = None
    StatusCode = None
    Context = None

from backend.middleware.sanitize import sanitize_payload, REDACTED_TOKEN

SERVICE_NAME = "health-observability-backend"
DEFAULT_TRACE_ID = "00000000000000000000000000000000"
DEFAULT_SPAN_ID = "0000000000000000"

tracer = trace.get_tracer(__name__, "1.0.0") if OTEL_AVAILABLE else None
propagator = TraceContextTextMapPropagator() if OTEL_AVAILABLE else None


class StructuredJSONLogFormatter(logging.Formatter):
    """
    JSON Log Formatter standardizing log outputs for Loki ingestion.
    Extracts trace_id and span_id from active OpenTelemetry context,
    enforces service.name, ISO-8601 UTC timestamp, and fail-closed PHI/PII sanitization.
    """

    def __init__(self, service_name: str = SERVICE_NAME):
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        try:
            span = trace.get_current_span() if OTEL_AVAILABLE else None
            span_context = span.get_span_context() if (span and hasattr(span, "get_span_context")) else None

            if span_context and getattr(span_context, "is_valid", False):
                trace_id = f"{span_context.trace_id:032x}"
                span_id = f"{span_context.span_id:016x}"
            else:
                trace_id = DEFAULT_TRACE_ID
                span_id = DEFAULT_SPAN_ID

            raw_msg = record.getMessage()
            sanitized_msg = sanitize_payload(raw_msg)

            log_data: Dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "service.name": self.service_name,
                "trace_id": trace_id,
                "span_id": span_id,
                "logger.name": record.name,
                "message": sanitized_msg,
            }

            for genai_key in (
                "gen_ai.system",
                "gen_ai.request.model",
                "gen_ai.usage.prompt_tokens",
                "gen_ai.usage.completion_tokens",
                "gen_ai.usage.total_tokens",
            ):
                if hasattr(record, genai_key):
                    log_data[genai_key] = getattr(record, genai_key)

            if record.exc_info:
                exc_type, exc_val, _ = record.exc_info
                log_data["exception"] = {
                    "type": exc_type.__name__ if exc_type else "Exception",
                    "message": sanitize_payload(str(exc_val)),
                }

            return json.dumps(log_data)
        except Exception:
            fallback = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "ERROR",
                "service.name": self.service_name,
                "trace_id": DEFAULT_TRACE_ID,
                "span_id": DEFAULT_SPAN_ID,
                "message": REDACTED_TOKEN,
            }
            return json.dumps(fallback)


def record_genai_telemetry(
    span: Optional[Any],
    logger: logging.Logger,
    system: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    message: str = "Diagnostic AI model execution completed",
) -> None:
    """
    Attaches OTel GenAI semantic attributes to active span and emits a correlated JSON log record.

    Attributes:
      gen_ai.system: Target AI framework or platform (e.g. 'health_diagnostic_llm')
      gen_ai.request.model: Model identifier (e.g. 'medlm-large')
      gen_ai.usage.prompt_tokens: Prompt token count
      gen_ai.usage.completion_tokens: Completion token count
    """
    total_tokens = prompt_tokens + completion_tokens

    if span and hasattr(span, "is_recording") and span.is_recording():
        span.set_attribute("gen_ai.system", system)
        span.set_attribute("gen_ai.request.model", model)
        span.set_attribute("gen_ai.usage.prompt_tokens", prompt_tokens)
        span.set_attribute("gen_ai.usage.completion_tokens", completion_tokens)
        span.set_attribute("gen_ai.usage.total_tokens", total_tokens)

    extra = {
        "gen_ai.system": system,
        "gen_ai.request.model": model,
        "gen_ai.usage.prompt_tokens": prompt_tokens,
        "gen_ai.usage.completion_tokens": completion_tokens,
        "gen_ai.usage.total_tokens": total_tokens,
    }
    logger.info(message, extra=extra)


class TelemetryMiddleware(BaseHTTPMiddleware):
    """
    FastAPI / ASGI Middleware for W3C TraceContext extraction and response injection,
    span tracing, latency measurement, and correlated error logging.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start_time = time.time()

        carrier = dict(request.headers)
        extracted_context = propagator.extract(carrier) if propagator else None

        route_path = request.url.path
        method = request.method
        span_name = f"HTTP {method} {route_path}"

        if OTEL_AVAILABLE and tracer:
            cm = tracer.start_as_current_span(
                span_name,
                context=extracted_context,
                kind=SpanKind.SERVER,
            )
        else:
            cm = None

        if cm:
            with cm as span:
                span.set_attribute("http.method", method)
                span.set_attribute("http.target", route_path)
                span.set_attribute("http.scheme", request.url.scheme)
                span.set_attribute("service.name", SERVICE_NAME)

                try:
                    response = await call_next(request)
                    status_code = response.status_code
                    span.set_attribute("http.status_code", status_code)

                    if status_code >= 500:
                        span.set_status(Status(StatusCode.ERROR, f"HTTP {status_code}"))

                    response_carrier: Dict[str, str] = {}
                    if propagator:
                        propagator.inject(response_carrier)
                        for header_key, header_val in response_carrier.items():
                            response.headers[header_key] = header_val

                    return response
                except Exception as exc:
                    span.set_status(Status(StatusCode.ERROR, str(exc)))
                    span.record_exception(exc)
                    raise exc
                finally:
                    duration_ms = (time.time() - start_time) * 1000.0
                    span.set_attribute("duration_ms", duration_ms)
        else:
            try:
                response = await call_next(request)
                return response
            except Exception as exc:
                raise exc
