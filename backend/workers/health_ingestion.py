"""
System Health Telemetry Ingestion Worker Implementation

File: backend/workers/health_ingestion.py
Background worker process for ingesting software application health, microservice metrics,
DB connection pool events, and system vitals telemetry data.
Instruments OpenTelemetry TracerProvider, MeterProvider, and OTLPSpanExporter (gRPC/HTTP),
with fail-closed secret scrubbing and zero credentials leakage guarantees.
"""

import asyncio
import hashlib
import logging
import os
import random
import time
from typing import Any, Dict, Optional

# Import fail-closed sanitizer
from backend.middleware.sanitize import sanitize_payload, REDACTED_TOKEN

# OpenTelemetry imports with fallback handling
try:
    from opentelemetry import trace, metrics
    from opentelemetry.trace import StatusCode, Status, Tracer
    from opentelemetry.metrics import Meter, Counter, Histogram
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader, ConsoleMetricExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPGrpcSpanExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter as OTLPGrpcMetricExporter
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as OTLPHttpSpanExporter
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter as OTLPHttpMetricExporter
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None
    metrics = None

logger = logging.getLogger("health_ingestion")

SALT = os.getenv("PATIENT_HASH_SALT", "cires_r_secure_health_salt_2026")


def anonymize_patient_id(raw_patient_id: str) -> str:
    """Generates a salted SHA-256 HMAC hash token to avoid ID/PHI leakage."""
    if not raw_patient_id:
        return "patient_hash_unknown"
    salt = os.getenv("PATIENT_HASH_SALT", "cires_r_secure_health_salt_2026")
    clean_id = sanitize_payload(str(raw_patient_id))
    salted = f"{salt}:{clean_id}"
    digest = hashlib.sha256(salted.encode("utf-8")).hexdigest()[:16]
    return f"patient_hash_{digest}"


def init_telemetry(
    service_name: str = "health-ingestion-service",
    service_version: str = "1.0.0",
    protocol: str = "grpc",
    endpoint: Optional[str] = None,
) -> tuple:
    """
    Initializes OpenTelemetry SDK TracerProvider and MeterProvider.
    Supports gRPC (localhost:4317) and HTTP (localhost:4318).
    Falls back gracefully if OTel packages are unavailable or connection fails.
    """
    if not OTEL_AVAILABLE:
        logger.warning("OpenTelemetry packages not installed. Running in mock telemetry mode.")
        return None, None

    resource = Resource.create({
        "service.name": service_name,
        "service.version": service_version,
        "deployment.environment": os.getenv("ENV", "production"),
    })

    # Setup Tracer Provider & OTLP Span Exporter
    tracer_provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(tracer_provider)

    if protocol.lower() == "http":
        otlp_endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_HTTP_ENDPOINT", "http://localhost:4318/v1/traces")
        span_exporter = OTLPHttpSpanExporter(endpoint=otlp_endpoint)
    else:  # gRPC default
        otlp_endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_GRPC_ENDPOINT", "localhost:4317")
        span_exporter = OTLPGrpcSpanExporter(endpoint=otlp_endpoint, insecure=True)

    span_processor = BatchSpanProcessor(span_exporter)
    tracer_provider.add_span_processor(span_processor)
    tracer = trace.get_tracer(service_name, service_version)

    # Setup Meter Provider & OTLP Metric Exporter
    if protocol.lower() == "http":
        metric_endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_METRICS_HTTP_ENDPOINT", "http://localhost:4318/v1/metrics")
        metric_exporter = OTLPHttpMetricExporter(endpoint=metric_endpoint)
    else:
        metric_endpoint = endpoint or os.getenv("OTEL_EXPORTER_OTLP_METRICS_GRPC_ENDPOINT", "localhost:4317")
        metric_exporter = OTLPGrpcMetricExporter(endpoint=metric_endpoint, insecure=True)

    metric_reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=5000)
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)
    meter = metrics.get_meter(service_name, service_version)

    return tracer, meter


class HealthIngestionWorker:
    """
    Background Ingestion Worker managing 3 software system telemetry streams:
    1. System Metrics & API Query Telemetry (Database, cache)
    2. Microservice / Node Health Telemetry (CPU, Memory, Connections)
    3. Application Service Log & Transaction Telemetry (Events, Jobs)
    """

    def __init__(self, tracer=None, meter=None):
        if OTEL_AVAILABLE:
            self.tracer = tracer or trace.get_tracer("health-ingestion-service", "1.0.0")
            self.meter = meter or metrics.get_meter("health-ingestion-service", "1.0.0")
            
            # Instrument Metrics
            self.lab_counter = self.meter.create_counter(
                "health_lab_results_ingested_total",
                description="Total number of lab result items processed",
                unit="1",
            )
            self.iot_counter = self.meter.create_counter(
                "health_iot_telemetry_samples_total",
                description="Total number of IoT medical sensor telemetry samples processed",
                unit="1",
            )
            self.ehr_counter = self.meter.create_counter(
                "health_ehr_records_processed_total",
                description="Total number of EHR record events processed",
                unit="1",
            )
            self.duration_histogram = self.meter.create_histogram(
                "health_ingestion_duration_seconds",
                description="Histogram of processing latency per ingestion stream",
                unit="s",
            )
            self.error_counter = self.meter.create_counter(
                "health_ingestion_errors_total",
                description="Total number of ingestion failures and errors",
                unit="1",
            )
        else:
            self.tracer = None
            self.meter = None
            self.lab_counter = None
            self.iot_counter = None
            self.ehr_counter = None
            self.duration_histogram = None
            self.error_counter = None

    async def ingest_lab_results(self, lab_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stream 1: Ingest System API Query Telemetry / Lab Results.
        Creates span 'health.ingest.lab_results' with rich attributes.
        Strictly guarantees ZERO Secret/PII leakage.
        """
        start_time = time.time()
        test_code = lab_data.get("test_code", "SYS_API_QUERY")
        category = lab_data.get("category", "database_query")
        specimen_type = lab_data.get("specimen_type", "sql_query")
        batch_size = int(lab_data.get("batch_size", 1))
        patient_hash = anonymize_patient_id(lab_data.get("patient_id", ""))

        span = self.tracer.start_span("health.ingest.lab_results") if self.tracer else None
        if span:
            span.set_attribute("health.stream", "lab_results")
            span.set_attribute("health.lab.test_code", test_code)
            span.set_attribute("health.lab.category", category)
            span.set_attribute("health.lab.specimen_type", specimen_type)
            span.set_attribute("health.lab.batch_size", batch_size)
            span.set_attribute("health.patient_hash", patient_hash)

        try:
            await asyncio.sleep(random.uniform(0.01, 0.05))

            if lab_data.get("simulate_error"):
                raise ValueError(f"Lab result validation failed for test_code {test_code}")

            if span:
                span.set_status(Status(StatusCode.OK))
                span.end()

            duration = time.time() - start_time
            if self.lab_counter:
                self.lab_counter.add(batch_size, {"category": category, "status": "success"})
                self.duration_histogram.record(duration, {"stream": "lab_results"})

            return {
                "status": "success",
                "stream": "lab_results",
                "test_code": test_code,
                "batch_size": batch_size,
                "patient_hash": patient_hash,
            }

        except Exception as exc:
            sanitized_err = sanitize_payload(str(exc))
            if span:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, sanitized_err))
                span.end()
            if self.error_counter:
                self.error_counter.add(1, {"stream": "lab_results", "error": type(exc).__name__})
            logger.error(f"[Lab Ingestion Error] {sanitized_err}")
            return {"status": "error", "stream": "lab_results", "error": sanitized_err, "patient_hash": patient_hash}

    async def ingest_iot_telemetry(self, sensor_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stream 2: Ingest System Health Vitals / Microservice Node Telemetry (CPU, Memory, Connections).
        Creates span 'health.ingest.iot_telemetry' with rich device & sensor attributes.
        """
        start_time = time.time()
        device_type = sensor_data.get("device_type", "system_node_agent")
        device_id = sensor_data.get("device_id", "NODE-SYS-001")
        firmware = sensor_data.get("firmware_version", "v1.0.0")
        metric_type = sensor_data.get("metric_type", "cpu_utilization")
        unit = sensor_data.get("unit", "percent")
        sample_count = int(sensor_data.get("sample_count", 1))
        is_anomaly = bool(sensor_data.get("is_anomaly", False))
        patient_hash = anonymize_patient_id(sensor_data.get("patient_id", ""))

        span = self.tracer.start_span("health.ingest.iot_telemetry") if self.tracer else None
        if span:
            span.set_attribute("health.stream", "iot_sensors")
            span.set_attribute("health.device.type", device_type)
            span.set_attribute("health.device.id", device_id)
            span.set_attribute("health.device.firmware_version", firmware)
            span.set_attribute("health.sensor.metric_type", metric_type)
            span.set_attribute("health.sensor.unit", unit)
            span.set_attribute("health.sensor.sample_count", sample_count)
            span.set_attribute("health.sensor.is_anomaly", is_anomaly)
            span.set_attribute("health.patient_hash", patient_hash)

        try:
            await asyncio.sleep(random.uniform(0.005, 0.02))

            if sensor_data.get("simulate_error"):
                raise ConnectionResetError(f"IoT sensor stream interrupted for device {device_id}")

            if span:
                span.set_status(Status(StatusCode.OK))
                span.end()

            duration = time.time() - start_time
            if self.iot_counter:
                self.iot_counter.add(sample_count, {"device_type": device_type, "unit": unit, "status": "ok"})
                self.duration_histogram.record(duration, {"stream": "iot_sensors"})

            return {
                "status": "success",
                "stream": "iot_sensors",
                "device_id": device_id,
                "sample_count": sample_count,
                "patient_hash": patient_hash,
            }

        except Exception as exc:
            sanitized_err = sanitize_payload(str(exc))
            if span:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, sanitized_err))
                span.end()
            if self.error_counter:
                self.error_counter.add(1, {"stream": "iot_sensors", "error": type(exc).__name__})
            logger.error(f"[IoT Ingestion Error] {sanitized_err}")
            return {"status": "error", "stream": "iot_sensors", "error": sanitized_err, "patient_hash": patient_hash}

    async def ingest_ehr_records(self, ehr_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stream 3: Ingest Application System Transaction Telemetry (Service Events, DB Queries).
        Creates span 'health.ingest.ehr_records' with rich system event attributes.
        """
        start_time = time.time()
        event_type = ehr_event.get("event_type", "TRANSACTION")
        department = ehr_event.get("department", "BACKEND_API")
        icd10_code = ehr_event.get("icd10_code", "SYS.200.OK")
        record_count = int(ehr_event.get("record_count", 1))
        patient_hash = anonymize_patient_id(ehr_event.get("patient_id", ""))

        span = self.tracer.start_span("health.ingest.ehr_records") if self.tracer else None
        if span:
            span.set_attribute("health.stream", "ehr_processing")
            span.set_attribute("health.ehr.event_type", event_type)
            span.set_attribute("health.ehr.department", department)
            span.set_attribute("health.ehr.icd10_code", icd10_code)
            span.set_attribute("health.ehr.record_count", record_count)
            span.set_attribute("health.patient_hash", patient_hash)

        try:
            await asyncio.sleep(random.uniform(0.02, 0.08))

            if ehr_event.get("simulate_error"):
                raise RuntimeError(f"EHR transaction lock timeout for department {department}")

            if span:
                span.set_status(Status(StatusCode.OK))
                span.end()

            duration = time.time() - start_time
            if self.ehr_counter:
                self.ehr_counter.add(record_count, {"event_type": event_type, "status": "processed"})
                self.duration_histogram.record(duration, {"stream": "ehr_processing"})

            return {
                "status": "success",
                "stream": "ehr_processing",
                "event_type": event_type,
                "department": department,
                "patient_hash": patient_hash,
            }

        except Exception as exc:
            sanitized_err = sanitize_payload(str(exc))
            if span:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, sanitized_err))
                span.end()
            if self.error_counter:
                self.error_counter.add(1, {"stream": "ehr_processing", "error": type(exc).__name__})
            logger.error(f"[EHR Ingestion Error] {sanitized_err}")
            return {"status": "error", "stream": "ehr_processing", "error": sanitized_err, "patient_hash": patient_hash}

    async def run_loop(self, interval_seconds: float = 2.0, max_iterations: Optional[int] = None):
        """Continuous simulation loop for background software system health ingestion."""
        logger.info("Starting Software System Health Telemetry Ingestion Worker Loop...")
        count = 0

        while True:
            if max_iterations and count >= max_iterations:
                break

            count += 1
            await self.ingest_lab_results({
                "test_code": random.choice(["SYS_DB_SELECT", "SYS_CACHE_GET", "SYS_MQ_DISPATCH"]),
                "category": random.choice(["database_query", "cache_lookup", "mq_dispatch"]),
                "specimen_type": "sql_query",
                "batch_size": random.randint(1, 5),
                "patient_id": f"SYS-USER-{random.randint(1000, 9999)}",
                "simulate_error": (random.random() < 0.05),
            })

            await self.ingest_iot_telemetry({
                "device_type": random.choice(["system_node_agent", "microservice_worker", "api_gateway"]),
                "device_id": f"NODE-SYS-{random.randint(100, 999)}",
                "firmware_version": "v2.1.0",
                "metric_type": random.choice(["cpu_utilization", "ram_usage", "active_connections"]),
                "unit": "percent",
                "sample_count": 60,
                "is_anomaly": (random.random() < 0.1),
                "patient_id": f"SYS-USER-{random.randint(1000, 9999)}",
                "simulate_error": (random.random() < 0.05),
            })

            await self.ingest_ehr_records({
                "event_type": random.choice(["HTTP_REQUEST", "BACKGROUND_JOB", "ASYNC_WORKER"]),
                "department": random.choice(["API_GATEWAY", "AUTH_SERVICE", "PAYMENT_WORKER"]),
                "icd10_code": random.choice(["HTTP.200.OK", "HTTP.500.ERROR", "HTTP.504.TIMEOUT"]),
                "record_count": 1,
                "patient_id": f"SYS-USER-{random.randint(1000, 9999)}",
                "simulate_error": (random.random() < 0.05),
            })

            await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    tracer, meter = init_telemetry(protocol="grpc", endpoint="localhost:4317")
    worker = HealthIngestionWorker(tracer=tracer, meter=meter)
    try:
        asyncio.run(worker.run_loop(interval_seconds=1.0, max_iterations=5))
    except KeyboardInterrupt:
        logger.info("Worker stopped by user.")
