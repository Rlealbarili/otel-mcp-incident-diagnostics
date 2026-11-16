# OpenSpec Specification: OpenTelemetry LGTM Pipeline (CIRES-R)

## 1. Overview & Purpose
This specification defines the OpenTelemetry Collector architecture and Grafana LGTM stack integration for healthcare applications.

## 2. Ingress & Egress Ports
- **OTLP gRPC**: `4317`
- **OTLP HTTP**: `4318`
- **Loki Log Egress**: `http://loki:3100/loki/api/v1/push`
- **Tempo Trace Egress**: `tempo:4317`
- **Prometheus / Mimir Egress**: `http://mimir:9009/api/v1/push`

## 3. Resilience & Buffering
- **Memory Limiter**: 80% hard limit, 20% spike limit.
- **Persistent Disk Queue**: `/var/lib/otelcol/file_storage`, capacity 5 GB.
- **Retry Policy**: Initial 5s, max 60s, max elapsed 5m.
