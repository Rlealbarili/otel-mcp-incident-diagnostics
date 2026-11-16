# DESIGN.md — Health Data Observability & Automated Incident Diagnostics (CIRES-R)

## 1. Executive Summary & Architectural Goals

The **Health Data Observability & Automated Incident Diagnostics (CIRES-R)** architecture provides a privacy-first, resilient, distributed telemetry infrastructure and automated root cause analysis engine for healthcare applications. 

Following the **CIRES-R (Robustness-focused Observability)** engineering doctrine, the architecture integrates the OpenTelemetry Collector, Grafana LGTM Stack (Loki for logs, Tempo for traces, Mimir/Prometheus for metrics), Model Context Protocol (MCP) servers (`mcp-grafana`, `chrome-devtools-mcp`, `cires_rag_search`), and an Autonomous Diagnostic Agent.


### Core Architectural Goals:
1. **Zero PHI/PII Leakage**: Guaranteed via fail-closed OpenTelemetry Collector redaction pipelines, ensuring no unredacted healthcare or personal identification data escapes the application boundary.
2. **Infrastructure Resilience & Robustness**: Dual-tier memory/disk buffering, persistent queueing, and exponential backoff prevent data loss during downstream outages or network partitions.
3. **NIST CSF 2.0 Mapping**: Comprehensive alignment of telemetry and incident diagnostics with all six NIST CSF 2.0 core functions (*Govern, Identify, Protect, Detect, Respond, Recover*).
4. **Automated Root Cause Analysis (RCA)**: MCP-driven diagnostic workflows correlate metrics, traces, and logs across distributed services to generate actionable remediation playbooks.

---

## 2. NIST CSF 2.0 Governance & Control Mapping Matrix

The observability and diagnostic framework directly maps its technical components to the **NIST Cybersecurity Framework (CSF) 2.0**:

| NIST CSF 2.0 Function | Target Objective | System Component & Mechanism | Architectural Implementation |
|---|---|---|---|
| **Govern (GV)** | Establish telemetry governance, privacy policies, compliance boundaries (HIPAA/LGPD), and auditability. | Standardized Layout, Audit Logs, Policy Enforcer | Enforces standardized directory structure (`backend/`, `scripts/`, `tests/`), mandatory secret masking, and strict agent execution boundaries. |
| **Identify (ID)** | Asset & data flow mapping, risk identification, PHI/PII classification. | Telemetry Schema Mapper, Middleware (`backend/middleware/telemetry.py`) | Classifies telemetry data paths, tags health endpoints (`/api/v1/health-events`), and maps PHI/PII risk vectors across logs, traces, and metrics. |
| **Protect (PR)** | Zero PHI/PII leakage, data masking, fail-closed redaction, transport security, resource protection. | OTel Collector Fail-Closed Redactor (`scripts/otel-collector.yaml`), Memory Limiter | Intercepts logs/spans/metrics; applies regex redaction for CPF/SSN/names/lab values. Defaults to `[REDACTED_FAIL_CLOSED]` on pattern or engine error. |
| **Detect (DE)** | Continuous telemetry ingestion, real-time metrics, log aggregation, trace correlation, anomaly detection. | LGTM Stack (Mimir metrics, Loki logs, Tempo traces), Health Fault Simulator | Correlates metric spikes (`http_requests_total`, latency) with exemplars -> Tempo traces -> Loki log stack traces to detect system faults instantly. |
| **Respond (RS)** | Autonomous incident analysis, correlated telemetry query, root cause determination, mitigation plan generation. | Autonomous Diagnostic Agent, `mcp-grafana`, `chrome-devtools-mcp`, `cires_rag_search` | Automated RCA engine triggered by incident alerts; executes cross-signal telemetry lookups via MCP and generates NIST-mapped remediation plans. |
| **Recover (RC)** | System resilience, graceful degradation, data loss prevention under pressure, post-mortem playbooks. | OTel `file_storage` disk queue, Exponential Backoff, RAG Knowledge Base | Buffers unsent telemetry to persistent disk during LGTM outage; restores full observability post-recovery; archives post-mortem insights to RAG. |

---

## 3. CIRES-R Robustness Architecture & Guarantees

CIRES-R prioritizes robustness and system resilience over raw throughput. The system incorporates four non-negotiable robustness safeguards:

### 3.1 Fail-Closed PHI/PII Redactor Processor Specification
- **Mandate**: Protected Health Information (PHI: medical record numbers, lab results, diagnoses, patient telemetry) and Personally Identifiable Information (PII: CPF, SSN, full names, emails, addresses) MUST be sanitized at the OpenTelemetry Collector boundary.
- **Fail-Closed Guarantee**:
  - If the redactor processor encounters an unparseable payload, regex execution failure, timeout, or memory pressure event, the affected span attribute or log message body is overwritten with `[REDACTED_FAIL_CLOSED]`.
  - Telemetry payloads with unverified redactor execution are forbidden from entering the exporter pipeline.
- **Regex & Masking Specification**:
  - **CPF (Brazilian National ID)**: `\b\d{3}\.\d{3}\.\d{3}-\d{2}\b` -> `[CPF_REDACTED]`
  - **SSN (US Social Security)**: `\b\d{3}-\d{2}-\d{4}\b` -> `[SSN_REDACTED]`
  - **Email Addresses**: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b` -> `[EMAIL_REDACTED]`
  - **Patient Name & Explicit Identifiers**: Stripped or replaced with salted SHA-256 HMAC tokens (`health.patient_hash`).

### 3.2 Dual-Tier Buffering (Memory Limiter & Persistent Disk Queue)
To safeguard against memory exhaustion and ensure zero data loss during storage backpressure:
- **Memory Limiter Processor**:
  - `check_interval`: `1s`
  - `limit_percentage`: `80%` (Hard threshold for memory limit enforcement)
  - `spike_limit_percentage`: `20%`
- **Persistent Disk Queue (`file_storage`)**:
  - Buffer location: `/var/lib/otelcol/file_storage`
  - Disk-backed sending queue: `queue_size: 5000` batches, persisted via `file_storage`
  - Guarantees durability of unsent telemetry logs, traces, and metrics during downstream service failure (e.g. Loki or Tempo network partition).

### 3.3 Exponential Backoff & Fault Tolerance
- **Exporter Queue Configuration**:
  - `num_consumers`: `4`
  - `queue_size`: `5000`
- **Retry Policy**:
  - `enabled`: `true`
  - `initial_interval`: `5s`
  - `max_interval`: `60s`
  - `max_elapsed_time`: `5m`
- Prevents thundering herd problems when reconnecting to LGTM storage backends.

### 3.4 Graceful Degradation & Adaptive Sampling Strategy
- Under severe system load (Host CPU utilization > 85% or Memory utilization > 75%):
  - Head-based 100% sampling transitions to tail-based error-only sampling.
  - 100% of 5xx HTTP responses, unhandled exceptions, and latency outliers (> 500ms) are preserved.
  - Successful 200 OK spans are sampled down to 1% to protect system stability.

---

## 4. Component Topology & System Interfaces

```
+-----------------------------------------------------------------------------------+
|                            HEALTH APPLICATION LAYER                               |
|  - backend/routes/ (health_routes.py, patient_routes.py)                          |
|  - backend/workers/ (health_ingestion.py, fault_simulator.py)                     |
|  - backend/middleware/ (telemetry.py - OTel SDK, sanitize.py)                     |
+-----------------------------------------------------------------------------------+
                                         |
                                         | OTLP / gRPC (Port 4317)
                                         | TraceContext Propagation
                                         v
+-----------------------------------------------------------------------------------+
|                        OPENTELEMETRY COLLECTOR PIPELINE                           |
|  [Receivers]    : otlp (grpc:4317, http:4318)                                     |
|  [Processors]   : memory_limiter -> redactor (fail-closed) -> batch               |
|  [Extensions]   : file_storage (persistent disk queue)                            |
|  [Exporters]    : otlp/loki, otlp/tempo, prometheusremotewrite                    |
+-----------------------------------------------------------------------------------+
                                         |
                +------------------------+------------------------+
                | (Logs)                 | (Traces)               | (Metrics)
                v                        v                        v
        +---------------+        +---------------+        +---------------+
        |     Loki      |        |     Tempo     |        | Mimir/Prometh.|
        | (LogQL Engine)|        | (Trace Engine)|        | (PromQL Engine|
        +---------------+        +---------------+        +---------------+
                |                        |                        |
                +------------------------+------------------------+
                                         |
                                         v (Unified Telemetry Data Store)
+-----------------------------------------------------------------------------------+
|                            MCP & DIAGNOSTIC AGENT LAYER                           |
|                                                                                   |
|  +---------------------+  +---------------------+  +---------------------------+  |
|  |     mcp-grafana     |  | chrome-devtools-mcp |  |     cires_rag_search      |  |
|  | (Metrics, Logs,     |  | (Frontend UI, DOM,  |  | (NIST CSF 2.0 rules,      |  |
|  |  Traces Query API)  |  |  Network Timing)    |  |  RCA Playbooks, Specs)    |  |
|  +---------------------+  +---------------------+  +---------------------------+  |
|                                   \       |       /                               |
|                                    v      v      v                                |
|                        +-------------------------------------+                    |
|                        |     AUTONOMOUS DIAGNOSTIC AGENT     |                    |
|                        |  - Incident Anomaly Trigger          |                    |
|                        |  - Metric -> Trace -> Log Correlation|                    |
|                        |  - NIST CSF 2.0 RCA & Mitigation    |                    |
|                        +-------------------------------------+                    |
+-----------------------------------------------------------------------------------+
```

### 4.1 Health Application & Middleware Telemetry Layer
- **`backend/middleware/telemetry.py`**: Intercepts inbound FastAPI requests, initializes OpenTelemetry spans, and extracts/injects W3C TraceContext headers (`traceparent`, `tracestate`).
- **`backend/middleware/sanitize.py`**: In-application preliminary scrubbing layer enforcing immediate redaction of known PHI/PII fields before OTel SDK export.

### 4.2 OpenTelemetry Collector Pipeline (`scripts/otel-collector.yaml`)
- Configured as the single ingress gateway for telemetry (`0.0.0.0:4317` gRPC / `0.0.0.0:4318` HTTP).
- Chaining order: `memory_limiter` -> `transform/redactor` -> `batch` -> `file_storage` -> `exporters`.

### 4.3 LGTM Stack Storage & Correlation (`scripts/docker-compose.yml`)
- **Mimir / Prometheus**: Time-series database storing operational metrics (`http_requests_total`, `latency_seconds`, `error_rate`).
- **Tempo**: Distributed tracing store indexing spans by `trace_id`. Supports exemplar correlation from Prometheus metrics.
- **Loki**: Log aggregation system parsing JSON logs with explicit `trace_id` metadata for point-to-point trace-to-log jumps.

### 4.4 MCP Infrastructure & Autonomous Diagnostic Agent
- **`mcp-grafana`**: Grants AI agent structured query access to LogQL, PromQL, and Tempo APIs.
- **`chrome-devtools-mcp`**: Captures frontend errors, DOM state, and network timing waterfalls.
- **`cires_rag_search`**: Provides semantic retrieval of NIST CSF 2.0 guidelines, historical post-mortems, and system specs.

---

## 5. Incident Diagnostic & RCA Workflow

When an incident occurs or an automated anomaly trigger fires:

1. **Phase 1 — Anomaly Trigger & Metric Pinpointing**:
   - The Diagnostic Agent queries Mimir via `mcp-grafana` using PromQL (e.g. `rate(http_requests_total{status=~"5.."}[5m]) > 0.05`).
   - Identifies the exact timestamp window and extracts metric exemplars containing the offending `trace_id`.

2. **Phase 2 — Trace Graph Deep-Dive**:
   - Agent uses `mcp-grafana` to fetch full span tree from Tempo via `trace_id`.
   - Traverses service boundaries, pinpoints the root failing span, and checks execution latency and span status code (`STATUS_CODE_ERROR`).

3. **Phase 3 — Log Stack-Trace Correlation**:
   - Agent executes LogQL query in Loki matching `{trace_id="<TARGET_TRACE_ID>"}`.
   - Extracts exact error stack traces and exception context.

4. **Phase 4 — NIST CSF 2.0 Mapped Remediation Report**:
   - Queries `cires_rag_search` for relevant remediation playbooks.
   - Outputs a structured Root Cause Analysis (RCA) report outlining:
     - **Incident Summary & Scope** (Identify)
     - **Impact & Security Assessment** (Protect - Zero PHI Leak confirmation)
     - **Root Cause Technical Breakdown** (Detect)
     - **Automated Mitigation Plan** (Respond & Recover)

---

## 6. Verification & Compliance Verification Matrix

| Verification Aspect | Command / Tool | Success Criteria |
|---|---|---|
| **Fail-Closed Redaction** | `pytest tests/test_phi_redaction.py` | 100% pass on redaction unit tests. |
| **Telemetry Ingestion** | `pytest tests/test_otel_pipeline.py` | Successful trace-log-metric correlation. |

