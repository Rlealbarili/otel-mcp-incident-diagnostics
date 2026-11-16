# ⚡ CIRES-R Software System Health & AI Incident Diagnostics Platform

[![tests](https://github.com/Rlealbarili/otel-mcp-incident-diagnostics/actions/workflows/tests.yml/badge.svg)](https://github.com/Rlealbarili/otel-mcp-incident-diagnostics/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-v1.25.0-orange.svg)](https://opentelemetry.io/)
[![Grafana LGTM](https://img.shields.io/badge/Grafana-LGTM%20Stack-F46800.svg)](https://grafana.com/)
[![NIST CSF 2.0](https://img.shields.io/badge/NIST%20CSF-2.0%20Compliant-00e676.svg)](https://www.nist.gov/cyberframework)
[![CIRES-R](https://img.shields.io/badge/Doctrine-CIRES--R%20Robustness-7f00ff.svg)](#cires-r-engineering-doctrine)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

[**Português (Brasil)**](README.pt-BR.md) | **English**

A distributed, privacy-first software application health telemetry ingestion platform and autonomous AI incident diagnostic system. Built with **OpenTelemetry (OTel)**, **Grafana LGTM Stack** (Loki, Tempo, Mimir/Prometheus), and the **Model Context Protocol (MCP)**, aligned with the **NIST CSF 2.0** framework.

---

## 🌟 Executive Summary & Key Highlights

Modern software systems require **high-throughput system health observability** coupled with **zero credentials/secrets data leakage** guarantees. This platform provides:

- **Fail-Closed Secrets & Credentials Sanitization**: Intercepts API Keys (`sk-`), Bearer Tokens, Passwords, Connection Strings, JWTs, and Private Keys at the OpenTelemetry Collector boundary. If redaction fails or regex execution times out, payloads are automatically overwritten as `[REDACTED_FAIL_CLOSED]`.
- **Dual-Tier Resilient Buffering**: Operates a persistent disk-backed sending queue (`file_storage`, 5,000 batches) paired with a memory limiter (80% hard limit / 20% spike limit) and exponential backoff retry policy (5s to 60s) to guarantee zero telemetry loss during downstream infrastructure outages.
- **Automated AI Root Cause Analysis (RCA)**: Correlates time-series metrics (Mimir) → trace span graphs (Tempo) → error stack traces (Loki) via Model Context Protocol (`mcp-grafana`) to generate 6-function NIST CSF 2.0 mitigation playbooks for software incidents.
- **Glassmorphic Software System Dashboard**: Embedded web dashboard for real-time system vitals monitoring (CPU, RAM, Connections, Latency), synthetic fault injection (latency spikes, service timeouts, DB pool exhaustion), and automated RCA report viewing.

---

## 📐 System Architecture

```
+-----------------------------------------------------------------------------------+
|                         SOFTWARE APPLICATION SYSTEM LAYER                         |
|  - FastAPIRoutes (health_routes.py, patient_routes.py)                            |
|  - Middleware (telemetry.py - OTel SDK, sanitize.py - In-App Secret Scrubbing)    |
|  - Workers (health_ingestion.py, fault_simulator.py, rca_engine.py)               |
+-----------------------------------------------------------------------------------+
                                         |
                                         | OTLP / gRPC (Port 4317)
                                         | TraceContext Propagation (traceparent)
                                         v
+-----------------------------------------------------------------------------------+
|                        OPENTELEMETRY COLLECTOR PIPELINE                           |
|  [Receivers]    : OTLP gRPC (4317), OTLP HTTP (4318)                              |
|  [Processors]   : memory_limiter -> transform/redactor (fail-closed) -> batch     |
|  [Extensions]   : file_storage (persistent disk-backed queue)                     |
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
|                        |  AUTONOMOUS SOFTWARE DIAGNOSTIC     |                    |
|                        |  - Incident Anomaly Trigger          |                    |
|                        |  - Metric -> Trace -> Log Correlation|                    |
|                        |  - NIST CSF 2.0 Software Playbooks   |                    |
|                        +-------------------------------------+                    |
+-----------------------------------------------------------------------------------+
```

---

## 🏛️ NIST Cybersecurity Framework (CSF) 2.0 Mapping Matrix

| NIST Function | Core Focus | System Implementation |
|---|---|---|
| **Govern (GV)** | Governance & Boundaries | Standardized layout (`backend/`, `scripts/`, `tests/`), mandatory secret masking, versioned specs in `openspec/`. |
| **Identify (ID)** | Secret Risk Classification | System telemetry tagger, mapping secret & credential risk vectors across logs, traces, and metrics. |
| **Protect (PR)** | Zero Secret Leakage | OTel Collector Fail-Closed Regex Redactor (`scripts/otel-collector.yaml`) + Memory Limiter. |
| **Detect (DE)** | System Anomaly & Fault Detection | Metric exemplars -> Tempo trace graphs -> Loki log stack trace correlation across LGTM pipeline. |
| **Respond (RS)** | Autonomous Software RCA | Diagnostic Agent via `mcp-grafana` executing automated root-cause analysis and 6-function mitigation plans. |
| **Recover (RC)** | Resilience & Storage Queue | `file_storage` persistent disk buffer (5,000-batch queue) maintaining telemetry state during LGTM storage degradation. |

---

## 🛡️ CIRES-R Engineering Doctrine

The project operates under the **CIRES-R Framework** with primary emphasis on **Robustness (R)**:

- **C — Clarity**: Unambiguous API contracts, clean component separation (`backend/routes`, `backend/workers`, `tests/`, `openspec/`).
- **I — Intelligence**: Smart metric exemplar extraction and context propagation without redundant processing.
- **R — Robustness (Primary Focus)**: Fail-closed security mechanics, dual-tier memory/disk queueing, 60s cooldown deduplication, and transactional isolation.
- **E — Elegance**: Glassmorphic UI dashboard, modular typed Python backend, structured JSON logging.
- **S — Security**: Zero hardcoded secrets, Git exclusively via SSH (SSH key auth), NIST CSF 2.0 alignment, and least-privilege scoping.

---

## 🚀 Quickstart & Setup Guide

### Prerequisites
- Python 3.12+
- Docker & Docker Compose
- Git with SSH authentication configured

### 1. Clone & Setup Repository
```bash
git clone https://github.com/Rlealbarili/otel-mcp-incident-diagnostics.git
cd otel-mcp-incident-diagnostics
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Launch Local Backend API & Dashboard
```bash
python3 -m backend.main
```
Open your browser at `http://localhost:8000/ui` to view the interactive **Glassmorphic Software System Health Dashboard**.

### 3. Launch Docker Compose LGTM Stack (Infra Blueprint)
```bash
docker compose -f scripts/docker-compose.yml up -d
```

---

## 🧪 Testing & Empirical Verification

Run the comprehensive test suite:
```bash
python3 -m pytest tests/ -v
```

---

## 📄 License & Author

**Author**: Rafael Henrique Leal Barili ([@Rlealbarili](https://github.com/Rlealbarili))  
**License**: [Apache License 2.0](LICENSE)
