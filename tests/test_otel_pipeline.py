"""
Test OpenTelemetry Pipeline & Infrastructure Blueprint

Validates configuration syntax, topology contracts, processor sequencing,
resilience parameters, and Docker Compose network bindings for CIRES-R.
"""

from pathlib import Path
import pytest
import yaml

from backend.middleware.sanitize import sanitize_payload, REDACTED_TOKEN

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCKER_COMPOSE_PATH = PROJECT_ROOT / "scripts" / "docker-compose.yml"
OTEL_COLLECTOR_PATH = PROJECT_ROOT / "scripts" / "otel-collector.yaml"


@pytest.fixture
def otel_config():
    """Loads and parses the OpenTelemetry Collector YAML configuration."""
    assert OTEL_COLLECTOR_PATH.exists(), f"Missing config file: {OTEL_COLLECTOR_PATH}"
    with open(OTEL_COLLECTOR_PATH, "r", encoding="utf-8") as f:
        content = yaml.safe_load(f)
    assert content is not None, "otel-collector.yaml is empty or invalid YAML"
    return content


@pytest.fixture
def compose_config():
    """Loads and parses the Docker Compose YAML configuration."""
    assert DOCKER_COMPOSE_PATH.exists(), f"Missing compose file: {DOCKER_COMPOSE_PATH}"
    with open(DOCKER_COMPOSE_PATH, "r", encoding="utf-8") as f:
        content = yaml.safe_load(f)
    assert content is not None, "docker-compose.yml is empty or invalid YAML"
    return content


# ============================================================================
# 1. OPENTELEMETRY COLLECTOR TESTS
# ============================================================================

def test_otel_collector_yaml_structure(otel_config):
    """Verifies that otel-collector.yaml contains mandatory top-level sections."""
    required_sections = ["receivers", "processors", "exporters", "service", "extensions"]
    for section in required_sections:
        assert section in otel_config, f"Missing required top-level section: '{section}'"


def test_otel_collector_receivers(otel_config):
    """Validates receiver endpoint protocols and port bindings."""
    receivers = otel_config.get("receivers", {})
    assert "otlp" in receivers, "OTEL collector missing 'otlp' receiver"
    protocols = receivers["otlp"].get("protocols", {})
    
    assert "grpc" in protocols, "OTLP receiver missing gRPC protocol"
    assert "http" in protocols, "OTLP receiver missing HTTP protocol"
    
    grpc_endpoint = str(protocols["grpc"].get("endpoint", ""))
    http_endpoint = str(protocols["http"].get("endpoint", ""))
    
    assert "4317" in grpc_endpoint, f"gRPC endpoint should specify port 4317, got '{grpc_endpoint}'"
    assert "4318" in http_endpoint, f"HTTP endpoint should specify port 4318, got '{http_endpoint}'"


def test_otel_collector_memory_limiter(otel_config):
    """Verifies memory_limiter processor configuration for zero memory exhaustion."""
    processors = otel_config.get("processors", {})
    assert "memory_limiter" in processors, "Missing 'memory_limiter' processor"
    mem_limiter = processors["memory_limiter"]
    
    assert mem_limiter.get("limit_percentage") == 80, "Memory limit must be set to 80%"
    assert mem_limiter.get("spike_limit_percentage") == 20, "Spike limit must be set to 20%"
    assert mem_limiter.get("check_interval") == "1s", "Check interval must be '1s'"


def test_otel_collector_processor_order(otel_config):
    """Enforces critical processor ordering: memory_limiter -> transform/fail_closed_redactor -> batch in logs, traces, and metrics."""
    service = otel_config.get("service", {})
    pipelines = service.get("pipelines", {})
    assert len(pipelines) > 0, "No pipelines defined in service section"
    
    mandatory_pipelines = ["logs", "traces", "metrics"]
    for pipe_name in mandatory_pipelines:
        assert pipe_name in pipelines, f"Mandatory pipeline '{pipe_name}' missing from service.pipelines"
        pipe_cfg = pipelines[pipe_name]
        procs = pipe_cfg.get("processors", [])
        
        assert "memory_limiter" in procs, f"Pipeline '{pipe_name}' missing 'memory_limiter'"
        assert "transform/fail_closed_redactor" in procs, (
            f"Pipeline '{pipe_name}' missing mandatory 'transform/fail_closed_redactor' processor"
        )
        assert "batch" in procs, f"Pipeline '{pipe_name}' missing 'batch'"
        
        mem_idx = procs.index("memory_limiter")
        redact_idx = procs.index("transform/fail_closed_redactor")
        batch_idx = procs.index("batch")
        
        assert mem_idx < redact_idx < batch_idx, (
            f"Pipeline '{pipe_name}': Processor ordering MUST be memory_limiter ({mem_idx}) "
            f"-> transform/fail_closed_redactor ({redact_idx}) -> batch ({batch_idx})"
        )


def test_otel_collector_extensions_and_buffering(otel_config):
    """Verifies file_storage persistent queue extension for disk durability."""
    extensions = otel_config.get("extensions", {})
    assert "file_storage" in extensions, "OTel Collector configuration MUST define 'file_storage' extension"
    
    exporters = otel_config.get("exporters", {})
    for exp_name, exp_cfg in exporters.items():
        if isinstance(exp_cfg, dict) and "sending_queue" in exp_cfg:
            sq = exp_cfg["sending_queue"]
            assert sq.get("storage") == "file_storage", (
                f"Exporter '{exp_name}' sending_queue must use 'file_storage' queue storage"
            )


@pytest.mark.parametrize("legitimate_telemetry", [
    "2026-08-11 request completed in 45ms on port 8000",
    "2026-08-11T14:32:52Z [INFO] GET /api/v1/health status=200 duration=12ms port=4317",
    "HTTP 1.1 GET /api/v1/metrics returned status 404 in 15ms",
    "HTTP 500 internal server error on upstream service port 8080",
    "System uptime 99.9% on port 8080 with 0 errors",
    "Metric cpu_usage_percent=45.2 memory_bytes=1048576",
    "Trace id=4bf92f3577b34da6a3ce929d0e0e4736 span_id=00f067aa0ba902b7 status_code=200",
    'http_requests_total{status="200", method="GET"} 1542',
    "127.0.0.1:8000 connected to 0.0.0.0:8888",
    "Log timestamp 2026-08-11 14:36:36.123456 info message",
    "GET /api/v1/patient/status?patient_id=ANON-998877665544 status_code=200",
    "Service initialized with thread_pool=16, queue_capacity=10000",
    "Metric total_requests=12345678901 bytes_sent=123456789",
    "HTTP request duration_ns=12345678901 memory_bytes=10737418240",
    "System uptime_ms=1700000000000 active_connections=123456789",
])
def test_legitimate_telemetry_strings_pass_through(legitimate_telemetry):
    """Verifies valid system telemetry strings (ISO dates, port numbers, status codes) pass through without false redaction."""
    sanitized = sanitize_payload(legitimate_telemetry)
    assert sanitized == legitimate_telemetry, (
        f"Legitimate telemetry string was falsely redacted! Original: '{legitimate_telemetry}', Sanitized: '{sanitized}'"
    )
    assert REDACTED_TOKEN not in sanitized


@pytest.mark.parametrize("secret_input, expected_token", [
    ("API key sk-123456789012345678 present", REDACTED_TOKEN),
    ("API key pk-123456789012345678 present", REDACTED_TOKEN),
    ("sk_live_12345678901234567890", REDACTED_TOKEN),
    ('api_key="123456789012345678"', REDACTED_TOKEN),
    ("api-key: secretkey123456789", REDACTED_TOKEN),
    ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature", REDACTED_TOKEN),
    ("Bearer token_abc123456789_xyz", REDACTED_TOKEN),
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", REDACTED_TOKEN),
    ("Database postgres://admin:secret@localhost:5432/healthdb", REDACTED_TOKEN),
    ("postgresql://user:pass@host:5432/dbname?sslmode=require", REDACTED_TOKEN),
    ("redis://:secretpass@redis.internal:6379/0", REDACTED_TOKEN),
    ("amqp://guest:guest@rabbitmq:5672/", REDACTED_TOKEN),
    ("User password='SecretPassword123' logged in", REDACTED_TOKEN),
    ('passwd: "admin123"', REDACTED_TOKEN),
    ("secret='my-app-secret-value'", REDACTED_TOKEN),
    ("token=xyz123abc456", REDACTED_TOKEN),
    ("auth_key: 998877665544", REDACTED_TOKEN),
    ("-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----", REDACTED_TOKEN),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----", REDACTED_TOKEN),
])
def test_sensitive_credentials_redaction(secret_input, expected_token):
    """Verifies that API keys, Bearer tokens, passwords, connection strings, JWTs, and private keys are properly redacted."""
    sanitized = sanitize_payload(secret_input)
    assert expected_token in sanitized


def test_otel_collector_ottl_statements_empirical_verification(otel_config):
    """Empirically parses and verifies all OTTL regex statements in otel-collector.yaml against secret and legitimate telemetry inputs."""
    import re
    redact_cfg = otel_config.get("processors", {}).get("transform/fail_closed_redactor", {})
    all_statements = []
    for key in ["log_statements", "trace_statements", "metric_statements"]:
        blocks = redact_cfg.get(key, [])
        for block in blocks:
            all_statements.extend(block.get("statements", []))
            
    assert len(all_statements) > 0, "No OTTL statements found in transform/fail_closed_redactor"

    patterns = []
    for stmt in all_statements:
        idx1 = stmt.find('"value", "')
        if idx1 != -1:
            idx1 += len('"value", "')
            idx2 = stmt.find('", "', idx1)
            if idx2 != -1:
                pat_str = stmt[idx1:idx2]
                clean_pat = pat_str.encode("utf-8").decode("unicode_escape") if "\\\\" in pat_str else pat_str
                flags = re.IGNORECASE if any(k in pat_str for k in ["password", "postgres", "bearer", "api"]) else 0
                patterns.append((pat_str, re.compile(clean_pat, flags)))

    assert len(patterns) > 0, "Failed to extract regex patterns from OTTL statements"

    legitimate_inputs = [
        "2026-08-11 request completed in 45ms on port 8000",
        "2026-08-11T14:32:52Z [INFO] GET /api/v1/health status=200 duration=12ms port=4317",
        "HTTP 1.1 GET /api/v1/metrics returned status 404 in 15ms",
        "System uptime 99.9% on port 8080 with 0 errors",
    ]
    for leg in legitimate_inputs:
        for pat_str, comp_pat in patterns:
            assert not comp_pat.search(leg), f"OTTL pattern '{pat_str}' falsely matched legitimate telemetry: '{leg}'"

    secret_inputs = [
        "API key sk-123456789012345678 present",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        "Database postgres://admin:secret@localhost:5432/healthdb",
        "User password='SecretPassword123' logged in",
        "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----",
    ]
    for sec in secret_inputs:
        matched = any(comp_pat.search(sec) for _, comp_pat in patterns)
        assert matched, f"Secret input '{sec}' was NOT matched by any OTTL regex pattern in otel-collector.yaml"



# ============================================================================
# 2. DOCKER COMPOSE TOPOLOGY & INTEGRATION TESTS
# ============================================================================

def test_docker_compose_services(compose_config):
    """Validates that all required LGTM stack services are defined."""
    services = compose_config.get("services", {})
    required_services = ["otel-collector", "grafana", "loki", "tempo"]
    
    for svc in required_services:
        assert svc in services, f"docker-compose.yml missing service '{svc}'"
    
    # Must have either mimir or prometheus for metrics
    has_metrics_backend = ("mimir" in services) or ("prometheus" in services)
    assert has_metrics_backend, "docker-compose.yml must define either 'mimir' or 'prometheus' service"


def test_docker_compose_ports(compose_config):
    """Validates exposed port mappings for OTel and LGTM services."""
    services = compose_config.get("services", {})
    all_ports = []
    for svc_name, svc_cfg in services.items():
        ports = svc_cfg.get("ports", [])
        for p in ports:
            port_str = str(p)
            host_port = port_str.split(":")[0] if ":" in port_str else port_str
            all_ports.append(host_port)
            
    required_ports = ["4317", "4318", "3000", "3100", "3200", "9090"]
    for rp in required_ports:
        assert any(rp == p for p in all_ports), f"Required host port mapping '{rp}' missing from docker-compose.yml"


def test_docker_compose_networks(compose_config):
    """Validates network isolation via 'health-net' bridge network."""
    networks = compose_config.get("networks", {})
    assert "health-net" in networks, "docker-compose.yml missing isolated network 'health-net'"
    
    services = compose_config.get("services", {})
    for svc_name, svc_cfg in services.items():
        svc_nets = svc_cfg.get("networks", [])
        if isinstance(svc_nets, list):
            assert "health-net" in svc_nets, f"Service '{svc_name}' is not attached to 'health-net' network"
        elif isinstance(svc_nets, dict):
            assert "health-net" in svc_nets, f"Service '{svc_name}' is not attached to 'health-net' network"


def test_docker_compose_healthchecks(compose_config):
    """Ensures healthcheck blocks exist for container resilience."""
    services = compose_config.get("services", {})
    for svc_name, svc_cfg in services.items():
        assert "healthcheck" in svc_cfg, f"Service '{svc_name}' missing mandatory healthcheck configuration"
        hc = svc_cfg["healthcheck"]
        assert "test" in hc, f"Service '{svc_name}' healthcheck missing 'test' command"


def test_docker_compose_volume_mounts(compose_config):
    """Ensures services configure appropriate persistent volume mounts."""
    services = compose_config.get("services", {})
    for svc_name, svc_cfg in services.items():
        assert "volumes" in svc_cfg, f"Service '{svc_name}' missing volume mounts"
        assert len(svc_cfg["volumes"]) > 0, f"Service '{svc_name}' has empty volume mounts list"
