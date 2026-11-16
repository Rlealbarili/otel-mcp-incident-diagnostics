"""
Unit tests for MCPGrafanaClient (backend/clients/mcp_grafana_client.py)
"""

import pytest
from backend.clients.mcp_grafana_client import MCPGrafanaClient


@pytest.mark.anyio
async def test_mcp_grafana_client_promql_query_fallback():
    """Verifies MCPGrafanaClient.query_promql_metric handles fallbacks gracefully when offline."""
    client = MCPGrafanaClient(prometheus_url="http://localhost:9999")
    res = await client.query_promql_metric("sum(rate(http_requests_total[5m]))")
    assert res["status"] == "fallback"
    assert res["query"] == "sum(rate(http_requests_total[5m]))"
    assert "error" in res


@pytest.mark.anyio
async def test_mcp_grafana_client_tempo_trace_fallback():
    """Verifies MCPGrafanaClient.query_tempo_trace handles fallbacks gracefully when offline."""
    client = MCPGrafanaClient(tempo_url="http://localhost:9999")
    res = await client.query_tempo_trace("0123456789abcdef0123456789abcdef")
    assert res["status"] == "fallback"
    assert res["trace_id"] == "0123456789abcdef0123456789abcdef"


@pytest.mark.anyio
async def test_mcp_grafana_client_loki_logql_fallback():
    """Verifies MCPGrafanaClient.query_loki_logql handles fallbacks gracefully when offline."""
    client = MCPGrafanaClient(loki_url="http://localhost:9999")
    res = await client.query_loki_logql('{app="backend"}')
    assert res["status"] == "fallback"
    assert res["query"] == '{app="backend"}'
