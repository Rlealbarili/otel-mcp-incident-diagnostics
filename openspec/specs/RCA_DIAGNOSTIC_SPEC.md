# OpenSpec Specification: Automated Incident RCA Engine (NIST CSF 2.0)

## 1. Trigger Mechanics
Initiated by metric anomalies (`http_requests_total` status 500 or latency > 500ms).

## 2. Multi-Signal Correlation Workflow
1. **Metric**: PromQL query in Mimir extracts exemplar `trace_id`.
2. **Trace**: Tempo lookup via `trace_id` traverses span tree to locate failing span.
3. **Log**: Loki LogQL lookup `{trace_id="..."}` retrieves error stack trace.
4. **Playbook**: Generates 6-function NIST CSF 2.0 mitigation plan.

## 3. Cooldown & Deduplication
Applies a 60-second cooldown per `(component, fault_mode)` tuple to avoid notification floods.
