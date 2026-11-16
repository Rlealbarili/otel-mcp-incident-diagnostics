# OpenSpec Specification: Fail-Closed Secrets & Credentials Sanitization Engine

## 1. Scope & Mandate
Defines mandatory fail-closed redaction rules for software application secrets, API keys, Bearer tokens, JWTs, connection strings, private keys, passwords, and sensitive identifiers.

## 2. Redaction Patterns
- **API Keys**: `\b(?:sk|pk)[-_][a-zA-Z0-9_-]{16,}\b` -> `[REDACTED_FAIL_CLOSED]`
- **Bearer Tokens**: `Bearer\s+[a-zA-Z0-9._~+/-]+=*` -> `[REDACTED_FAIL_CLOSED]`
- **Connection Strings**: `\b(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^\s'\";]+\b` -> `[REDACTED_FAIL_CLOSED]`
- **JWT Tokens**: `\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b` -> `[REDACTED_FAIL_CLOSED]`
- **Private Keys**: `-----BEGIN[A-Z\s]+PRIVATE KEY-----...-----END[A-Z\s]+PRIVATE KEY-----` -> `[REDACTED_FAIL_CLOSED]`

## 3. Fail-Closed Guarantee
If sanitization parsing encounters errors, unhandled exceptions, or regex timeouts, the body/payload is replaced with `[REDACTED_FAIL_CLOSED]`.

## 4. Operational Metrics Preservation & Unlabelled Digit Trade-off
To prevent signal destruction of valid operational telemetry (such as ISO timestamps, metric byte counters, port numbers, and Unix epoch milliseconds), unlabelled 9-digit and 11-digit standalone numbers are allowed through the pipeline. Contextual PII keywords (e.g. `cpf:`, `ssn:`) or formatted delimiters remain strictly redacted under fail-closed security.
