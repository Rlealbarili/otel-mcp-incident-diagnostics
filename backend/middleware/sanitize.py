"""
Sanitize Middleware for System Health Telemetry

Fail-closed secret & credentials regex transformation and sanitization filter for software systems telemetry.
Redacts API Keys, Bearer Tokens, Passwords, Connection Strings, Private Keys, JWTs, and PII.
"""

import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Regex Patterns for Software System Credentials & Sensitive Data
REGEX_API_KEY = re.compile(r"\b(?:sk|pk)[-_][a-zA-Z0-9_-]{16,}\b|\bapi[_-]?key[=\s:]+['\"]?[a-zA-Z0-9_-]{16,}['\"]?\b", re.IGNORECASE)
REGEX_BEARER_TOKEN = re.compile(r"Bearer\s+[a-zA-Z0-9._~+/-]+=*", re.IGNORECASE)
REGEX_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
REGEX_PASSWORD = re.compile(r"\b(?:password|passwd|secret|token|auth_key)[=\s:]+['\"]?[^\s'\";]{3,}['\"]?\b", re.IGNORECASE)
REGEX_CONN_STRING = re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^\s'\";]+\b", re.IGNORECASE)
REGEX_PRIVATE_KEY = re.compile(r"-----BEGIN[A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END[A-Z\s]+PRIVATE KEY-----")

# Legacy / General PII Regex Patterns
REGEX_CPF = re.compile(
    r"\b\d{3}[\s/.\-_]\d{3}[\s/.\-_]\d{3}[\s/.\-_]\d{2}\b"
    r"|\b(?:cpf|paciente[_\s]*cpf|patient[_\s]*cpf|id[_\s]*cpf|cpf[_\s]*(?:num|number|id))[\s:=]*\d{11}\b",
    re.IGNORECASE,
)
REGEX_SSN = re.compile(
    r"\b\d{3}[\s/.\-_]\d{2}[\s/.\-_]\d{4}\b"
    r"|\b(?:ssn|patient[_\s]*ssn|id[_\s]*ssn|ssn[_\s]*(?:num|number|id))[\s:=]*\d{9}\b",
    re.IGNORECASE,
)
REGEX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
REGEX_DOB = re.compile(
    r"\b(?:dob|born|nascimento|data\s+de\s+nascimento|date\s+of\s+birth|birth\s*date)[\s:]+(?:(?:19|20)\d{2}[-/.]\d{2}[-/.]\d{2}|\d{2}[-/.]\d{2}[-.](?:19|20)\d{2})\b",
    re.IGNORECASE,
)
REGEX_PATIENT_NAME = re.compile(
    r"\b(?:[Pp]atient|[Nn]ome|[Pp]aciente)\s+([A-Z\xc0-\xdf][a-z\xe0-\xff]+(?:\s+(?:da|de|do|dos|das|[A-Z\xc0-\xdf][a-z\xe0-\xff]+))+)\b"
)

REDACTED_TOKEN = "[REDACTED_FAIL_CLOSED]"


def sanitize_payload(payload: Any) -> str:
    """
    Fail-closed system telemetry redactor.
    Replaces API keys, tokens, credentials, connection strings, JWTs, and PII patterns with [REDACTED_FAIL_CLOSED].
    If payload is not a string or raises an exception, returns [REDACTED_FAIL_CLOSED].
    """
    if not isinstance(payload, str):
        return REDACTED_TOKEN

    try:
        sanitized = REGEX_PRIVATE_KEY.sub(REDACTED_TOKEN, payload)
        sanitized = REGEX_CONN_STRING.sub(REDACTED_TOKEN, sanitized)
        sanitized = REGEX_JWT.sub(REDACTED_TOKEN, sanitized)
        sanitized = REGEX_BEARER_TOKEN.sub(REDACTED_TOKEN, sanitized)
        sanitized = REGEX_API_KEY.sub(REDACTED_TOKEN, sanitized)
        sanitized = REGEX_PASSWORD.sub(REDACTED_TOKEN, sanitized)
        
        # PII Scrubbing
        sanitized = REGEX_CPF.sub(REDACTED_TOKEN, sanitized)
        sanitized = REGEX_SSN.sub(REDACTED_TOKEN, sanitized)
        sanitized = REGEX_EMAIL.sub(REDACTED_TOKEN, sanitized)
        sanitized = REGEX_DOB.sub(REDACTED_TOKEN, sanitized)
        sanitized = REGEX_PATIENT_NAME.sub(REDACTED_TOKEN, sanitized)
        return sanitized
    except Exception as exc:
        logger.error("Fail-closed redaction exception: %s", exc)
        return REDACTED_TOKEN
