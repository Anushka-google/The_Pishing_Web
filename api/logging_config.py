"""
Phishing Detection & Risk Intelligence Platform
Phase 24: Structured Operational Logging & Privacy-Preserving Sanitization

Formats logs as structured JSON containing:
- timestamp: ISO-8601 UTC timestamp
- request_id: Unique UUID correlation token
- endpoint: HTTP method and route path
- model_version: Active model version (v1, v2, v3)
- prediction_latency: Latency in milliseconds
- prediction_result: Prediction verdict and risk assessment
- Privacy protection: Automatic redaction of sensitive query parameters and credentials
"""

import os
import re
import sys
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


SENSITIVE_QUERY_KEYS = {
    "token", "auth", "key", "api_key", "apikey", "password", "passwd",
    "secret", "access_token", "jwt", "session", "session_id", "email",
    "code", "credential", "signature", "sig", "bearer", "private", "pin"
}


def sanitize_url(raw_url: str) -> str:
    """
    Sanitizes URL to prevent leaking sensitive user credentials, tokens, or PII into logs.
    - Redacts authority userinfo: 'user:password@domain.com' -> '[REDACTED]@domain.com'
    - Redacts sensitive query string tokens: '?token=secret123&user=john' -> '?token=[REDACTED]&user=john'
    """
    if not raw_url or not isinstance(raw_url, str):
        return ""

    try:
        parsed = urlparse(raw_url.strip())
        netloc = parsed.netloc

        # 1. Redact credentials in authority if present
        if "@" in netloc:
            parts = netloc.split("@", 1)
            netloc = f"[REDACTED]@{parts[1]}"

        # 2. Redact sensitive query parameters
        if parsed.query:
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_pairs = []
            for k, v in query_pairs:
                if k.lower() in SENSITIVE_QUERY_KEYS:
                    sanitized_pairs.append((k, "[REDACTED]"))
                else:
                    sanitized_pairs.append((k, v))
            clean_query = urlencode(sanitized_pairs)
        else:
            clean_query = ""

        # Recompose sanitized URL
        clean_url = urlunparse((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            clean_query,
            parsed.fragment
        ))
        return clean_url
    except Exception:
        # Fallback safe string if URL is malformed
        return "[UNPARSEABLE_URL]"


class StructuredJSONFormatter(logging.Formatter):
    """
    Formats standard library log records as single-line structured JSON objects.
    Ensures mandatory operational visibility fields:
    timestamp, request_id, endpoint, model_version, prediction_latency, prediction_result.
    """
    def format(self, record: logging.LogRecord) -> str:
        # 1. Timestamp (UTC ISO-8601)
        created_utc = datetime.fromtimestamp(record.created, tz=timezone.utc)
        timestamp_str = created_utc.isoformat()

        # 2. Extract standard operational fields from record extra dict
        request_id = getattr(record, "request_id", None)
        endpoint = getattr(record, "endpoint", None)
        model_version = getattr(record, "model_version", None)
        prediction_latency = getattr(record, "prediction_latency", None)
        prediction_result = getattr(record, "prediction_result", None)

        log_payload: Dict[str, Any] = {
            "timestamp": timestamp_str,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage()
        }

        # Include mandatory Phase 24 operational fields if present
        if request_id is not None:
            log_payload["request_id"] = str(request_id)
        if endpoint is not None:
            log_payload["endpoint"] = str(endpoint)
        if model_version is not None:
            log_payload["model_version"] = str(model_version)
        if prediction_latency is not None:
            log_payload["prediction_latency"] = round(float(prediction_latency), 4)
        if prediction_result is not None:
            log_payload["prediction_result"] = prediction_result

        # Extra operational telemetry
        for attr in ("status_code", "total_latency_ms", "client_ip", "sanitized_url"):
            val = getattr(record, attr, None)
            if val is not None:
                log_payload[attr] = val

        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload, ensure_ascii=False)


def setup_structured_logging(
    logger_name: str = "phishing_intelligence",
    log_level: str = "INFO",
    log_file: Optional[str] = "logs/app.log"
) -> logging.Logger:
    """
    Configures and returns the application structured logger with JSON formatting.
    """
    logger = logging.getLogger(logger_name)
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(level)

    # Avoid duplicate handlers on re-import
    if not logger.handlers:
        formatter = StructuredJSONFormatter()

        # Stream handler (stdout)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        # File handler (if directory specified)
        if log_file:
            try:
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                file_handler = logging.FileHandler(log_file, encoding="utf-8")
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception:
                pass

    logger.propagate = False
    return logger


# Global default logger instance
logger = setup_structured_logging()
