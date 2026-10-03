# Phase 24: Structured Operational Logging & Privacy-Preserving Sanitization

## 1. Executive Summary & Objectives

Modern production cybersecurity platforms require deep operational visibility to diagnose system behavior, track threat classification decisions, audit latency anomalies, and trace distributed requests. However, logging raw requests without stringent safeguards creates severe privacy and regulatory vulnerabilities (GDPR, CCPA, PCI-DSS, SOC 2).

**Phase 24** implements an enterprise-grade structured JSON logging pipeline and privacy-preserving URL sanitization engine for the Phishing Detection & Risk Intelligence Platform.

```
                          Incoming Request (with/without X-Request-ID)
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │  StructuredLoggingMiddleware  │
                             │  - Injects / correlates req_id│
                             │  - Starts high-res stopwatch  │
                             └───────────────┬───────────────┘
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │       FastAPI Endpoint        │
                             │  (e.g., POST /api/v1/predict) │
                             │                               │
                             │  1. Predictor inference       │
                             │  2. Privacy URL Sanitization  │
                             │  3. Attach state attributes:  │
                             │     - model_version           │
                             │     - prediction_latency      │
                             │     - prediction_result       │
                             │     - sanitized_url           │
                             └───────────────┬───────────────┘
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │    StructuredJSONFormatter    │
                             │  - Formats single-line JSON   │
                             │  - Standardizes UTC timestamp │
                             │  - Guaranteed schema layout   │
                             └───────────────┬───────────────┘
                                             │
                      ┌──────────────────────┴──────────────────────┐
                      ▼                                             ▼
               Standard Output                                Rotating File
             (Docker / K8s / Cloud)                          (`logs/app.log`)
```

---

## 2. Mandatory Log Schema

Every operational log record generated during request processing or inference emits a single-line JSON object adhering to the schema below:

| Field Name | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `timestamp` | String (ISO-8601 UTC) | Exact UTC timestamp of log event creation | `"2026-10-03T09:05:12.384102+00:00"` |
| `request_id` | String | Unique correlation UUID tracking request lifecycle | `"req_3f8a9b1c7d2e"` |
| `endpoint` | String | HTTP method and path of targeted route | `"POST /api/v1/predict"` |
| `model_version` | String | Active machine learning model version in production | `"v1"` |
| `prediction_latency`| Float (ms) | Pure model inference and SHAP calculation time | `12.4851` |
| `prediction_result` | Object | Verdict classification, threat level, and probability | `{"prediction": "phishing", "risk_level": "HIGH", "probability": 0.9994}` |
| `sanitized_url` | String | Cleaned URL with all secrets and credentials redacted | `"https://login.portal.com/auth?token=[REDACTED]"` |
| `status_code` | Integer | HTTP response status code | `200` |
| `total_latency_ms`| Float (ms) | Complete end-to-end roundtrip HTTP latency | `18.239` |
| `client_ip` | String | Client host address | `"127.0.0.1"` |
| `level` | String | Logging level (`INFO`, `WARNING`, `ERROR`) | `"INFO"` |

### Example Log Output
```json
{
  "timestamp": "2026-10-03T09:05:12.384102+00:00",
  "level": "INFO",
  "logger": "phishing_intelligence",
  "message": "Prediction completed: PHISHING (HIGH)",
  "request_id": "req_a1b2c3d4e5f6",
  "endpoint": "POST /predict",
  "model_version": "v1",
  "prediction_latency": 13.8214,
  "prediction_result": {
    "prediction": "phishing",
    "risk_level": "HIGH",
    "probability": 0.9994
  },
  "sanitized_url": "https://secure-login.chase-verify.com/login?token=[REDACTED]&ref=email",
  "status_code": 200,
  "total_latency_ms": 19.451,
  "client_ip": "127.0.0.1"
}
```

---

## 3. Privacy-Preserving Sanitization (`sanitize_url`)

To comply with the strict requirement — *"Do not unnecessarily log sensitive user information"* — incoming URLs undergo RFC 3986 lexical decomposition prior to any logging:

1. **Authority Credential Stripping**:
   Any username or password embedded within the network location (`https://user:password@domain.com`) is stripped and replaced with `[REDACTED]@domain.com`.
2. **Sensitive Query Parameter Scrubbing**:
   All query string key-value pairs are inspected against a sensitive key blacklist:
   `token`, `auth`, `key`, `api_key`, `apikey`, `password`, `passwd`, `secret`, `access_token`, `jwt`, `session`, `session_id`, `email`, `code`, `credential`, `signature`, `sig`, `bearer`, `private`, `pin`.
   Values matching these keys are replaced with `[REDACTED]`.
3. **Preservation of Benign Structure**:
   Non-sensitive parameters (e.g., `lang=en`, `q=phishing+definition`, `page=1`) and path structures are preserved, allowing cybersecurity engineers to debug classification behavior without compromising client privacy.
4. **Header and Payload Sanitization**:
   Raw authentication headers (`Authorization`, `Cookie`, `X-API-Key`) are never included in structured operational logs.

---

## 4. End-to-End Tracing (`X-Request-ID`)

The platform supports distributed tracing across microservices, browser extensions, and API gateways:
- If an incoming request includes an `X-Request-ID` header, the middleware adopts that ID for all logs and emits it in the response header.
- If no header is present, the middleware automatically mints a unique `req_<uuid12>` identifier.
- The `request_id` is propagated to `request.state` and injected into every log entry generated by the route handler.

---

## 5. Architectural Components

1. **`api/logging_config.py`**:
   - `sanitize_url(raw_url: str) -> str`: RFC 3986 parser and secret redactor.
   - `StructuredJSONFormatter(logging.Formatter)`: Custom JSON serializer emitting ISO-8601 UTC timestamps and operational keys.
   - `setup_structured_logging(...)`: Configures stdout stream and rotating file handlers (`logs/app.log`).

2. **`api/middleware.py`**:
   - `StructuredLoggingMiddleware(BaseHTTPMiddleware)`: Intercepts all incoming requests, computes high-precision duration (`perf_counter`), extracts route telemetry from `request.state`, and logs structured JSON.

3. **`api/routes.py`**:
   - Updates `POST /predict`, `GET /health`, `GET /history`, `GET /stats`, `GET /model/versions`, `POST /model/switch`, and `POST /model/rollback` to populate `request.state.model_version`, `prediction_latency`, and `prediction_result`.

4. **`tests/test_structured_logging.py`**:
   - Comprehensive test suite covering URL sanitization, credential redaction, JSON formatting, request ID correlation, and live log stream interception.
