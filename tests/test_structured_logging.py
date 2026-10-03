"""
Phishing Detection & Risk Intelligence Platform
Phase 24: Test Suite for Structured Logging & Privacy-Preserving Sanitization

Verifies:
1. Structured JSON formatting with mandatory fields:
   - timestamp
   - request_id
   - endpoint
   - model_version
   - prediction_latency
   - prediction_result
2. Privacy preservation & sensitive information redaction:
   - Credentials in authority (user:pass@host)
   - Sensitive query tokens (token, api_key, password, jwt, session, email)
   - Benign query parameters preserved for debugging
3. X-Request-ID correlation propagation between requests, responses, and log records
4. Route integration with FastAPI
"""

import io
import json
import logging
import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.logging_config import sanitize_url, StructuredJSONFormatter, setup_structured_logging
from api.routes import get_predictor


@pytest.fixture(autouse=True)
def ensure_default_model():
    """Ensure active model is reset to default v1 before and after each test."""
    predictor = get_predictor()
    try:
        predictor.switch_version("v1")
    except Exception:
        pass
    yield
    try:
        predictor.switch_version("v1")
    except Exception:
        pass


def test_sanitize_url_redacts_sensitive_query_parameters():
    """Verifies that authentication tokens, credentials, and PII are redacted from URLs."""
    raw_url = "https://portal.bank.com/auth?token=supersecret123&user=alice&password=mypassword&session_id=sess_789"
    sanitized = sanitize_url(raw_url)
    
    assert "supersecret123" not in sanitized
    assert "mypassword" not in sanitized
    assert "sess_789" not in sanitized
    assert "token=%5BREDACTED%5D" in sanitized or "token=[REDACTED]" in sanitized
    assert "password=%5BREDACTED%5D" in sanitized or "password=[REDACTED]" in sanitized
    assert "session_id=%5BREDACTED%5D" in sanitized or "session_id=[REDACTED]" in sanitized
    assert "user=alice" in sanitized


def test_sanitize_url_redacts_authority_credentials():
    """Verifies that username:password in URL authority is redacted."""
    raw_url = "https://admin:secretpass@secure.phish-target.com/dashboard"
    sanitized = sanitize_url(raw_url)

    assert "secretpass" not in sanitized
    assert "admin:secretpass" not in sanitized
    assert "[REDACTED]@secure.phish-target.com" in sanitized


def test_sanitize_url_preserves_benign_urls():
    """Verifies that ordinary non-sensitive query keys and structure are preserved."""
    raw_url = "https://www.google.com/search?q=machine+learning&lang=en&page=2"
    sanitized = sanitize_url(raw_url)

    assert "machine+learning" in sanitized or "machine%20learning" in sanitized
    assert "lang=en" in sanitized
    assert "page=2" in sanitized


def test_structured_json_formatter_mandatory_fields():
    """Verifies StructuredJSONFormatter produces valid JSON with all Phase 24 required fields."""
    formatter = StructuredJSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="Inference completed",
        args=(),
        exc_info=None
    )
    # Attach Phase 24 required fields
    record.request_id = "req_test_abc123"
    record.endpoint = "POST /api/v1/predict"
    record.model_version = "v1"
    record.prediction_latency = 14.5281
    record.prediction_result = {
        "prediction": "phishing",
        "risk_level": "HIGH",
        "probability": 0.9875
    }

    formatted_str = formatter.format(record)
    parsed = json.loads(formatted_str)

    assert "timestamp" in parsed
    assert parsed["request_id"] == "req_test_abc123"
    assert parsed["endpoint"] == "POST /api/v1/predict"
    assert parsed["model_version"] == "v1"
    assert parsed["prediction_latency"] == 14.5281
    assert parsed["prediction_result"]["prediction"] == "phishing"
    assert parsed["prediction_result"]["risk_level"] == "HIGH"
    assert parsed["prediction_result"]["probability"] == 0.9875


def test_predict_endpoint_attaches_request_id_and_headers():
    """Verifies X-Request-ID propagation through middleware."""
    client = TestClient(app)

    # 1. Custom incoming X-Request-ID is preserved
    custom_id = "corr-uuid-987654321"
    res1 = client.post(
        "/api/v1/predict",
        json={"url": "https://www.wikipedia.org/wiki/Phishing"},
        headers={"X-Request-ID": custom_id}
    )
    assert res1.status_code == 200
    assert res1.headers.get("X-Request-ID") == custom_id

    # 2. Automatically generated X-Request-ID when not provided
    res2 = client.post(
        "/api/v1/predict",
        json={"url": "https://www.wikipedia.org/wiki/Phishing"}
    )
    assert res2.status_code == 200
    generated_id = res2.headers.get("X-Request-ID")
    assert generated_id is not None
    assert generated_id.startswith("req_")


def test_end_to_end_structured_logging_capture():
    """
    Simulates an end-to-end API inference request and captures structured JSON logs.
    Asserts:
    1. Operational log emitted with all mandatory fields.
    2. URL is sanitized in log output.
    """
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setFormatter(StructuredJSONFormatter())

    test_logger = logging.getLogger("phishing_intelligence")
    test_logger.addHandler(handler)

    try:
        client = TestClient(app)
        secret_token = "ultra_confidential_token_xyz"
        sensitive_url = f"https://target-portal.com/login?token={secret_token}&source=email"

        response = client.post(
            "/api/v1/predict",
            json={"url": sensitive_url},
            headers={"X-Request-ID": "req_trace_phase24"}
        )
        assert response.status_code == 200

        # Flush handler output
        handler.flush()
        captured_logs = log_capture.getvalue().strip().split("\n")

        # Find the JSON log entry corresponding to the prediction completion
        prediction_logs = []
        for line in captured_logs:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                if data.get("endpoint") == "POST /predict" or "predict" in str(data.get("endpoint")):
                    prediction_logs.append(data)
            except Exception:
                pass

        assert len(prediction_logs) > 0, "Expected at least one structured prediction log"

        pred_log = prediction_logs[0]
        # Verify Phase 24 required fields:
        assert "timestamp" in pred_log
        assert "request_id" in pred_log
        assert pred_log["request_id"] == "req_trace_phase24"
        assert "endpoint" in pred_log
        assert pred_log["model_version"] in ["v1", "v2", "v3"]
        assert "prediction_latency" in pred_log
        assert isinstance(pred_log["prediction_latency"], (int, float))
        assert "prediction_result" in pred_log
        assert "prediction" in pred_log["prediction_result"]
        assert "risk_level" in pred_log["prediction_result"]

        # Verify privacy preservation: secret_token must NEVER be in log
        raw_log_text = log_capture.getvalue()
        assert secret_token not in raw_log_text, "Privacy violation: Sensitive token leaked into structured logs!"
    finally:
        test_logger.removeHandler(handler)


def test_health_and_version_endpoints_propagate_request_id():
    """Verifies that health and governance endpoints also produce X-Request-ID."""
    client = TestClient(app)

    h_res = client.get("/api/v1/health")
    assert h_res.status_code == 200
    assert "X-Request-ID" in h_res.headers

    v_res = client.get("/api/v1/model/versions")
    assert v_res.status_code == 200
    assert "X-Request-ID" in v_res.headers
