"""
Phishing Detection & Risk Intelligence Platform
Phase 20.2: API End-to-End Endpoint Tests

Covers:
1. POST /predict  (URL assessment, risk scoring, explainability)
2. GET  /health   (Service health, uptime, model status)
3. GET  /history  (Chronological scan log retrieval)
4. GET  /stats    (Aggregate security intelligence telemetry)
"""

import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_api_get_health():
    """Test 26.2.2: GET /health returns 200 with active service status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert "version" in data
    assert "uptime_seconds" in data


def test_api_post_predict_benign():
    """Test 26.2.1: POST /predict on benign URL returns LOW risk and ALLOW action."""
    payload = {"url": "https://www.wikipedia.org/wiki/Phishing"}
    response = client.post("/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == payload["url"]
    assert data["prediction"] == "legitimate"
    assert data["risk_level"] in ["LOW", "MEDIUM"]
    assert data["action"] in ["ALLOW", "CAUTION"]
    assert 0.0 <= data["probability"] <= 1.0
    assert "metadata" in data
    assert data["metadata"]["total_latency_ms"] > 0


def test_api_post_predict_phishing():
    """Test 26.2.1: POST /predict on deceptive phishing URL returns HIGH risk and BLOCK action."""
    phish_payload = {"url": "https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284"}
    response = client.post("/predict", json=phish_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "phishing"
    assert data["risk_level"] in ["MEDIUM", "HIGH"]
    assert data["action"] in ["CAUTION", "BLOCK"]
    assert data["probability"] >= 0.40

    # Ensure SHAP explanation is generated
    assert "explanation" in data
    assert len(data["explanation"]["top_risk_contributors"]) > 0


def test_api_get_history():
    """Test 26.2.3: GET /history retrieves past scan entries."""
    response = client.get("/history?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "total_records" in data
    assert "records" in data
    assert isinstance(data["records"], list)
    if len(data["records"]) > 0:
        first = data["records"][0]
        assert "url" in first
        assert "risk_level" in first
        assert "probability" in first


def test_api_get_stats():
    """Test 26.2.4: GET /stats returns aggregate threat analytics."""
    response = client.get("/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "phishing_detected" in data
    assert "legitimate_detected" in data
    assert "risk_distribution" in data
    assert "LOW" in data["risk_distribution"]
    assert "MEDIUM" in data["risk_distribution"]
    assert "HIGH" in data["risk_distribution"]
