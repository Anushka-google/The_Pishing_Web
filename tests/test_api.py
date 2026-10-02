import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert "service" in data


def test_predict_benign_url():
    response = client.post("/predict", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://www.google.com"
    assert data["prediction"] == "legitimate"
    assert data["risk_level"] in ["LOW", "MEDIUM"]
    assert "explanation" in data
    assert "metadata" in data


def test_predict_phishing_url():
    phish_url = "https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284"
    response = client.post("/predict", json={"url": phish_url})
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "phishing"
    assert data["risk_level"] in ["MEDIUM", "HIGH"]
    assert data["probability"] >= 0.50
    assert len(data["explanation"]["top_risk_contributors"]) > 0


def test_input_validation_empty_url():
    response = client.post("/predict", json={"url": ""})
    assert response.status_code == 422
    assert "error" in response.json()


def test_input_validation_unsupported_scheme():
    response = client.post("/predict", json={"url": "ftp://files.example.com/archive.zip"})
    assert response.status_code == 422
    assert "error" in response.json()


def test_input_validation_oversized_url():
    oversized = "https://example.com/" + "a" * 2100
    response = client.post("/predict", json={"url": oversized})
    assert response.status_code == 422
    assert "error" in response.json()


def test_history_and_stats_endpoints():
    # History
    hist_resp = client.get("/history")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert "total_records" in hist_data
    assert isinstance(hist_data["records"], list)

    # Stats
    stats_resp = client.get("/stats")
    assert stats_resp.status_code == 200
    stats_data = stats_resp.json()
    assert "total_scans" in stats_data
    assert "risk_distribution" in stats_data
    assert stats_data["total_scans"] >= 2
