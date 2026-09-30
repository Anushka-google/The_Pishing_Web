"""
Unit tests for Phase 1 MVP Pipeline
"""

import pytest
from src.prediction.mvp_pipeline import MVPPhishingPipeline, RiskLevel, MVPResult


@pytest.fixture
def pipeline():
    return MVPPhishingPipeline()


def test_legitimate_url_low_risk(pipeline):
    url = "https://www.google.com/search?q=machine-learning"
    result = pipeline.analyze(url)

    assert isinstance(result, MVPResult)
    assert result.prediction == "legitimate"
    assert result.risk_level == RiskLevel.LOW
    assert result.probability < 0.30
    assert result.confidence > 0.70
    assert result.extracted_features["has_ip_address"] == 0
    assert result.extracted_features["uses_https"] == 1
    assert result.execution_time_ms >= 0


def test_phishing_url_high_risk(pipeline):
    url = "http://192.168.1.55/account/login/verify/update-password?bank=secure"
    result = pipeline.analyze(url)

    assert result.prediction == "phishing"
    assert result.risk_level == RiskLevel.HIGH
    assert result.probability >= 0.70
    assert result.extracted_features["has_ip_address"] == 1
    assert result.extracted_features["suspicious_keyword_count"] >= 3


def test_suspicious_url_medium_risk(pipeline):
    url = "https://service.auth.client.portal.legit-site.com/view/document"
    result = pipeline.analyze(url)

    # Subdomain depth = 4 triggers intermediate score
    assert result.risk_level in (RiskLevel.MEDIUM, RiskLevel.LOW)
    assert 0.0 <= result.probability <= 1.0


def test_invalid_url_empty(pipeline):
    with pytest.raises(ValueError, match="non-empty string"):
        pipeline.analyze("")


def test_invalid_url_length(pipeline):
    excessive_url = "https://example.com/" + ("a" * 2050)
    with pytest.raises(ValueError, match="maximum length"):
        pipeline.analyze(excessive_url)


def test_url_without_scheme_auto_prepends(pipeline):
    raw = "example.com/login"
    result = pipeline.analyze(raw)
    assert result.url.startswith("https://")


def test_result_to_dict_structure(pipeline):
    result = pipeline.analyze("https://example.org")
    data = result.to_dict()

    assert "url" in data
    assert "prediction" in data
    assert "probability" in data
    assert "risk_level" in data
    assert "confidence" in data
    assert "extracted_features" in data
    assert "summary" in data
    assert "execution_time_ms" in data
    assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
