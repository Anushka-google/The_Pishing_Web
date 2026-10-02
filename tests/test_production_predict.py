import os
import pytest
from src.prediction.predict import ProductionPredictor


def test_production_predictor_single_url():
    predictor = ProductionPredictor(enable_shap=True)
    res = predictor.predict("https://www.github.com/torvalds/linux", include_explanation=True)

    assert "url" in res
    assert "prediction" in res
    assert "probability" in res
    assert "risk_level" in res
    assert "action" in res
    assert "features" in res
    assert "explanation" in res
    assert "metadata" in res

    assert res["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
    assert 0.0 <= res["probability"] <= 1.0
    assert res["metadata"]["total_latency_ms"] > 0


def test_production_predictor_batch():
    predictor = ProductionPredictor(enable_shap=False)
    urls = [
        "https://www.google.com",
        "https://login.microsoftonline.com",
        "http://phish-login-update.cc/verify"
    ]
    results = predictor.predict_batch(urls)

    assert len(results) == 3
    for r in results:
        assert "prediction" in r
        assert "probability" in r
