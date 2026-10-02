"""
Phishing Detection & Risk Intelligence Platform
Phase 20.3: Machine Learning Invariant Tests

Verifies critical ML production constraints:
1. Model artifact loads successfully without missing dependencies.
2. Feature vector dimensions match training specification (22 features).
3. Prediction labels are strictly valid ('phishing' | 'legitimate').
4. Predicted probabilities are strictly bounded within [0.0, 1.0].
5. Probability distributions sum to 1.0 across classes.
"""

import os
import pytest
import numpy as np
import joblib

from src.features.extractor import FeatureExtractor
from src.prediction.predict import ProductionPredictor


@pytest.fixture(scope="module")
def model_package():
    model_path = "models/champion_phishing_model.joblib"
    assert os.path.exists(model_path), f"Champion model artifact missing at {model_path}"
    pkg = joblib.load(model_path)
    return pkg


@pytest.fixture(scope="module")
def predictor():
    return ProductionPredictor(enable_shap=False)


def test_ml_model_loads_successfully(model_package):
    """Test 26.3.1: Model loads successfully with all required dictionary keys."""
    assert "model" in model_package
    assert "feature_names" in model_package
    assert "thresholds" in model_package
    assert model_package["model"] is not None


def test_ml_feature_dimensions_match_training(model_package):
    """Test 26.3.2: Feature dimensions match training (22 features)."""
    expected_dim = len(FeatureExtractor.FEATURE_NAMES)
    assert expected_dim == 22, f"Expected 22 features, got {expected_dim}"

    # Verify model trained dimensions
    model = model_package["model"]
    assert hasattr(model, "n_features_in_")
    assert model.n_features_in_ == 22

    # Verify extractor produces exact 22 features
    extractor = FeatureExtractor()
    feat_vector = extractor.extract_features_vector("https://example.com")
    assert feat_vector.shape == (22,)


def test_ml_prediction_validity(predictor):
    """Test 26.3.3: Prediction is strictly valid ('phishing' or 'legitimate')."""
    test_cases = [
        "https://www.google.com",
        "https://login.microsoftonline.com/common/oauth2",
        "https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284",
        "http://192.168.1.1:8080/admin/auth?session=4819"
    ]

    for url in test_cases:
        res = predictor.predict(url, include_explanation=False)
        assert res["prediction"] in ["phishing", "legitimate"]
        assert res["risk_level"] in ["LOW", "MEDIUM", "HIGH"]
        assert res["action"] in ["ALLOW", "CAUTION", "BLOCK"]


def test_ml_probability_within_zero_one(predictor, model_package):
    """Test 26.3.4: Probability is strictly within [0.0, 1.0] and sums to 1."""
    model = model_package["model"]
    extractor = FeatureExtractor()

    sample_urls = [
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://github.com/torvalds/linux",
        "http://portal-9797.online/home/v2",
        "https://wellsfargo-verify-22.club/portal/verify"
    ]

    for url in sample_urls:
        vector = extractor.extract_features_vector(url).reshape(1, -1)
        probas = model.predict_proba(vector)[0]

        # Invariant: Each probability must be in [0, 1]
        assert 0.0 <= probas[0] <= 1.0
        assert 0.0 <= probas[1] <= 1.0

        # Invariant: Probabilities must sum to 1.0 within floating point tolerance
        assert np.isclose(np.sum(probas), 1.0, atol=1e-5)

        # Production predictor check
        res = predictor.predict(url, include_explanation=False)
        assert 0.0 <= res["probability"] <= 1.0
