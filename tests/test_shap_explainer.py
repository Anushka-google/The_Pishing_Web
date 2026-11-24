import os
import warnings
import pytest
import numpy as np
import pandas as pd
from src.explanation.shap_explainer import PhishingExplainer
from src.prediction.predict import ProductionPredictor
from src.features.extractor import FeatureExtractor


def test_shap_explainer_initialization():
    explainer = PhishingExplainer()
    assert explainer.model is not None
    assert explainer.explainer is not None
    assert len(explainer.feature_names) == 22


def test_shap_global_importance():
    explainer = PhishingExplainer()
    report = explainer.compute_global_importance(sample_size=50)

    assert "rankings" in report
    assert len(report["rankings"]) == len(explainer.feature_names)
    assert report["rankings"][0]["mean_abs_shap"] >= report["rankings"][-1]["mean_abs_shap"]
    assert os.path.exists("data/processed/global_shap_importance.json")


def test_shap_additive_consistency():
    """Validates the fundamental SHAP additive efficiency property: Base Value + sum(phi_i) == Raw Probability."""
    explainer = PhishingExplainer()
    urls = [
        "https://www.wikipedia.org/wiki/Machine_learning",
        "https://accounts.google.com/signin/v2/identifier",
        "https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284",
        "https://secure.appleid-support-21.club/portal/login?auth=9183",
        "http://192.168.1.100:8080/admin"
    ]

    for url in urls:
        res = explainer.explain_url(url)
        assert res["is_additively_consistent"] is True
        assert res["additive_residual"] < 1e-3
        # reconstructed_probability is base_value + all SHAP impacts
        assert abs(res["reconstructed_probability"] - res["raw_probability"]) < 1e-3


def test_no_feature_name_warnings():
    """Ensures inference and SHAP attribution run cleanly with zero UserWarning about feature names."""
    explainer = PhishingExplainer()
    test_url = "https://accounts.google.com/ServiceLogin"

    with warnings.catch_warnings(record=True) as recorded_warnings:
        warnings.simplefilter("always")
        _ = explainer.explain_url(test_url)

        feature_warnings = [
            w for w in recorded_warnings
            if "does not have valid feature names" in str(w.message)
        ]
        assert len(feature_warnings) == 0, f"Encountered feature name warnings: {feature_warnings}"


def test_local_explanations_across_6_archetypes():
    """Validates SHAP attribution and directive assignment across 6 mandatory URL archetypes."""
    explainer = PhishingExplainer()

    archetypes = {
        "legitimate": "https://www.wikipedia.org/wiki/Machine_learning",
        "suspicious": "https://secure.appleid-support-21.club/portal/login?auth=9183",
        "brand_impersonation": "https://auth.chase.com.cloud-node-147.cc/session/update",
        "user_info_deception": "http://admin:pass@verify-bank.com/account",
        "punycode": "http://xn--gogle-pua.com/signin",
        "direct_ip": "http://192.168.1.100:8080/login.html"
    }

    results = {}
    for name, url in archetypes.items():
        res = explainer.explain_url(url)
        results[name] = res

        # Core assertions for every archetype
        assert "phishing_probability" in res
        assert "risk_level" in res
        assert "action" in res
        assert res["action"] in ["ALLOW", "CAUTION", "BLOCK"]
        assert "top_risk_contributors" in res
        assert "top_mitigating_factors" in res
        assert "narrative_signals" in res
        assert "narrative_mitigators" in res
        assert "recommendation" in res
        assert res["is_additively_consistent"] is True

        # Check feature values and SHAP contributions exist and are non-empty
        all_features = res["top_risk_contributors"] + res["top_mitigating_factors"]
        assert len(all_features) > 0
        for feat in all_features:
            assert "feature" in feat
            assert "value" in feat
            assert "shap_impact" in feat
            assert "direction" in feat
            if feat["direction"] == "RISK_INCREASING":
                assert feat["shap_impact"] > 0
            else:
                assert feat["shap_impact"] < 0

    # Archetype-specific assertions
    # 1. Legitimate: ALLOW
    assert results["legitimate"]["action"] == "ALLOW"
    assert results["legitimate"]["risk_level"] == "LOW"

    # 2. Suspicious: BLOCK
    assert results["suspicious"]["action"] == "BLOCK"
    assert results["suspicious"]["phishing_probability"] >= 0.65

    # 3. Brand impersonation: BLOCK
    assert results["brand_impersonation"]["action"] == "BLOCK"
    assert results["brand_impersonation"]["phishing_probability"] >= 0.65

    # 4. Direct IP: has_ip_address identified in risk drivers
    direct_ip_risk = [c["feature"] for c in results["direct_ip"]["top_risk_contributors"]]
    assert "has_ip_address" in direct_ip_risk


def test_operational_directive_thresholds():
    """Validates the strict operational risk thresholds: ALLOW (<0.40), CAUTION (0.40-0.65), BLOCK (>=0.65)."""
    predictor = ProductionPredictor()
    assert predictor.t1_low == 0.40
    assert predictor.t2_high == 0.65

    test_cases = [
        (0.10, "LOW", "ALLOW"),
        (0.399, "LOW", "ALLOW"),
        (0.40, "MEDIUM", "CAUTION"),
        (0.50, "MEDIUM", "CAUTION"),
        (0.649, "MEDIUM", "CAUTION"),
        (0.65, "HIGH", "BLOCK"),
        (0.95, "HIGH", "BLOCK"),
    ]

    for prob, expected_risk, expected_action in test_cases:
        if prob < predictor.t1_low:
            risk = "LOW"
            action = "ALLOW"
        elif prob < predictor.t2_high:
            risk = "MEDIUM"
            action = "CAUTION"
        else:
            risk = "HIGH"
            action = "BLOCK"

        assert risk == expected_risk
        assert action == expected_action


def test_production_predictor_with_calibrator():
    """Validates that ProductionPredictor loads calibrator and reports calibrated probability in metadata."""
    predictor = ProductionPredictor()
    res = predictor.predict("https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284")

    assert "probability" in res
    assert "metadata" in res
    assert "calibrated" in res["metadata"]
    assert res["metadata"]["calibrated"] is True
    assert "raw_probability" in res["metadata"]
    assert "action" in res
    assert res["action"] in ["ALLOW", "CAUTION", "BLOCK"]
