import os
import pytest
from src.explanation.shap_explainer import PhishingExplainer


def test_shap_explainer_initialization():
    explainer = PhishingExplainer()
    assert explainer.model is not None
    assert explainer.explainer is not None


def test_shap_global_importance():
    explainer = PhishingExplainer()
    report = explainer.compute_global_importance(sample_size=50)

    assert "rankings" in report
    assert len(report["rankings"]) == len(explainer.feature_names)
    assert report["rankings"][0]["mean_abs_shap"] >= report["rankings"][-1]["mean_abs_shap"]
    assert os.path.exists("data/processed/global_shap_importance.json")


def test_shap_local_url_explanation():
    explainer = PhishingExplainer()

    benign_url = "https://www.wikipedia.org/wiki/Machine_learning"
    phish_url = "https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284"

    res_benign = explainer.explain_url(benign_url)
    res_phish = explainer.explain_url(phish_url)

    assert "phishing_probability" in res_benign
    assert "risk_level" in res_benign
    assert "action" in res_benign
    assert "top_risk_contributors" in res_benign
    assert "top_mitigating_factors" in res_benign
    assert "recommendation" in res_benign

    assert res_benign["phishing_probability"] <= res_phish["phishing_probability"]
    assert res_phish["risk_level"] in ["MEDIUM", "HIGH"]
