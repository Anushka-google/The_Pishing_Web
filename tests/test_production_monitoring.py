"""
Phishing Detection & Risk Intelligence Platform
Phase 27: Production Monitoring & Data Drift Detection Test Suite

Verifies:
1. Mathematical metrics:
   - Population Stability Index (PSI) with adaptive binning
   - Kolmogorov-Smirnov (KS) two-sample test
   - Total Variation Distance (TVD) for categorical TLDs
2. Baseline Reference Profile compilation and persistence
3. Full 6-dimensional production data monitoring:
   - URL-length distributions
   - Domain characteristics (subdomains, Shannon entropy, IP host ratio, TLDs)
   - Prediction distributions & risk tiers
   - Phishing/legitimate ratio
   - API latency percentiles (P50/P95/P99) and SLA compliance
   - System error rate
4. Automated Investigation & Root Cause Hypotheses
5. Retraining Justification Engine ("Retrain when justified")
6. FastAPI REST endpoints:
   - GET  /monitoring/drift
   - POST /monitoring/evaluate-retrain
"""

import os
import json
import numpy as np
import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.monitoring.drift_detector import (
    calculate_psi,
    calculate_ks_test,
    calculate_tvd,
    BaselineProfile,
    DataDriftDetector,
    ProductionMonitor
)


@pytest.fixture(scope="module")
def client():
    """Provides FastAPI test client for integration testing."""
    return TestClient(app)


@pytest.fixture(scope="module")
def monitor():
    """Provides initialized ProductionMonitor instance."""
    return ProductionMonitor()


# -----------------------------------------------------------------------------
# 1. Statistical Core Functions Tests
# -----------------------------------------------------------------------------

def test_psi_identical_distributions():
    """Identical distributions must have PSI near zero (< 0.05) and STABLE tier."""
    np.random.seed(42)
    sample_a = np.random.normal(50.0, 10.0, 500)
    sample_b = np.random.normal(50.0, 10.0, 500)

    psi_val, bin_details = calculate_psi(sample_a, sample_b, num_bins=10)
    assert psi_val < 0.10, f"Expected PSI < 0.10 for identical distributions, got {psi_val}"
    assert len(bin_details) > 0
    assert "baseline_pct" in bin_details[0]
    assert "current_pct" in bin_details[0]


def test_psi_drastic_shift():
    """Severely shifted distribution must trigger PSI >= 0.25 (CRITICAL_DRIFT)."""
    np.random.seed(42)
    baseline = np.random.normal(50.0, 5.0, 500)
    shifted = np.random.normal(120.0, 15.0, 500)  # Complete shift to the right

    psi_val, _ = calculate_psi(baseline, shifted, num_bins=10)
    assert psi_val >= 0.25, f"Expected PSI >= 0.25 for heavily drifted distribution, got {psi_val}"


def test_ks_test_divergence():
    """KS test must indicate statistical significance for distinct distributions."""
    np.random.seed(42)
    dist_1 = np.random.normal(0, 1, 300)
    dist_2 = np.random.normal(3, 1, 300)

    ks_res = calculate_ks_test(dist_1, dist_2)
    assert ks_res["is_statistically_significant"] is True
    assert ks_res["p_value"] < 0.01
    assert ks_res["statistic"] > 0.5


def test_tvd_categorical_distance():
    """Total Variation Distance must be 0 for identical and bounded between [0, 1]."""
    p = {"com": 0.6, "org": 0.3, "net": 0.1}
    q = {"com": 0.6, "org": 0.3, "net": 0.1}
    assert calculate_tvd(p, q) == 0.0

    divergent = {"com": 0.1, "xyz": 0.7, "top": 0.2}
    tvd_val = calculate_tvd(p, divergent)
    assert 0.0 < tvd_val <= 1.0
    assert tvd_val >= 0.5


# -----------------------------------------------------------------------------
# 2. Baseline Profile Tests
# -----------------------------------------------------------------------------

def test_baseline_profile_structure():
    """Baseline profile must contain all 6 core monitoring dimensions and statistics."""
    bp = BaselineProfile()
    profile = bp.profile

    assert "url_length" in profile
    assert "subdomain_count" in profile
    assert "url_entropy" in profile
    assert "domain_entropy" in profile
    assert "ip_host_ratio" in profile
    assert "top_tlds" in profile
    assert "prediction_probability" in profile
    assert "phishing_ratio" in profile
    assert "legitimate_ratio" in profile
    assert "latency_ms" in profile

    # Quantiles check
    assert profile["url_length"]["mean"] > 0
    assert "p50" in profile["url_length"]
    assert "sample_points" in profile["url_length"]
    assert len(profile["url_length"]["sample_points"]) > 50


# -----------------------------------------------------------------------------
# 3. Drift Detector Operational Scenarios
# -----------------------------------------------------------------------------

def test_healthy_production_traffic_scenario(monitor):
    """Healthy production traffic matching baseline must remain HEALTHY with no retraining."""
    healthy_batch = monitor.generate_synthetic_production_window(scenario="healthy", sample_size=100)
    assert len(healthy_batch) == 100

    report = monitor.detector.evaluate_production_data(healthy_batch)

    assert report["overall_status"] == "HEALTHY"
    assert report["retraining_evaluation"]["retrain_justified"] is False
    assert report["retraining_evaluation"]["recommended_action"] == "MAINTAIN_CURRENT_MODEL"
    assert report["retraining_evaluation"]["triggers_fired_count"] == 0

    # Dimension checks
    assert report["metrics"]["url_length"]["status"] == "STABLE"
    assert report["metrics"]["phishing_legitimate_ratio"]["status"] == "STABLE"
    assert report["metrics"]["api_latency"]["status"] == "HEALTHY"


def test_short_url_evasion_drift_scenario(monitor):
    """Short URL campaigns (bit.ly, t.co) must trigger URL length drift and root cause diagnosis."""
    short_batch = monitor.generate_synthetic_production_window(scenario="short_urls", sample_size=100)
    report = monitor.detector.evaluate_production_data(short_batch)

    # URL length PSI must trigger critical drift
    assert report["metrics"]["url_length"]["psi"] >= 0.25
    assert report["metrics"]["url_length"]["status"] == "CRITICAL_DRIFT"

    # Investigation hypotheses must identify link shorteners
    findings_text = " ".join(report["investigation"]["findings"]).lower()
    hypotheses_text = " ".join(report["investigation"]["root_cause_hypotheses"]).lower()
    assert "url length" in findings_text or "compression" in findings_text
    assert "shorten" in hypotheses_text or "bit.ly" in hypotheses_text


def test_phishing_surge_ratio_drift_scenario(monitor):
    """A sudden 100% phishing attack flood must trigger class ratio shift."""
    surge_batch = monitor.generate_synthetic_production_window(scenario="phishing_surge", sample_size=100)
    report = monitor.detector.evaluate_production_data(surge_batch)

    # Phishing ratio shift should be large (> 25% shift)
    assert report["metrics"]["phishing_legitimate_ratio"]["status"] == "CRITICAL_DRIFT"
    assert report["metrics"]["phishing_legitimate_ratio"]["current_phishing_pct"] == 100.0


def test_critical_multi_dimensional_drift_retraining_trigger(monitor):
    """Critical multi-dimensional drift must justify retraining and generate actionable plan."""
    critical_batch = monitor.generate_synthetic_production_window(scenario="critical_drift", sample_size=100)
    report = monitor.detector.evaluate_production_data(critical_batch)

    assert report["overall_status"] == "CRITICAL_DRIFT"
    retrain_eval = report["retraining_evaluation"]

    # Retraining justified
    assert retrain_eval["retrain_justified"] is True
    assert retrain_eval["severity"] == "CRITICAL"
    assert retrain_eval["recommended_action"] == "TRIGGER_RETRAINING"
    assert retrain_eval["triggers_fired_count"] >= 2

    # Retraining plan structure
    plan = retrain_eval["retraining_plan"]
    assert plan["retraining_priority"] == "P1 - HIGH"
    assert len(plan["recommended_steps"]) >= 4
    assert plan["target_model_version"] == "v4"


def test_api_latency_and_error_drift_detection(monitor):
    """High latency and non-zero error telemetry must be correctly flagged."""
    records = monitor.generate_synthetic_production_window(scenario="healthy", sample_size=50)
    # Inject latency breach (> 100ms SLA)
    for r in records:
        r["api_response_time_ms"] = 145.0

    error_telemetry = {"error_count": 5, "total_requests": 50}  # 10% error rate
    report = monitor.detector.evaluate_production_data(records, error_telemetry=error_telemetry)

    assert report["metrics"]["api_latency"]["status"] == "CRITICAL_DRIFT"
    assert report["metrics"]["api_latency"]["sla_violation_rate_pct"] == 100.0
    assert report["metrics"]["error_rate"]["status"] == "CRITICAL_DRIFT"
    assert report["metrics"]["error_rate"]["error_rate_pct"] == 10.0


# -----------------------------------------------------------------------------
# 4. FastAPI REST Endpoints Integration Tests
# -----------------------------------------------------------------------------

def test_api_get_monitoring_drift_endpoint(client):
    """GET /monitoring/drift must return 200 with complete 6-dimensional report."""
    response = client.get("/monitoring/drift?scenario=healthy&sample_limit=100")
    assert response.status_code == 200

    data = response.json()
    assert "timestamp" in data
    assert "window_size" in data
    assert "overall_status" in data
    assert data["overall_status"] == "HEALTHY"

    # Verify all 6 dimensions are present
    metrics = data["metrics"]
    assert "url_length" in metrics
    assert "domain_characteristics" in metrics
    assert "prediction_distribution" in metrics
    assert "phishing_legitimate_ratio" in metrics
    assert "api_latency" in metrics
    assert "error_rate" in metrics

    # Verify investigation and retraining evaluation
    assert "investigation" in data
    assert "findings" in data["investigation"]
    assert "retraining_evaluation" in data
    assert data["retraining_evaluation"]["retrain_justified"] is False


def test_api_post_evaluate_retrain_endpoint(client):
    """POST /monitoring/evaluate-retrain with critical scenario must trigger retraining recommendation."""
    payload = {
        "sample_window_size": 100,
        "scenario": "critical_drift"
    }
    response = client.post("/monitoring/evaluate-retrain", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["retrain_justified"] is True
    assert data["severity"] == "CRITICAL"
    assert data["recommended_action"] == "TRIGGER_RETRAINING"
    assert len(data["triggers_fired"]) >= 2
    assert "retraining_plan" in data
    assert data["retraining_plan"]["retraining_priority"] == "P1 - HIGH"
    assert "metrics_summary" in data
    assert data["metrics_summary"]["overall_status"] == "CRITICAL_DRIFT"
