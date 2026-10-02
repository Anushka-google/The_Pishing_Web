import os
import pytest
import numpy as np
from src.evaluation.threshold_optimizer import ThresholdOptimizer, classify_risk


def test_classify_risk():
    low = classify_risk(0.15, t1=0.40, t2=0.65)
    assert low["risk_level"] == "LOW"
    assert low["action"] == "ALLOW"

    med = classify_risk(0.50, t1=0.40, t2=0.65)
    assert med["risk_level"] == "MEDIUM"
    assert med["action"] == "CAUTION"

    high = classify_risk(0.85, t1=0.40, t2=0.65)
    assert high["risk_level"] == "HIGH"
    assert high["action"] == "BLOCK"


def test_threshold_optimizer_execution():
    optimizer = ThresholdOptimizer()
    report = optimizer.optimize()

    assert "optimal_f1_threshold" in report
    assert "calibrated_thresholds" in report
    t1 = report["calibrated_thresholds"]["t1_low_risk_threshold"]
    t2 = report["calibrated_thresholds"]["t2_high_risk_threshold"]

    assert 0.0 < t1 < t2 < 1.0
    assert os.path.exists("data/processed/threshold_calibration.json")
