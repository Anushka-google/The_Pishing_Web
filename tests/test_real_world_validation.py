"""
Unit tests for Real-World Dataset Validation (URLhaus + Tranco)
"""

import os
import pytest
from src.training.validate_real_world import RealWorldValidator


def test_real_world_files_exist():
    assert os.path.exists("data/real_world/urls_real_world.csv")
    assert os.path.exists("data/real_world/features_real_world.csv")
    assert os.path.exists("data/real_world/real_world_metrics.json")


def test_real_world_benchmark_execution():
    validator = RealWorldValidator()
    report = validator.run_real_world_benchmark()

    assert report["total_real_world_samples"] == 10000
    assert report["unique_domains"] > 5000
    assert report["domain_leakage_overlap"] == 0

    assert len(report["models_benchmark"]) == 4
    for r in report["models_benchmark"]:
        assert 0.95 <= r["accuracy"] <= 1.0
        assert 0.95 <= r["recall"] <= 1.0
        assert 0.95 <= r["f1_score"] <= 1.0
