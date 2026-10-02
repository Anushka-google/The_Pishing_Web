"""
Unit tests for Phase 11: Leakage-Safe Domain-Grouped Evaluation
"""

import pytest
from src.training.leakage_safe_evaluation import LeakageSafeEvaluator


def test_leakage_safe_evaluator_guarantees_zero_domain_overlap():
    evaluator = LeakageSafeEvaluator(features_csv="data/processed/features.csv")
    audit = evaluator.run_comparative_audit()

    assert audit["total_samples"] > 0
    assert audit["unique_domains"] > 100
    # Crucial guarantee: Zero overlap between training domains and testing domains!
    assert audit["domain_leakage_overlap"] == 0

    assert len(audit["naive_random_results"]) == 4
    assert len(audit["leakage_safe_results"]) == 4

    for res in audit["leakage_safe_results"]:
        assert 0.85 <= res["accuracy"] <= 1.0
        assert 0.85 <= res["f1_score"] <= 1.0
        assert 0.85 <= res["roc_auc"] <= 1.0
