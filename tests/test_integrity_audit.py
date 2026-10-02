"""
Unit tests for 5-Rule Evaluation Integrity and Zero-Leakage Audit
"""

import pytest
from src.evaluation.audit_leakage_and_integrity import EvaluationIntegrityAuditor


def test_evaluation_integrity_audit_passes_all_rules():
    auditor = EvaluationIntegrityAuditor()
    audit = auditor.run_full_integrity_audit()

    # Rule 1 & 2: Zero exact or near duplicates crossing
    assert audit["rule_1_exact_duplicates_across_datasets"] == 0
    assert audit["rule_2_near_duplicates_across_datasets"] == 0

    # Rule 3: Zero domain overlap between train and test holdout
    assert audit["rule_3_domain_overlap_count"] == 0

    # Rule 4: Model trained ONLY on dev generalizes to unseen holdout
    holdout = audit["rule_4_strict_unseen_holdout_evaluation"]
    assert holdout["total_real_world_urls"] > 9000
    assert 0.85 <= holdout["accuracy"] <= 1.0
    assert 0.80 <= holdout["recall"] <= 1.0
    assert 0.85 <= holdout["f1_score"] <= 1.0
    assert 0.90 <= holdout["roc_auc"] <= 1.0

    # Rule 5: Scaler fit strictly on train
    assert audit["rule_5_scaler_fit_strictly_on_train"] is True
    assert "PASSED" in audit["audit_verdict"]
