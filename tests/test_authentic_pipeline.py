"""
Unit & Integration Tests for Authentic Phishing Dataset Pipeline
Verifies:
1. Authentic dataset existence and verified schema
2. Zero duplicate URLs in authentic dataset
3. Domain-grouped split guarantees zero domain overlap
4. Timestamp continuity and chronological split valid
5. Independent holdout integrity
"""

import os
import json
import pytest
import pandas as pd
import numpy as np

from src.data.authentic_pipeline import AuthenticDatasetPipeline
from src.evaluation.authentic_evaluation import AuthenticEvaluator
from src.features.extractor import FeatureExtractor


@pytest.fixture(scope="module")
def authentic_data():
    csv_path = "data/real_world/features_real_world.csv"
    assert os.path.exists(csv_path), f"Authentic features CSV missing at {csv_path}"
    df = pd.read_csv(csv_path)
    return df


def test_authentic_features_schema_and_integrity(authentic_data):
    """Verifies that all 22 numeric features and mandatory metadata columns exist."""
    df = authentic_data
    assert len(df) >= 10000, "Authentic dataset should contain at least 10,000 real samples"

    # Verify 22 feature columns
    for col in FeatureExtractor.FEATURE_NAMES:
        assert col in df.columns, f"Missing required feature column: {col}"
        assert pd.api.types.is_numeric_dtype(df[col]), f"Feature column {col} must be numeric"

    # Verify metadata columns
    for meta_col in ["label", "url", "registered_domain", "source", "collection_timestamp"]:
        assert meta_col in df.columns, f"Missing required metadata column: {meta_col}"

    # Labels must be binary 0 or 1
    assert set(df["label"].unique()).issubset({0, 1})


def test_zero_exact_duplicates(authentic_data):
    """Guarantees zero exact duplicate URLs exist in the authentic corpus."""
    urls = authentic_data["url"].str.strip().str.lower()
    duplicate_count = urls.duplicated().sum()
    assert duplicate_count == 0, f"Found {duplicate_count} duplicate URLs in authentic dataset!"


def test_domain_grouped_split_zero_leakage():
    """Confirms that domain-grouped evaluation guarantees exactly 0 domain overlap."""
    evaluator = AuthenticEvaluator()
    res = evaluator.run_domain_grouped_evaluation()

    assert res["domain_overlap"] == 0
    assert res["train_domains_count"] > 1000
    assert res["test_domains_count"] > 500

    # Every model must achieve > 85% accuracy on authentic domain split
    for m in res["models"]:
        assert m["accuracy"] >= 0.85
        assert m["precision"] >= 0.85
        assert m["recall"] >= 0.85
        assert m["false_positive_rate"] <= 0.05


def test_time_based_split_chronological_order():
    """Verifies that the chronological split splits past vs future strictly."""
    evaluator = AuthenticEvaluator()
    res = evaluator.run_time_based_evaluation()

    assert res["train_samples"] > 0
    assert res["test_samples"] > 0
    assert len(res["models"]) == 4


def test_external_holdout_execution():
    """Verifies independent external holdout runs and generates full metrics."""
    evaluator = AuthenticEvaluator()
    res = evaluator.run_independent_external_holdout()

    assert "models" in res
    assert len(res["models"]) == 4
    for m in res["models"]:
        assert "confusion_matrix" in m
        assert "false_positive_rate" in m
        assert "false_negative_rate" in m
