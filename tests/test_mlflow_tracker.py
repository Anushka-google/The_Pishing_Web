"""
Phishing Detection & Risk Intelligence Platform
Unit and Integration Tests for Phase 22: MLflow Experiment Tracking & Model Registry
"""

import os
import json
import pytest
import pandas as pd
import numpy as np
import joblib

os.environ["MLFLOW_DISABLE_AGENT_HINT"] = "1"
import mlflow
from mlflow.tracking import MlflowClient

from src.training.mlflow_tracker import MLflowExperimentTracker
from src.features.extractor import FeatureExtractor


@pytest.fixture(scope="module")
def tracker_fixture(tmp_path_factory):
    temp_dir = tmp_path_factory.mktemp("mlflow_test_dir")
    test_db_path = str(temp_dir / "test_mlflow.db")
    test_models_dir = str(temp_dir / "models")
    tracking_uri = f"sqlite:///{test_db_path.replace(os.sep, '/')}"

    tracker = MLflowExperimentTracker(
        tracking_uri=tracking_uri,
        experiment_name="Test_Phishing_Detection",
        features_csv="data/processed/features.csv",
        dataset_version="v1.2.0-test",
        models_dir=test_models_dir,
        random_state=42
    )
    return tracker


def test_tracker_initialization(tracker_fixture):
    """Verifies tracker initialization, experiment existence, and metadata calculation."""
    tracker = tracker_fixture
    assert tracker.experiment_name == "Test_Phishing_Detection"
    assert tracker.dataset_version == "v1.2.0-test"
    assert os.path.exists(tracker.models_dir)

    client = MlflowClient(tracking_uri=tracker.tracking_uri)
    exp = client.get_experiment_by_name("Test_Phishing_Detection")
    assert exp is not None
    assert exp.name == "Test_Phishing_Detection"


def test_dataset_metadata(tracker_fixture):
    """Verifies dataset SHA-256 fingerprinting and distribution statistics."""
    meta = tracker_fixture.dataset_metadata
    assert "version" in meta
    assert meta["version"] == "v1.2.0-test"
    assert len(meta["sha256"]) == 64  # Valid SHA-256 hex string
    assert meta["total_samples"] > 0
    assert meta["num_features"] == len(FeatureExtractor.FEATURE_NAMES)
    assert 0.0 <= meta["phishing_ratio"] <= 1.0


def test_load_and_split_data(tracker_fixture):
    """Verifies train/test splitting under stratified holdout."""
    tracker = tracker_fixture
    X_train, X_test, y_train, y_test, scaler = tracker.load_and_split_data(
        test_size=0.20,
        split_strategy="stratified_holdout"
    )

    assert len(X_train) > len(X_test)
    assert X_train.shape[1] == len(FeatureExtractor.FEATURE_NAMES)
    assert X_test.shape[1] == len(FeatureExtractor.FEATURE_NAMES)
    assert len(y_train) == len(X_train)
    assert len(y_test) == len(X_test)
    assert set(np.unique(y_train)).issubset({0, 1})


def test_candidate_models_specification(tracker_fixture):
    """Verifies that all candidate models including tuned XGBoost (300 est, depth 6, lr 0.05) are specified."""
    candidates = tracker_fixture.get_candidate_models()
    names = [c["run_name"] for c in candidates]

    assert "XGBoost_Tuned" in names
    assert "XGBoost_Baseline" in names
    assert "Random_Forest" in names
    assert "Decision_Tree" in names
    assert "Logistic_Regression" in names

    # Verify XGBoost Tuned parameters from roadmap
    xgb_tuned = next(c for c in candidates if c["run_name"] == "XGBoost_Tuned")
    assert xgb_tuned["params"]["n_estimators"] == 300
    assert xgb_tuned["params"]["max_depth"] == 6
    assert xgb_tuned["params"]["learning_rate"] == 0.05
    assert xgb_tuned["params"]["subsample"] == 0.8
    assert xgb_tuned["params"]["colsample_bytree"] == 0.8


def test_train_and_log_single_run(tracker_fixture):
    """Verifies that train_and_log_run records parameters, metrics, tags, and artifacts."""
    tracker = tracker_fixture
    X_train, X_test, y_train, y_test, scaler = tracker.load_and_split_data(test_size=0.20)

    # Use Decision Tree for fast testing
    candidates = tracker.get_candidate_models()
    dt_candidate = next(c for c in candidates if c["run_name"] == "Decision_Tree")

    rec = tracker.train_and_log_run(
        candidate=dt_candidate,
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        scaler=scaler,
        split_strategy="stratified_holdout"
    )

    assert rec["run_name"] == "Decision_Tree"
    assert "metrics" in rec
    m = rec["metrics"]
    assert 0.0 <= m["precision"] <= 1.0
    assert 0.0 <= m["recall"] <= 1.0
    assert 0.0 <= m["f1_score"] <= 1.0
    assert 0.0 <= m["roc_auc"] <= 1.0
    assert 0.0 <= m["pr_auc"] <= 1.0
    assert 0.0 <= m["accuracy"] <= 1.0
    assert m["training_time_seconds"] >= 0.0
    assert m["latency_ms_per_url"] >= 0.0

    # Verify run in MLflow tracking database
    client = MlflowClient(tracking_uri=tracker.tracking_uri)
    run_data = client.get_run(rec["run_id"])
    assert run_data.info.run_id == rec["run_id"]
    assert run_data.data.metrics["f1_score"] == pytest.approx(m["f1_score"], rel=1e-3)
    assert run_data.data.tags["dataset_version"] == "v1.2.0-test"


def test_production_bundle_compatibility(tracker_fixture):
    """Verifies that the generated champion joblib bundle contains all necessary keys for production predictor."""
    champion_path = "models/champion_phishing_model.joblib"
    assert os.path.exists(champion_path), "Champion model artifact must exist after Phase 22 execution"

    pkg = joblib.load(champion_path)
    assert "model" in pkg
    assert "model_name" in pkg
    assert "feature_names" in pkg
    assert "thresholds" in pkg
    assert "mlflow_run_id" in pkg
    assert pkg["feature_names"] == FeatureExtractor.FEATURE_NAMES
    assert "t1_low" in pkg["thresholds"]
    assert "t2_high" in pkg["thresholds"]


def test_exported_summary_and_documentation():
    """Verifies that summary JSON and Phase 22 markdown docs were written properly."""
    summary_path = "data/processed/mlflow_experiment_summary.json"
    doc_path = "docs/phase_22_mlflow_tracking.md"

    assert os.path.exists(summary_path)
    with open(summary_path, "r", encoding="utf-8") as f:
        summary = json.load(f)
        assert "experiment_name" in summary
        assert "champion_model" in summary
        assert "runs" in summary
        assert len(summary["runs"]) >= 5

    assert os.path.exists(doc_path)
    with open(doc_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "Phase 22: MLflow Experiment Tracking" in content
        assert "XGBoost_Tuned" in content
        assert "Random_Forest" in content
        assert "F1-Score" in content
