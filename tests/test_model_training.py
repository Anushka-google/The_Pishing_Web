"""
Unit tests for Phase 8: Model Training and Experimentation
"""

import os
import joblib
import numpy as np
import pytest
from src.training.train_baseline import BaselineTrainer
from src.training.model_experimentation import ModelExperimenter
from src.features.extractor import FeatureExtractor


def test_baseline_trainer_executes():
    trainer = BaselineTrainer(features_csv="data/processed/features.csv")
    metrics, artifact_path = trainer.train_and_evaluate()

    assert os.path.exists(artifact_path)
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert 0.0 <= metrics["roc_auc"] <= 1.0
    assert 0.0 <= metrics["pr_auc"] <= 1.0
    assert metrics["train_time_sec"] >= 0.0


def test_model_experimentation_evaluates_four_models():
    experimenter = ModelExperimenter(features_csv="data/processed/features.csv")
    results, champ, champ_path = experimenter.run_experiments()

    assert len(results) == 4
    model_names = [r["model"] for r in results]
    assert "Logistic Regression" in model_names
    assert "Decision Tree" in model_names
    assert "Random Forest" in model_names
    assert "XGBoost" in model_names

    assert os.path.exists(champ_path)
    assert champ["model"] in model_names


def test_champion_model_inference():
    champ_path = "models/champion_phishing_model.joblib"
    assert os.path.exists(champ_path)

    pkg = joblib.load(champ_path)
    model = pkg["model"]
    scaler = pkg.get("scaler")
    requires_scaling = pkg.get("requires_scaling", False)

    extractor = FeatureExtractor()
    vector = extractor.extract_features_vector("https://login.paypal.com.verify-account.xyz/auth")
    X = vector.reshape(1, -1)

    if requires_scaling and scaler is not None:
        X = scaler.transform(X)

    prob = model.predict_proba(X)[0, 1]
    pred = model.predict(X)[0]

    assert 0.0 <= prob <= 1.0
    assert pred in (0, 1)
