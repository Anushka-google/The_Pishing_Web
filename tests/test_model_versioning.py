"""
Phishing Detection & Risk Intelligence Platform
Unit and Integration Tests for Phase 23: Model Versioning & Rollback Registry
"""

import os
import json
import pytest
from fastapi.testclient import TestClient
import joblib

from api.main import app
from src.models.version_manager import ModelVersionManager
from src.prediction.predict import ProductionPredictor
from src.features.extractor import FeatureExtractor
from database.connection import get_db, Base, engine
from database.repository import PredictionRepository


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(scope="module")
def version_manager():
    return ModelVersionManager()


def test_version_manifest_integrity(version_manager):
    """Verifies that version manifest contains v1, v2, and v3 with correct architectures and feature counts."""
    manifest = version_manager.manifest
    assert "active_version" in manifest
    assert "versions" in manifest
    versions = manifest["versions"]

    # Verify v1, v2, v3 exist
    assert "v1" in versions
    assert "v2" in versions
    assert "v3" in versions

    # v1: Random Forest (22 features)
    assert versions["v1"]["model_name"] == "Random Forest"
    assert versions["v1"]["feature_count"] == 22
    assert len(versions["v1"]["feature_names"]) == 22

    # v2: XGBoost (22 features)
    assert versions["v2"]["model_name"] == "XGBoost"
    assert versions["v2"]["feature_count"] == 22
    assert len(versions["v2"]["feature_names"]) == 22

    # v3: XGBoost + Improved Features (28 features)
    assert "Improved" in versions["v3"]["model_name"]
    assert versions["v3"]["feature_count"] == 28
    assert len(versions["v3"]["feature_names"]) == 28


def test_version_artifacts_exist_and_loadable(version_manager):
    """Verifies that serialized .joblib files for all 3 versions exist and have valid structure."""
    for v_id, meta in version_manager.manifest["versions"].items():
        artifact_path = meta["artifact_path"]
        assert os.path.exists(artifact_path), f"Artifact missing for version {v_id} at {artifact_path}"

        pkg = joblib.load(artifact_path)
        assert pkg["model_version"] == v_id
        assert "model" in pkg
        assert "model_name" in pkg
        assert "feature_names" in pkg
        assert "thresholds" in pkg
        assert "metrics" in pkg
        assert len(pkg["feature_names"]) == meta["feature_count"]


def test_production_predictor_version_binding():
    """Verifies that ProductionPredictor binds accurately to specified versions and tags predictions."""
    # Test v1
    p_v1 = ProductionPredictor(version="v1")
    assert p_v1.model_version == "v1"
    assert p_v1.model_name == "Random Forest"
    assert len(p_v1.feature_names) == 22
    res_v1 = p_v1.predict("https://accounts.google.com/signin")
    assert res_v1["metadata"]["model_version"] == "v1"
    assert 0.0 <= res_v1["probability"] <= 1.0

    # Test v2
    p_v2 = ProductionPredictor(version="v2")
    assert p_v2.model_version == "v2"
    assert p_v2.model_name == "XGBoost"
    assert len(p_v2.feature_names) == 22
    res_v2 = p_v2.predict("https://accounts.google.com/signin")
    assert res_v2["metadata"]["model_version"] == "v2"
    assert 0.0 <= res_v2["probability"] <= 1.0

    # Test v3 (Improved Features)
    p_v3 = ProductionPredictor(version="v3")
    assert p_v3.model_version == "v3"
    assert "Improved" in p_v3.model_name
    assert len(p_v3.feature_names) == 28
    res_v3 = p_v3.predict("https://login.paypal.com.verify-security.xyz/session")
    assert res_v3["metadata"]["model_version"] == "v3"
    assert 0.0 <= res_v3["probability"] <= 1.0


def test_live_hot_swapping_and_rollback():
    """Verifies in-memory live version switching and sequential rollback."""
    predictor = ProductionPredictor()

    # 1. Hot-swap to v1
    info1 = predictor.switch_version("v1")
    assert predictor.model_version == "v1"
    assert info1["version"] == "v1"
    r1 = predictor.predict("https://wikipedia.org")
    assert r1["metadata"]["model_version"] == "v1"

    # 2. Hot-swap to v3
    info3 = predictor.switch_version("v3")
    assert predictor.model_version == "v3"
    assert info3["version"] == "v3"
    r3 = predictor.predict("https://wikipedia.org")
    assert r3["metadata"]["model_version"] == "v3"

    # 3. Rollback (v3 -> v2)
    rb_v2 = predictor.rollback()
    assert rb_v2 == "v2"
    assert predictor.model_version == "v2"
    r2 = predictor.predict("https://wikipedia.org")
    assert r2["metadata"]["model_version"] == "v2"

    # 4. Rollback (v2 -> v1)
    rb_v1 = predictor.rollback()
    assert rb_v1 == "v1"
    assert predictor.model_version == "v1"
    r1_post = predictor.predict("https://wikipedia.org")
    assert r1_post["metadata"]["model_version"] == "v1"

    # Restore to default champion v1
    predictor.switch_version("v1")
    assert predictor.model_version == "v1"


def test_database_persistence_with_model_version():
    """Verifies that model_version is stored and queryable in database records."""
    db_gen = get_db()
    db = next(db_gen)
    try:
        rec_v1 = PredictionRepository.create_record(
            db=db,
            url="https://test-v1-storage.org",
            prediction="legitimate",
            probability=0.04,
            risk_level="LOW",
            model_version="v1"
        )
        assert rec_v1.model_version == "v1"

        rec_v3 = PredictionRepository.create_record(
            db=db,
            url="https://test-v3-storage.xyz/login",
            prediction="phishing",
            probability=0.98,
            risk_level="HIGH",
            model_version="v3"
        )
        assert rec_v3.model_version == "v3"

        # Query history and verify model_version preserved
        history = PredictionRepository.get_history(db=db, limit=5)
        v_stored = {h.model_version for h in history}
        assert "v1" in v_stored or "v3" in v_stored
    finally:
        db.close()


def test_api_model_version_endpoints(client):
    """Verifies GET /model/versions, POST /model/switch, and POST /model/rollback endpoints."""
    # 1. GET /model/versions
    res = client.get("/model/versions")
    assert res.status_code == 200
    data = res.json()
    assert "active_version" in data
    assert "versions" in data
    assert len(data["versions"]) == 3

    # 2. POST /model/switch to v1
    switch_res = client.post("/model/switch", json={"version": "v1"})
    assert switch_res.status_code == 200
    switch_data = switch_res.json()
    assert switch_data["status"] == "success"
    assert switch_data["active_version"] == "v1"
    assert switch_data["model_name"] == "Random Forest"

    # Verify predict output reflects v1
    pred_res = client.post("/predict", json={"url": "https://accounts.google.com"})
    assert pred_res.status_code == 200
    assert pred_res.json()["metadata"]["model_version"] == "v1"

    # 3. POST /model/switch to v3
    switch_res3 = client.post("/model/switch", json={"version": "v3"})
    assert switch_res3.status_code == 200
    assert switch_res3.json()["active_version"] == "v3"
    assert switch_res3.json()["feature_count"] == 28

    pred_res3 = client.post("/predict", json={"url": "https://accounts.google.com"})
    assert pred_res3.status_code == 200
    assert pred_res3.json()["metadata"]["model_version"] == "v3"

    # 4. POST /model/rollback
    rb_res = client.post("/model/rollback")
    assert rb_res.status_code == 200
    assert rb_res.json()["active_version"] == "v2"

    # 5. Invalid version rejection
    invalid_res = client.post("/model/switch", json={"version": "v99_nonexistent"})
    assert invalid_res.status_code == 400

    # Ensure system is left on v1
    client.post("/model/switch", json={"version": "v1"})
