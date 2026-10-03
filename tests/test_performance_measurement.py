"""
Phishing Detection & Risk Intelligence Platform
Phase 25: Test Suite for Subsystem Performance Measurement & Bottleneck Profiling

Verifies:
1. Isolated timing measurement for each subsystem:
   - Feature extraction time
   - Model inference time
   - Database latency
   - API response time
2. Bottleneck identification algorithm
3. Statistical distribution calculations (mean, p50, p90, p95, p99)
4. API response metadata and performance telemetry headers
5. GET /performance endpoint schema and analytics
6. Database storage of latency telemetry
7. Structured JSON log emission with subsystem timings
"""

import io
import json
import logging
import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.routes import get_predictor
from api.logging_config import StructuredJSONFormatter
from src.evaluation.performance_profiler import (
    identify_bottleneck,
    compute_distribution_stats,
    SystemPerformanceProfiler
)
from database.models import Base
from database.repository import PredictionRepository
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture(autouse=True)
def ensure_default_model():
    """Ensure active model is reset to default v1 before and after each test."""
    predictor = get_predictor()
    try:
        predictor.switch_version("v1")
    except Exception:
        pass
    yield
    try:
        predictor.switch_version("v1")
    except Exception:
        pass


def test_bottleneck_identification_logic():
    """Verifies that identify_bottleneck correctly identifies the largest latency contributor."""
    # Scenario A: Feature extraction is slowest
    res_feat = identify_bottleneck(
        feature_extraction_ms=45.0,
        model_inference_ms=10.0,
        database_latency_ms=2.0,
        api_response_time_ms=60.0
    )
    assert res_feat["bottleneck"] == "FEATURE_EXTRACTION"
    assert res_feat["bottleneck_share_pct"] == 75.0

    # Scenario B: Model inference is slowest
    res_inf = identify_bottleneck(
        feature_extraction_ms=1.5,
        model_inference_ms=35.0,
        database_latency_ms=1.2,
        api_response_time_ms=40.0
    )
    assert res_inf["bottleneck"] == "MODEL_INFERENCE"
    assert res_inf["bottleneck_share_pct"] == 87.5

    # Scenario C: Database is slowest
    res_db = identify_bottleneck(
        feature_extraction_ms=1.0,
        model_inference_ms=2.0,
        database_latency_ms=50.0,
        api_response_time_ms=55.0
    )
    assert res_db["bottleneck"] == "DATABASE_LATENCY"
    assert res_db["bottleneck_share_pct"] == round((50.0 / 55.0) * 100.0, 1)

    # Scenario D: Network / pipeline overhead is slowest
    res_over = identify_bottleneck(
        feature_extraction_ms=1.0,
        model_inference_ms=2.0,
        database_latency_ms=1.0,
        api_response_time_ms=100.0
    )
    assert res_over["bottleneck"] == "PIPELINE_OVERHEAD"
    assert res_over["bottleneck_share_pct"] == 96.0


def test_distribution_statistics_calculation():
    """Verifies that compute_distribution_stats computes percentiles and mean accurately."""
    latencies = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    stats = compute_distribution_stats(latencies)

    assert stats["mean_ms"] == 55.0
    assert stats["median_p50_ms"] == 55.0
    assert stats["min_ms"] == 10.0
    assert stats["max_ms"] == 100.0
    assert stats["p90_ms"] == 91.0 or stats["p90_ms"] == 90.0 or (90.0 <= stats["p90_ms"] <= 95.0)
    assert stats["p95_ms"] > stats["p90_ms"]


def test_system_performance_profiler_execution():
    """Verifies that SystemPerformanceProfiler produces valid empirical benchmark reports."""
    profiler = SystemPerformanceProfiler()
    report = profiler.benchmark_subsystems(iterations=12, warmup_runs=2)

    assert "subsystems" in report
    sub = report["subsystems"]
    for key in ["feature_extraction", "model_inference", "database_latency", "api_response_time"]:
        assert key in sub
        assert sub[key]["mean_ms"] >= 0.0
        assert sub[key]["median_p50_ms"] >= 0.0
        assert sub[key]["p95_ms"] >= 0.0

    assert "bottleneck_analysis" in report
    b = report["bottleneck_analysis"]
    assert b["primary_bottleneck"] in ["FEATURE_EXTRACTION", "MODEL_INFERENCE", "DATABASE_LATENCY", "PIPELINE_OVERHEAD"]
    assert 0.0 < b["primary_bottleneck_share_pct"] <= 100.0


def test_api_predict_returns_subsystem_latencies_and_headers():
    """Verifies POST /predict measures and returns all 4 performance dimensions in body and headers."""
    client = TestClient(app)
    response = client.post(
        "/api/v1/predict",
        json={"url": "https://www.wikipedia.org/wiki/Phishing"}
    )
    assert response.status_code == 200

    data = response.json()
    meta = data["metadata"]

    # 1. Body contains separate subsystem metrics
    assert "feature_extraction_time_ms" in meta
    assert meta["feature_extraction_time_ms"] > 0
    assert "model_inference_time_ms" in meta
    assert meta["model_inference_time_ms"] > 0
    assert "database_latency_ms" in meta
    assert meta["database_latency_ms"] >= 0
    assert "api_response_time_ms" in meta
    assert meta["api_response_time_ms"] > 0
    assert "bottleneck" in meta
    assert meta["bottleneck"] in ["FEATURE_EXTRACTION", "MODEL_INFERENCE", "DATABASE_LATENCY", "PIPELINE_OVERHEAD"]

    # 2. Response headers expose subsystem metrics
    headers = response.headers
    assert "X-Feature-Extraction-Time-MS" in headers
    assert "X-Model-Inference-Time-MS" in headers
    assert "X-Database-Latency-MS" in headers
    assert "X-Total-Response-Time-MS" in headers
    assert "X-Identified-Bottleneck" in headers
    assert headers["X-Identified-Bottleneck"] == meta["bottleneck"]


def test_api_performance_endpoint():
    """Verifies GET /performance returns benchmark statistics and live telemetry."""
    client = TestClient(app)
    response = client.get("/api/v1/performance")
    assert response.status_code == 200

    payload = response.json()
    assert payload["status"] == "success"
    assert "feature_extraction" in payload
    assert "model_inference" in payload
    assert "database_latency" in payload
    assert "api_response_time" in payload
    assert "primary_bottleneck" in payload
    assert "sla_compliance" in payload

    assert payload["feature_extraction"]["mean_ms"] >= 0
    assert payload["model_inference"]["mean_ms"] >= 0
    assert payload["database_latency"]["mean_ms"] >= 0
    assert payload["api_response_time"]["mean_ms"] >= 0


def test_database_latency_telemetry_persistence():
    """Verifies that database layer persists subsystem latency and computes performance telemetry."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # Create records with performance metrics
        PredictionRepository.create_record(
            db=db,
            url="https://sample-site-1.com",
            prediction="legitimate",
            probability=0.01,
            risk_level="LOW",
            model_version="v1",
            feature_extraction_ms=0.35,
            model_inference_ms=31.2,
            db_latency_ms=1.1,
            api_response_time_ms=33.5,
            bottleneck="MODEL_INFERENCE"
        )
        PredictionRepository.create_record(
            db=db,
            url="https://sample-site-2.com",
            prediction="phishing",
            probability=0.95,
            risk_level="HIGH",
            model_version="v1",
            feature_extraction_ms=0.42,
            model_inference_ms=30.8,
            db_latency_ms=1.3,
            api_response_time_ms=33.9,
            bottleneck="MODEL_INFERENCE"
        )

        history = PredictionRepository.get_history(db, limit=10)
        assert len(history) == 2
        assert history[0].feature_extraction_ms is not None
        assert history[0].bottleneck == "MODEL_INFERENCE"

        # Telemetry computation
        telemetry = PredictionRepository.get_performance_telemetry(db)
        assert telemetry["total_samples"] == 2
        assert telemetry["avg_feature_extraction_ms"] > 0
        assert telemetry["avg_model_inference_ms"] > 0
        assert telemetry["avg_db_latency_ms"] > 0
        assert telemetry["primary_bottleneck"] == "MODEL_INFERENCE"
    finally:
        db.close()


def test_structured_logging_includes_phase_25_performance_fields():
    """Verifies that structured JSON logger captures Phase 25 performance telemetry."""
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setFormatter(StructuredJSONFormatter())

    test_logger = logging.getLogger("phishing_intelligence")
    test_logger.addHandler(handler)

    try:
        client = TestClient(app)
        response = client.post(
            "/api/v1/predict",
            json={"url": "https://www.python.org"}
        )
        assert response.status_code == 200

        handler.flush()
        logs = log_capture.getvalue().strip().split("\n")

        predict_logs = []
        for line in logs:
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
                if parsed.get("endpoint") == "POST /predict":
                    predict_logs.append(parsed)
            except Exception:
                pass

        assert len(predict_logs) > 0
        p_log = predict_logs[0]

        # Verify Phase 25 fields logged in JSON
        assert "feature_extraction_time_ms" in p_log
        assert "database_latency_ms" in p_log
        assert "bottleneck" in p_log
    finally:
        test_logger.removeHandler(handler)
