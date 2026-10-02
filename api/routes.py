"""
Phishing Detection & Risk Intelligence Platform
Phase 15 & 16: API Route Handlers

Endpoints:
- GET  /health   : Health verification, model readiness, uptime
- POST /predict  : URL risk scoring, feature analysis, and SHAP explanation
- GET  /history  : Historical log of executed URL inspections
- GET  /stats    : Real-time telemetry, threat distribution, and latency statistics
"""

import uuid
import time
from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, status

from api.schemas import (
    PredictRequest, PredictResponse, HistoryResponse,
    HistoryRecord, StatsResponse, HealthResponse
)
from src.prediction.predict import ProductionPredictor

router = APIRouter()

# Shared runtime state
START_TIME = time.time()
_predictor: ProductionPredictor = None
_scan_history: List[Dict[str, Any]] = []


def get_predictor() -> ProductionPredictor:
    global _predictor
    if _predictor is None:
        _predictor = ProductionPredictor(enable_shap=True)
    return _predictor


@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Verifies service readiness and model availability."""
    predictor = get_predictor()
    uptime = time.time() - START_TIME
    return HealthResponse(
        status="healthy",
        service="Phishing Detection & Risk Intelligence Engine",
        version="1.0.0",
        model_loaded=predictor.model is not None,
        model_name=predictor.model_name,
        uptime_seconds=round(uptime, 2)
    )


@router.post("/predict", response_model=PredictResponse, status_code=status.HTTP_200_OK, tags=["Inference"])
async def predict_url(payload: PredictRequest, include_explanation: bool = True):
    """
    Analyzes an incoming URL:
    - Performs strict structural input sanitization
    - Extracts 22 RFC/lexical/entropy features
    - Executes calibrated tree ensemble classification
    - Attributes risk signals via SHAP TreeExplainer
    - Archives record for audit telemetry
    """
    try:
        predictor = get_predictor()
        result = predictor.predict(payload.url, include_explanation=include_explanation)

        # Record in history store
        record_id = str(uuid.uuid4())
        timestamp_iso = datetime.now(timezone.utc).isoformat()

        history_entry = {
            "id": record_id,
            "url": result["url"],
            "prediction": result["prediction"],
            "probability": result["probability"],
            "risk_level": result["risk_level"],
            "action": result["action"],
            "created_at": timestamp_iso,
            "model_version": result["metadata"]["model_version"],
            "latency_ms": result["metadata"]["total_latency_ms"]
        }
        _scan_history.insert(0, history_entry)
        if len(_scan_history) > 1000:
            _scan_history.pop()

        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference processing failed: {str(e)}"
        )


@router.get("/history", response_model=HistoryResponse, tags=["History"])
async def get_history(limit: int = Query(default=50, ge=1, le=200)):
    """Retrieves chronological log of scanned URLs and risk assessments."""
    records = _scan_history[:limit]
    formatted = [
        HistoryRecord(
            id=r["id"],
            url=r["url"],
            prediction=r["prediction"],
            probability=r["probability"],
            risk_level=r["risk_level"],
            action=r["action"],
            created_at=r["created_at"],
            model_version=r["model_version"]
        )
        for r in records
    ]
    return HistoryResponse(
        total_records=len(_scan_history),
        records=formatted
    )


@router.get("/stats", response_model=StatsResponse, tags=["Analytics"])
async def get_statistics():
    """Aggregates system-wide telemetry, threat ratios, and operational latencies."""
    total = len(_scan_history)
    if total == 0:
        return StatsResponse(
            total_scans=0,
            phishing_detected=0,
            legitimate_detected=0,
            phishing_rate_pct=0.0,
            avg_latency_ms=0.0,
            risk_distribution={"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        )

    phish_count = sum(1 for r in _scan_history if r["prediction"] == "phishing")
    legit_count = total - phish_count
    phish_pct = round((phish_count / total) * 100.0, 2)
    avg_latency = round(sum(r.get("latency_ms", 0.0) for r in _scan_history) / total, 2)

    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for r in _scan_history:
        level = r.get("risk_level", "LOW")
        risk_counts[level] = risk_counts.get(level, 0) + 1

    return StatsResponse(
        total_scans=total,
        phishing_detected=phish_count,
        legitimate_detected=legit_count,
        phishing_rate_pct=phish_pct,
        avg_latency_ms=avg_latency,
        risk_distribution=risk_counts
    )
