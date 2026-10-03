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
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api.schemas import (
    PredictRequest, PredictResponse, HistoryResponse,
    HistoryRecord, StatsResponse, HealthResponse,
    ModelVersionsResponse, ModelSwitchRequest, ModelSwitchResponse, ModelVersionItem
)
from src.prediction.predict import ProductionPredictor
from database.connection import get_db
from database.repository import PredictionRepository

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
        model_version=predictor.model_version,
        uptime_seconds=round(uptime, 2)
    )


@router.post("/predict", response_model=PredictResponse, status_code=status.HTTP_200_OK, tags=["Inference"])
async def predict_url(
    payload: PredictRequest,
    include_explanation: bool = True,
    db: Session = Depends(get_db)
):
    """
    Analyzes an incoming URL:
    - Performs strict structural input sanitization
    - Extracts 22 RFC/lexical/entropy features
    - Executes calibrated tree ensemble classification
    - Attributes risk signals via SHAP TreeExplainer
    - Archives record in PostgreSQL / Database for audit telemetry
    """
    try:
        predictor = get_predictor()
        result = predictor.predict(payload.url, include_explanation=include_explanation)

        # 1. Store in Database
        try:
            db_record = PredictionRepository.create_record(
                db=db,
                url=result["url"],
                prediction=result["prediction"],
                probability=result["probability"],
                risk_level=result["risk_level"],
                model_version=result["metadata"]["model_version"]
            )
            record_id = str(db_record.id)
            timestamp_iso = db_record.created_at.isoformat() if db_record.created_at else datetime.now(timezone.utc).isoformat()
        except Exception as db_err:
            record_id = str(uuid.uuid4())
            timestamp_iso = datetime.now(timezone.utc).isoformat()

        # 2. Maintain fast in-memory cache
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
async def get_history(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves chronological log of scanned URLs and risk assessments from PostgreSQL / DB."""
    try:
        db_records = PredictionRepository.get_history(db, limit=limit)
        if db_records:
            formatted = [
                HistoryRecord(
                    id=str(r.id),
                    url=r.url,
                    prediction=r.prediction,
                    probability=r.probability,
                    risk_level=r.risk_level,
                    action="ALLOW" if r.risk_level == "LOW" else ("CAUTION" if r.risk_level == "MEDIUM" else "BLOCK"),
                    created_at=r.created_at.isoformat() if r.created_at else "",
                    model_version=r.model_version
                )
                for r in db_records
            ]
            return HistoryResponse(
                total_records=len(db_records),
                records=formatted
            )
    except Exception:
        pass

    # Fallback to in-memory records
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
async def get_statistics(db: Session = Depends(get_db)):
    """Aggregates system-wide telemetry, threat ratios, and operational latencies."""
    try:
        stats = PredictionRepository.get_stats(db)
        if stats["total_scans"] > 0:
            return StatsResponse(**stats)
    except Exception:
        pass

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


@router.get("/model/versions", response_model=ModelVersionsResponse, tags=["Model Governance"])
async def get_model_versions():
    """Returns all available model versions (v1, v2, v3), active status, and evaluation metrics."""
    predictor = get_predictor()
    manifest = predictor.manager.manifest
    active_v = manifest.get("active_version", predictor.model_version)
    prev_v = manifest.get("previous_version")

    version_items = []
    for v_id, meta in manifest.get("versions", {}).items():
        version_items.append(ModelVersionItem(
            version=meta["version"],
            model_name=meta["model_name"],
            architecture=meta.get("architecture", "TreeEnsemble"),
            feature_count=meta.get("feature_count", 22),
            feature_names=meta.get("feature_names", []),
            description=meta.get("description", ""),
            is_active=(meta["version"] == active_v),
            created_at=meta.get("created_at", datetime.now(timezone.utc).isoformat()),
            metrics=meta.get("metrics", {})
        ))

    return ModelVersionsResponse(
        active_version=active_v,
        previous_version=prev_v,
        versions=version_items
    )


@router.post("/model/switch", response_model=ModelSwitchResponse, tags=["Model Governance"])
async def switch_model_version(payload: ModelSwitchRequest):
    """
    Dynamically activates a specific model version ('v1', 'v2', 'v3').
    Enables live model promotion, validation, and zero-downtime hot-swapping.
    """
    predictor = get_predictor()
    try:
        info = predictor.switch_version(payload.version)
        return ModelSwitchResponse(
            status="success",
            active_version=info["version"],
            model_name=info["model_name"],
            feature_count=info.get("feature_count", 22),
            message=f"Production model successfully hot-swapped to {info['version']} ({info['model_name']})."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to switch model version: {str(e)}"
        )


@router.post("/model/rollback", response_model=ModelSwitchResponse, tags=["Model Governance"])
async def rollback_model_version():
    """
    Rolls back the active model to the predecessor version in case of drift, latency anomalies, or regressions.
    Sequence: v3 -> v2 -> v1.
    """
    predictor = get_predictor()
    try:
        new_v = predictor.rollback()
        info = predictor.manager.get_version_info(new_v)
        return ModelSwitchResponse(
            status="success",
            active_version=new_v,
            model_name=info["model_name"],
            feature_count=info.get("feature_count", 22),
            message=f"Production model successfully rolled back to {new_v} ({info['model_name']})."
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to rollback model version: {str(e)}"
        )
