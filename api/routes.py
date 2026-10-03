"""
Phishing Detection & Risk Intelligence Platform
Phase 15 & 16: API Route Handlers

Endpoints:
- GET  /health   : Health verification, model readiness, uptime
- POST /predict  : URL risk scoring, feature analysis, and SHAP explanation
- GET  /history  : Historical log of executed URL inspections
- GET  /stats    : Real-time telemetry, threat distribution, and latency statistics
"""

import os
import json
import uuid
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api.schemas import (
    PredictRequest, PredictResponse, HistoryResponse,
    HistoryRecord, StatsResponse, HealthResponse,
    ModelVersionsResponse, ModelSwitchRequest, ModelSwitchResponse, ModelVersionItem,
    PerformanceResponse, PerformanceDistribution,
    DriftMonitoringResponse, RetrainingJustificationRequest, RetrainingJustificationResponse,
    EnhancedAnalyzeRequest, EnhancedAnalyzeResponse, EmailAnalyzeRequest, EmailAnalyzeResponse
)
from src.prediction.predict import ProductionPredictor
from src.evaluation.performance_profiler import identify_bottleneck, SystemPerformanceProfiler
from src.monitoring.drift_detector import ProductionMonitor, DataDriftDetector
from src.extensions.reputation import DomainReputationEngine
from src.extensions.dns_features import DNSFeatureExtractor
from src.extensions.whois_features import WHOISFeatureExtractor
from src.extensions.email_analyzer import EmailRiskAnalyzer
from database.connection import get_db
from database.repository import PredictionRepository
from api.logging_config import logger, sanitize_url

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


_monitor: Optional[ProductionMonitor] = None


def get_monitor() -> ProductionMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ProductionMonitor()
    return _monitor


_reputation_engine: Optional[DomainReputationEngine] = None
_dns_extractor: Optional[DNSFeatureExtractor] = None
_whois_extractor: Optional[WHOISFeatureExtractor] = None
_email_analyzer: Optional[EmailRiskAnalyzer] = None


def get_reputation_engine() -> DomainReputationEngine:
    global _reputation_engine
    if _reputation_engine is None:
        _reputation_engine = DomainReputationEngine()
    return _reputation_engine


def get_dns_extractor() -> DNSFeatureExtractor:
    global _dns_extractor
    if _dns_extractor is None:
        _dns_extractor = DNSFeatureExtractor()
    return _dns_extractor


def get_whois_extractor() -> WHOISFeatureExtractor:
    global _whois_extractor
    if _whois_extractor is None:
        _whois_extractor = WHOISFeatureExtractor()
    return _whois_extractor


def get_email_analyzer() -> EmailRiskAnalyzer:
    global _email_analyzer
    if _email_analyzer is None:
        _email_analyzer = EmailRiskAnalyzer(
            predictor=get_predictor(),
            reputation_engine=get_reputation_engine()
        )
    return _email_analyzer



@router.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check(request: Request):
    """Verifies service readiness and model availability."""
    predictor = get_predictor()
    uptime = time.time() - START_TIME
    request.state.model_version = predictor.model_version
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
    request: Request,
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
    t_req_start = time.perf_counter()
    try:
        predictor = get_predictor()
        result = predictor.predict(payload.url, include_explanation=include_explanation)

        # Phase 25: Extract individual subsystem metrics
        feat_latency = result["metadata"]["feature_extraction_time_ms"]
        inf_latency = result["metadata"]["model_inference_time_ms"]
        model_ver = result["metadata"]["model_version"]

        # 1. Store in Database & measure exact Database latency
        t_db_start = time.perf_counter()
        db_record = None
        try:
            db_record = PredictionRepository.create_record(
                db=db,
                url=result["url"],
                prediction=result["prediction"],
                probability=result["probability"],
                risk_level=result["risk_level"],
                model_version=result["metadata"]["model_version"],
                feature_extraction_ms=feat_latency,
                model_inference_ms=inf_latency
            )
            record_id = str(db_record.id)
            timestamp_iso = db_record.created_at.isoformat() if db_record.created_at else datetime.now(timezone.utc).isoformat()
        except Exception as db_err:
            record_id = str(uuid.uuid4())
            timestamp_iso = datetime.now(timezone.utc).isoformat()
        t_db_end = time.perf_counter()
        db_latency = round((t_db_end - t_db_start) * 1000.0, 3)

        # 2. Total API response time for endpoint
        t_req_end = time.perf_counter()
        api_resp_time = round((t_req_end - t_req_start) * 1000.0, 3)

        # 3. Identify subsystem bottleneck
        b_info = identify_bottleneck(
            feature_extraction_ms=feat_latency,
            model_inference_ms=inf_latency,
            database_latency_ms=db_latency,
            api_response_time_ms=api_resp_time
        )
        bottleneck = b_info["bottleneck"]

        # Backfill DB record with finalized DB/API times and bottleneck
        if db_record is not None:
            try:
                db_record.db_latency_ms = db_latency
                db_record.api_response_time_ms = api_resp_time
                db_record.bottleneck = bottleneck
                db.commit()
            except Exception:
                pass

        # Update metadata dictionary
        result["metadata"]["database_latency_ms"] = db_latency
        result["metadata"]["api_response_time_ms"] = api_resp_time
        result["metadata"]["bottleneck"] = bottleneck
        result["metadata"]["performance_breakdown"] = b_info["components"]

        # Operational telemetry and privacy-preserving sanitization
        sanitized_url = sanitize_url(payload.url)
        pred_summary = {
            "prediction": result["prediction"],
            "risk_level": result["risk_level"],
            "probability": result["probability"]
        }

        # Propagate to request.state for StructuredLoggingMiddleware
        request.state.sanitized_url = sanitized_url
        request.state.model_version = model_ver
        request.state.feature_extraction_time = feat_latency
        request.state.prediction_latency = inf_latency
        request.state.database_latency = db_latency
        request.state.api_response_time = api_resp_time
        request.state.bottleneck = bottleneck
        request.state.prediction_result = pred_summary

        # Emit explicit structured operational log with Phase 25 metrics
        logger.info(
            f"Prediction completed: {result['prediction'].upper()} ({result['risk_level']}) | Bottleneck: {bottleneck}",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "endpoint": "POST /predict",
                "model_version": model_ver,
                "feature_extraction_time_ms": feat_latency,
                "prediction_latency": inf_latency,
                "database_latency_ms": db_latency,
                "api_response_time_ms": api_resp_time,
                "bottleneck": bottleneck,
                "prediction_result": pred_summary,
                "sanitized_url": sanitized_url
            }
        )

        # 4. Maintain fast in-memory cache
        history_entry = {
            "id": record_id,
            "url": result["url"],
            "prediction": result["prediction"],
            "probability": result["probability"],
            "risk_level": result["risk_level"],
            "action": result["action"],
            "created_at": timestamp_iso,
            "model_version": result["metadata"]["model_version"],
            "latency_ms": result["metadata"]["total_latency_ms"],
            "feature_extraction_ms": feat_latency,
            "model_inference_ms": inf_latency,
            "db_latency_ms": db_latency,
            "api_response_time_ms": api_resp_time,
            "bottleneck": bottleneck
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
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves chronological log of scanned URLs and risk assessments from PostgreSQL / DB."""
    predictor = get_predictor()
    request.state.model_version = predictor.model_version
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
                    model_version=r.model_version,
                    feature_extraction_ms=r.feature_extraction_ms,
                    model_inference_ms=r.model_inference_ms,
                    db_latency_ms=r.db_latency_ms,
                    api_response_time_ms=r.api_response_time_ms,
                    bottleneck=r.bottleneck
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
            model_version=r["model_version"],
            feature_extraction_ms=r.get("feature_extraction_ms"),
            model_inference_ms=r.get("model_inference_ms"),
            db_latency_ms=r.get("db_latency_ms"),
            api_response_time_ms=r.get("api_response_time_ms"),
            bottleneck=r.get("bottleneck")
        )
        for r in records
    ]
    return HistoryResponse(
        total_records=len(_scan_history),
        records=formatted
    )


@router.get("/stats", response_model=StatsResponse, tags=["Analytics"])
async def get_statistics(request: Request, db: Session = Depends(get_db)):
    """Aggregates system-wide telemetry, threat ratios, and operational latencies."""
    predictor = get_predictor()
    request.state.model_version = predictor.model_version
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
async def get_model_versions(request: Request):
    """Returns all available model versions (v1, v2, v3), active status, and evaluation metrics."""
    predictor = get_predictor()
    manifest = predictor.manager.manifest
    active_v = manifest.get("active_version", predictor.model_version)
    prev_v = manifest.get("previous_version")
    request.state.model_version = active_v

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
async def switch_model_version(payload: ModelSwitchRequest, request: Request):
    """
    Dynamically activates a specific model version ('v1', 'v2', 'v3').
    Enables live model promotion, validation, and zero-downtime hot-swapping.
    """
    predictor = get_predictor()
    try:
        info = predictor.switch_version(payload.version)
        request.state.model_version = info["version"]
        logger.info(
            f"Model version switched to {info['version']}",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "endpoint": "POST /model/switch",
                "model_version": info["version"]
            }
        )
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
async def rollback_model_version(request: Request):
    """
    Rolls back the active model to the predecessor version in case of drift, latency anomalies, or regressions.
    Sequence: v3 -> v2 -> v1.
    """
    predictor = get_predictor()
    try:
        new_v = predictor.rollback()
        info = predictor.manager.get_version_info(new_v)
        request.state.model_version = new_v
        logger.info(
            f"Model version rolled back to {new_v}",
            extra={
                "request_id": getattr(request.state, "request_id", None),
                "endpoint": "POST /model/rollback",
                "model_version": new_v
            }
        )
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


@router.get("/performance", response_model=PerformanceResponse, tags=["Analytics"])
async def get_performance_telemetry(request: Request, db: Session = Depends(get_db)):
    """
    Returns empirical subsystem performance benchmarks across:
    - Feature extraction time
    - Model inference time
    - Database latency
    - API response time
    Includes bottleneck analysis and live database telemetry.
    """
    predictor = get_predictor()
    request.state.model_version = predictor.model_version

    report_file = "data/processed/performance_metrics.json"
    if os.path.exists(report_file):
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            profiler = SystemPerformanceProfiler(predictor=predictor)
            data = profiler.benchmark_subsystems(iterations=50, warmup_runs=5)
    else:
        profiler = SystemPerformanceProfiler(predictor=predictor)
        data = profiler.benchmark_subsystems(iterations=50, warmup_runs=5)
        try:
            profiler.save_report(data, report_file)
        except Exception:
            pass

    # Fetch live DB performance telemetry
    db_telemetry = PredictionRepository.get_performance_telemetry(db)

    return PerformanceResponse(
        status="success",
        model_version=predictor.model_version,
        model_name=predictor.model_name,
        feature_extraction=PerformanceDistribution(**data["subsystems"]["feature_extraction"]),
        model_inference=PerformanceDistribution(**data["subsystems"]["model_inference"]),
        database_latency=PerformanceDistribution(**data["subsystems"]["database_latency"]),
        api_response_time=PerformanceDistribution(**data["subsystems"]["api_response_time"]),
        primary_bottleneck=data["bottleneck_analysis"]["primary_bottleneck"],
        primary_bottleneck_share_pct=data["bottleneck_analysis"]["primary_bottleneck_share_pct"],
        sla_compliance=data["sla_compliance"],
        live_database_telemetry=db_telemetry
    )


@router.get("/monitoring/drift", response_model=DriftMonitoringResponse, tags=["Monitoring"])
async def get_drift_monitoring_report(
    request: Request,
    scenario: Optional[str] = Query(None, description="Optional simulation scenario ('healthy', 'short_urls', 'phishing_surge', 'critical_drift')"),
    sample_limit: int = Query(250, ge=10, le=2000, description="Max recent records to evaluate"),
    db: Session = Depends(get_db)
):
    """
    Phase 27: Production Monitoring & Drift Detection.
    Monitors 6 key dimensions:
    1. URL-length distributions (PSI + KS test)
    2. Domain characteristics (subdomains, entropy, IP host ratio, TLD TVD)
    3. Prediction distributions (probability PSI + risk tiers)
    4. Phishing/legitimate ratios
    5. API latency percentiles (P50/P95/P99) and SLA compliance
    6. System error rates
    Includes automated root-cause investigation and retraining evaluation.
    """
    monitor = get_monitor()
    predictor = get_predictor()
    request.state.model_version = predictor.model_version

    if scenario:
        records = monitor.generate_synthetic_production_window(scenario=scenario, sample_size=sample_limit)
        report = monitor.detector.evaluate_production_data(records)
    else:
        report = monitor.audit_from_database(db=db, sample_limit=sample_limit, include_synthetic_if_empty=True)

    logger.info(
        f"Drift monitoring audit executed: status={report['overall_status']}, retrain_justified={report['retraining_evaluation']['retrain_justified']}",
        extra={
            "request_id": getattr(request.state, "request_id", None),
            "endpoint": "GET /monitoring/drift",
            "model_version": predictor.model_version,
            "overall_status": report["overall_status"]
        }
    )
    return report


@router.post("/monitoring/evaluate-retrain", response_model=RetrainingJustificationResponse, tags=["Monitoring"])
async def evaluate_retraining_justification(
    payload: RetrainingJustificationRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Phase 27: Automated Retraining Justification Engine.
    Implements the closed-loop governance:
    Production Data -> Monitoring -> Detect Changes -> Investigate -> Retrain when justified.
    Evaluates multi-condition statistical triggers (PSI >= 0.25, class shift > 25%, emergent infrastructure).
    """
    monitor = get_monitor()
    predictor = get_predictor()
    request.state.model_version = predictor.model_version

    window_size = payload.sample_window_size or 250
    if payload.scenario:
        records = monitor.generate_synthetic_production_window(scenario=payload.scenario, sample_size=window_size)
        report = monitor.detector.evaluate_production_data(records)
    else:
        report = monitor.audit_from_database(db=db, sample_limit=window_size, include_synthetic_if_empty=True)

    retrain_eval = report["retraining_evaluation"]
    metrics_summary = {
        "url_length_psi": report["metrics"]["url_length"]["psi"],
        "probability_psi": report["metrics"]["prediction_distribution"]["probability_psi"],
        "entropy_psi": report["metrics"]["domain_characteristics"]["shannon_entropy"]["psi"],
        "phishing_shift_pct": report["metrics"]["phishing_legitimate_ratio"]["shift_percentage_points"],
        "p95_latency_ms": report["metrics"]["api_latency"]["p95_latency_ms"],
        "error_rate_pct": report["metrics"]["error_rate"]["error_rate_pct"],
        "overall_status": report["overall_status"]
    }

    logger.info(
        f"Retraining evaluation completed: justified={retrain_eval['retrain_justified']}, action={retrain_eval['recommended_action']}",
        extra={
            "request_id": getattr(request.state, "request_id", None),
            "endpoint": "POST /monitoring/evaluate-retrain",
            "retrain_justified": retrain_eval["retrain_justified"]
        }
    )

    return RetrainingJustificationResponse(
        timestamp=report["timestamp"],
        retrain_justified=retrain_eval["retrain_justified"],
        severity=retrain_eval["severity"],
        recommended_action=retrain_eval["recommended_action"],
        triggers_fired=retrain_eval["triggers_fired"],
        retraining_plan=retrain_eval["retraining_plan"],
        metrics_summary=metrics_summary
    )


@router.post("/analyze/enhanced", response_model=EnhancedAnalyzeResponse, tags=["Advanced Extensions"])
async def analyze_url_enhanced(payload: EnhancedAnalyzeRequest, request: Request):
    """
    Phase 29: Advanced Multi-Signal URL Inspection.
    Combines:
    - ML Statistical Inference (Phase 1-14 Champion Model)
    - External Domain Reputation Feeds & Whitelist (35.1)
    - DNS Record & Resolution Characterization (35.2)
    - WHOIS Domain Age & Registration Heuristics (35.3)
    """
    t0 = time.perf_counter()
    predictor = get_predictor()
    reputation_engine = get_reputation_engine()
    dns_extractor = get_dns_extractor()
    whois_extractor = get_whois_extractor()

    # 1. Base ML Prediction
    ml_res = predictor.predict(payload.url, include_explanation=False)
    ml_prob = ml_res["probability"]

    # 2. Domain Reputation Fusion (35.1)
    rep_res = None
    fused_prob = ml_prob
    if payload.enable_reputation:
        rep_fusion = reputation_engine.fuse_with_ml(ml_prob, payload.url)
        rep_res = rep_fusion["reputation"]
        fused_prob = rep_fusion["fused_probability"]

    # 3. DNS Features (35.2)
    dns_res = None
    if payload.enable_dns:
        dns_res = dns_extractor.extract_dns_features(payload.url)
        if not dns_res["resolves"] and fused_prob < 0.65:
            fused_prob = min(0.95, fused_prob + 0.20)
        elif dns_res["is_fast_flux_suspect"]:
            fused_prob = min(0.98, fused_prob + 0.35)

    # 4. WHOIS & Domain Age (35.3)
    whois_res = None
    if payload.enable_whois:
        whois_res = whois_extractor.extract_whois_features(payload.url)
        if whois_res["is_newly_registered"] and fused_prob < 0.70:
            fused_prob = min(0.95, fused_prob + 0.30)

    fused_prob = round(float(fused_prob), 4)

    # Calibrate final risk tier
    if fused_prob >= 0.65:
        final_risk = "HIGH"
        final_action = "BLOCK"
        recommendation = "Multi-signal threat confirmed (ML score + external intelligence). Block access immediately."
    elif fused_prob >= 0.40:
        final_risk = "MEDIUM"
        final_action = "CAUTION"
        recommendation = "Anomalies detected across domain characteristics. Exercise caution."
    else:
        final_risk = "LOW"
        final_action = "ALLOW"
        recommendation = "Verified safe. Domain conforms to trusted web standards."

    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    logger.info(
        f"Enhanced URL analysis completed: final_risk={final_risk}, fused_prob={fused_prob}",
        extra={
            "request_id": getattr(request.state, "request_id", None),
            "endpoint": "POST /analyze/enhanced",
            "url": sanitize_url(payload.url),
            "fused_prob": fused_prob,
            "final_risk": final_risk
        }
    )

    return EnhancedAnalyzeResponse(
        url=payload.url,
        prediction="phishing" if fused_prob >= 0.50 else "legitimate",
        final_risk_level=final_risk,
        final_action=final_action,
        recommendation=recommendation,
        ml_probability=round(ml_prob, 4),
        fused_probability=fused_prob,
        reputation=rep_res,
        dns=dns_res,
        whois=whois_res,
        execution_time_ms=round(elapsed_ms, 2)
    )


@router.post("/analyze/email", response_model=EmailAnalyzeResponse, tags=["Advanced Extensions"])
async def analyze_email_phishing(payload: EmailAnalyzeRequest, request: Request):
    """
    Phase 29.4: Multi-Modal Email Phishing Detection.
    Roadmap Architecture:
    Email (Subject, Body, Links, Sender) -> URL + Text + Sender Features -> Risk Model.
    Builds on top of reliable URL prediction and reputation intelligence.
    """
    email_analyzer = get_email_analyzer()
    result = email_analyzer.analyze_email(
        subject=payload.subject,
        body=payload.body,
        sender_email=payload.sender_email,
        sender_display_name=payload.sender_display_name,
        auth_headers=payload.auth_headers
    )

    logger.info(
        f"Email phishing analysis completed: verdict={result['overall_verdict']}, score={result['overall_risk_score']}",
        extra={
            "request_id": getattr(request.state, "request_id", None),
            "endpoint": "POST /analyze/email",
            "sender": payload.sender_email,
            "overall_verdict": result["overall_verdict"]
        }
    )

    return EmailAnalyzeResponse(**result)


