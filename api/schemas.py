"""
Phishing Detection & Risk Intelligence Platform
Phase 15 & 16: API Request & Response Schemas with Strict Input Validation
"""

import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlparse


class PredictRequest(BaseModel):
    url: str = Field(
        ...,
        description="The target web URL to inspect for phishing indicators.",
        examples=["https://accounts.google.com/signin", "https://login.paypal.com.cloud-node-402.cc/session/verify"]
    )

    @field_validator("url")
    @classmethod
    def validate_url_safety(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("URL cannot be empty or solely whitespace.")

        clean_url = v.strip()

        # Enforce reasonable length limits
        if len(clean_url) > 2048:
            raise ValueError("URL exceeds maximum permissible length of 2048 characters.")

        # Reject null bytes or dangerous control characters
        if any(ord(char) < 32 or ord(char) == 127 for char in clean_url):
            raise ValueError("URL contains illegal control characters or null bytes.")

        # Parse structure
        try:
            parsed = urlparse(clean_url)
        except Exception as e:
            raise ValueError(f"Malformed URL structure: {str(e)}")

        # Require explicit, supported scheme (http or https)
        scheme = parsed.scheme.lower()
        if not scheme:
            raise ValueError("Missing protocol scheme. URL must explicitly start with http:// or https://")

        if scheme not in ["http", "https"]:
            raise ValueError(f"Unsupported protocol scheme '{scheme}'. Only http:// and https:// are permitted.")

        # Check netloc / hostname
        netloc = parsed.netloc.split(":")[0].strip()
        if not netloc:
            raise ValueError("Malformed URL: Missing valid domain or host authority.")

        if " " in clean_url:
            raise ValueError("URL must not contain raw whitespace.")

        return clean_url


class FeatureAttribution(BaseModel):
    feature: str
    value: float
    shap_impact: float
    direction: str


class ExplanationData(BaseModel):
    top_risk_contributors: List[FeatureAttribution] = []
    top_mitigating_factors: List[FeatureAttribution] = []
    narrative_signals: List[str] = []
    narrative_mitigators: List[str] = []


class PerformanceDistribution(BaseModel):
    mean_ms: float
    median_p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    std_ms: float


class PerformanceResponse(BaseModel):
    status: str = "success"
    model_version: str
    model_name: str
    feature_extraction: PerformanceDistribution
    model_inference: PerformanceDistribution
    database_latency: PerformanceDistribution
    api_response_time: PerformanceDistribution
    primary_bottleneck: str
    primary_bottleneck_share_pct: float
    sla_compliance: Dict[str, Any]
    live_database_telemetry: Optional[Dict[str, Any]] = None


class LatencyMetadata(BaseModel):
    model_name: str
    model_version: str
    feature_extraction_time_ms: float
    model_inference_time_ms: float
    database_latency_ms: float = 0.0
    api_response_time_ms: float = 0.0
    total_latency_ms: float
    bottleneck: Optional[str] = None
    performance_breakdown: Optional[Dict[str, Any]] = None


class ThresholdMetadata(BaseModel):
    t1_low: float
    t2_high: float
    t_optimal: float


class PredictResponse(BaseModel):
    url: str
    prediction: str
    probability: float
    risk_level: str
    action: str
    recommendation: str
    thresholds: ThresholdMetadata
    features: Optional[Dict[str, Any]] = None
    explanation: Optional[ExplanationData] = None
    metadata: LatencyMetadata


class HistoryRecord(BaseModel):
    id: str
    url: str
    prediction: str
    probability: float
    risk_level: str
    action: str
    created_at: str
    model_version: str
    feature_extraction_ms: Optional[float] = None
    model_inference_ms: Optional[float] = None
    db_latency_ms: Optional[float] = None
    api_response_time_ms: Optional[float] = None
    bottleneck: Optional[str] = None


class HistoryResponse(BaseModel):
    total_records: int
    records: List[HistoryRecord]


class StatsResponse(BaseModel):
    total_scans: int
    phishing_detected: int
    legitimate_detected: int
    phishing_rate_pct: float
    avg_latency_ms: float
    risk_distribution: Dict[str, int]


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    model_loaded: bool
    model_name: str
    model_version: str = "v2"
    uptime_seconds: float


class ModelVersionItem(BaseModel):
    version: str
    model_name: str
    architecture: str
    feature_count: int
    feature_names: List[str] = []
    description: str
    is_active: bool
    created_at: str
    metrics: Dict[str, Any] = {}


class ModelVersionsResponse(BaseModel):
    active_version: str
    previous_version: Optional[str] = None
    versions: List[ModelVersionItem]


class ModelSwitchRequest(BaseModel):
    version: str = Field(..., description="Target model version to activate ('v1', 'v2', 'v3').", examples=["v1", "v2", "v3"])


class ModelSwitchResponse(BaseModel):
    status: str
    active_version: str
    model_name: str
    feature_count: int
    message: str


# ---------------------------------------------------------
# Phase 27: Production Monitoring & Drift Detection Schemas
# ---------------------------------------------------------

class RetrainingPlan(BaseModel):
    action: str
    target_model_version: str
    recommended_steps: List[str]
    retraining_priority: str


class RetrainingEvaluation(BaseModel):
    retrain_justified: bool
    severity: str
    triggers_fired_count: int
    triggers_fired: List[str]
    recommended_action: str
    retraining_plan: RetrainingPlan


class InvestigationReport(BaseModel):
    findings: List[str]
    root_cause_hypotheses: List[str]


class DriftMonitoringResponse(BaseModel):
    timestamp: str
    window_size: int
    overall_status: str
    metrics: Dict[str, Any]
    investigation: InvestigationReport
    retraining_evaluation: RetrainingEvaluation


class RetrainingJustificationRequest(BaseModel):
    sample_window_size: Optional[int] = Field(default=500, description="Number of recent records to evaluate.")
    scenario: Optional[str] = Field(
        default=None,
        description="Optional simulation scenario: 'healthy', 'short_urls', 'phishing_surge', 'critical_drift'."
    )


class RetrainingJustificationResponse(BaseModel):
    timestamp: str
    retrain_justified: bool
    severity: str
    recommended_action: str
    triggers_fired: List[str]
    retraining_plan: RetrainingPlan
    metrics_summary: Dict[str, Any]


# ---------------------------------------------------------
# Phase 29: Advanced Extensions Schemas (35.1 - 35.4)
# ---------------------------------------------------------

class EnhancedAnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect across ML, reputation, DNS, and WHOIS.")
    enable_reputation: bool = Field(default=True, description="Enable external threat intelligence reputation fusion.")
    enable_dns: bool = Field(default=True, description="Enable live DNS record and resolution enrichment.")
    enable_whois: bool = Field(default=True, description="Enable domain age and WHOIS registration enrichment.")


class EnhancedAnalyzeResponse(BaseModel):
    url: str
    prediction: str
    final_risk_level: str
    final_action: str
    recommendation: str
    ml_probability: float
    fused_probability: float
    reputation: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    whois: Optional[Dict[str, Any]] = None
    execution_time_ms: float


class EmailAnalyzeRequest(BaseModel):
    subject: str = Field(..., description="Email subject line.")
    body: str = Field(..., description="Plaintext or HTML email message body.")
    sender_email: str = Field(..., description="Sender's email address (e.g. alert@notice.xyz).")
    sender_display_name: Optional[str] = Field(default=None, description="Sender's display name header (e.g. 'PayPal Security').")
    auth_headers: Optional[Dict[str, str]] = Field(default=None, description="Authentication headers (SPF, DKIM, DMARC).")


class EmailAnalyzeResponse(BaseModel):
    overall_verdict: str
    overall_risk_score: float
    risk_tier: str
    recommendation: str
    multimodal_scores: Dict[str, float]
    url_analysis: Dict[str, Any]
    sender_analysis: Dict[str, Any]
    text_analysis: Dict[str, Any]


