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


class LatencyMetadata(BaseModel):
    model_name: str
    model_version: str
    feature_extraction_time_ms: float
    model_inference_time_ms: float
    total_latency_ms: float


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
