"""
Phishing Detection & Risk Intelligence Platform
MVP Pipeline: URL -> Feature Extraction -> ML Model -> Phishing Probability -> Risk Classification
"""

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import re
import time


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class MVPResult:
    url: str
    prediction: str
    probability: float
    risk_level: RiskLevel
    confidence: float
    extracted_features: Dict[str, Any]
    summary: str
    execution_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        return data


class MVPFeatureExtractor:
    """
    Initial MVP feature extractor implementing length, character, structural,
    and keyword heuristic indicators.
    """
    SUSPICIOUS_KEYWORDS = {
        "login", "verify", "account", "security", "update",
        "password", "bank", "payment", "confirm", "wallet", "signin"
    }

    def extract(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = url.lower()

        # Check for IP address in netloc
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
        has_ip = 1 if re.match(ip_pattern, netloc) else 0

        # Subdomains count
        domain_parts = netloc.split(":")[0].split(".")
        subdomain_count = max(0, len(domain_parts) - 2)

        # Keyword counts
        keyword_hits = sum(1 for kw in self.SUSPICIOUS_KEYWORDS if kw in full)

        features = {
            "url_length": len(url),
            "domain_length": len(netloc),
            "path_length": len(path),
            "query_length": len(query),
            "number_of_dots": full.count("."),
            "number_of_hyphens": full.count("-"),
            "number_of_slashes": full.count("/"),
            "number_of_digits": sum(c.isdigit() for c in url),
            "number_of_subdomains": subdomain_count,
            "has_ip_address": has_ip,
            "uses_https": 1 if parsed.scheme == "https" else 0,
            "suspicious_keyword_count": keyword_hits,
        }
        return features


class MVPBaselineScorer:
    """
    MVP baseline statistical/heuristic scorer.
    Maps extracted feature vectors to calibrated phishing probability in [0, 1].
    Will be seamlessly replaced by trained Logistic Regression / XGBoost in subsequent phases.
    """
    def score(self, features: Dict[str, Any]) -> float:
        score = 0.05  # Base benign prior probability

        # IP address host is a very strong malicious indicator
        if features.get("has_ip_address", 0) == 1:
            score += 0.55

        # Subdomain depth
        subdomains = features.get("number_of_subdomains", 0)
        if subdomains >= 3:
            score += 0.25
        elif subdomains == 2:
            score += 0.10

        # Suspicious keywords
        kw_count = features.get("suspicious_keyword_count", 0)
        score += min(0.35, kw_count * 0.12)

        # Unusual length
        if features.get("url_length", 0) > 75:
            score += 0.15

        # Punctuation / structural anomalies
        if features.get("number_of_hyphens", 0) >= 3:
            score += 0.10

        if not features.get("uses_https", 0):
            score += 0.05

        # Bound probability strictly to [0.01, 0.99]
        return float(max(0.01, min(0.99, round(score, 4))))


class MVPPhishingPipeline:
    """
    End-to-end MVP Pipeline:
    URL -> Validation -> Feature Extraction -> Scoring -> Probability -> Risk Classification
    """
    def __init__(
        self,
        extractor: Optional[MVPFeatureExtractor] = None,
        scorer: Optional[MVPBaselineScorer] = None,
        low_threshold: float = 0.30,
        high_threshold: float = 0.70
    ):
        self.extractor = extractor or MVPFeatureExtractor()
        self.scorer = scorer or MVPBaselineScorer()
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold

    def validate_url(self, url: str) -> str:
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string.")
        cleaned = url.strip()
        if len(cleaned) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters.")
        if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
            # Auto-prepend https for standard testing
            cleaned = "https://" + cleaned
        parsed = urlparse(cleaned)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL structure: cannot extract network location from '{url}'")
        return cleaned

    def classify_risk(self, probability: float) -> tuple[str, RiskLevel, str]:
        if probability < self.low_threshold:
            return (
                "legitimate",
                RiskLevel.LOW,
                "Benign characteristics detected. Low likelihood of phishing."
            )
        elif probability < self.high_threshold:
            return (
                "suspicious",
                RiskLevel.MEDIUM,
                "Elevated risk signals detected. Verification recommended before entering sensitive data."
            )
        else:
            return (
                "phishing",
                RiskLevel.HIGH,
                "Strong phishing patterns detected. Immediate caution or blocking recommended."
            )

    def analyze(self, raw_url: str) -> MVPResult:
        start_time = time.perf_counter()
        normalized_url = self.validate_url(raw_url)
        features = self.extractor.extract(normalized_url)
        probability = self.scorer.score(features)
        prediction, risk_level, summary = self.classify_risk(probability)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        confidence = probability if prediction == "phishing" else (1.0 - probability)

        return MVPResult(
            url=normalized_url,
            prediction=prediction,
            probability=probability,
            risk_level=risk_level,
            confidence=round(confidence, 4),
            extracted_features=features,
            summary=summary,
            execution_time_ms=elapsed_ms
        )
