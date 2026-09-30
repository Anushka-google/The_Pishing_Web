"""
Phishing Detection & Risk Intelligence Platform
Phase 2: Hybrid Detection Engine Architecture
Integrates Blacklist Fast-Path, Heuristic Rules, and ML Statistical Scoring
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Set
import re
from src.prediction.mvp_pipeline import MVPPhishingPipeline, MVPResult, RiskLevel


class DetectionMode(str, Enum):
    BLACKLIST = "BLACKLIST_MATCH"
    MACHINE_LEARNING = "MACHINE_LEARNING"
    HYBRID = "HYBRID_CONSENSUS"


@dataclass
class HybridAnalysisResult:
    url: str
    prediction: str
    probability: float
    risk_level: RiskLevel
    detection_mode: DetectionMode
    heuristic_flags: List[str]
    blacklist_matched: bool
    summary: str
    execution_time_ms: float
    feature_signals: Dict[str, Any] = field(default_factory=dict)


class BlacklistStore:
    """
    In-memory Bloom filter / set proxy representing verified malicious URL/domain feeds
    (e.g., PhishTank, URLhaus).
    """
    def __init__(self, initial_entries: Optional[Set[str]] = None):
        self._entries: Set[str] = {entry.lower().strip() for entry in (initial_entries or set())}

    def add(self, url_or_domain: str) -> None:
        self._entries.add(url_or_domain.lower().strip())

    def contains(self, url_or_domain: str) -> bool:
        normalized = url_or_domain.lower().strip()
        return normalized in self._entries


class HeuristicRuleEngine:
    """
    Heuristic rule evaluator identifying high-confidence structural signatures and anomalies.
    """
    IP_HOST_REGEX = re.compile(r"^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$")
    AT_SYMBOL_REGEX = re.compile(r"https?://[^/]*@")
    HIGH_RISK_KEYWORDS = {"wallet", "banking", "verify-account", "security-update", "confirm-identity"}

    def evaluate(self, url: str) -> List[str]:
        flags = []
        lowered = url.lower()

        # Rule 1: Raw IP host
        if self.IP_HOST_REGEX.match(lowered):
            flags.append("RAW_IP_HOST: Host identifier is a raw IP address instead of domain name.")

        # Rule 2: User-info delimiter '@' abuse
        if self.AT_SYMBOL_REGEX.search(lowered):
            flags.append("CREDENTIAL_DELIMITER_ABUSE: Contains '@' symbol used to obscure real host.")

        # Rule 3: Punycode homograph indicator
        if "xn--" in lowered:
            flags.append("IDN_HOMOGRAPH_INDICATOR: Contains 'xn--' Punycode representation.")

        # Rule 4: Multiple high-risk keywords combined
        matches = [kw for kw in self.HIGH_RISK_KEYWORDS if kw in lowered]
        if len(matches) >= 2:
            flags.append(f"HIGH_RISK_KEYWORD_CONCENTRATION: Multiple sensitive keywords present: {matches}")

        return flags


class HybridRiskEngine:
    """
    Hybrid Detection Orchestrator:
    - Layer 1: Fast-path blacklist lookup
    - Layer 2: Heuristic rule evaluation
    - Layer 3: Machine learning statistical scoring
    """
    def __init__(
        self,
        ml_pipeline: Optional[MVPPhishingPipeline] = None,
        blacklist: Optional[BlacklistStore] = None,
        heuristics: Optional[HeuristicRuleEngine] = None
    ):
        self.ml_pipeline = ml_pipeline or MVPPhishingPipeline()
        self.blacklist = blacklist or BlacklistStore()
        self.heuristics = heuristics or HeuristicRuleEngine()

    def analyze(self, raw_url: str) -> HybridAnalysisResult:
        normalized = self.ml_pipeline.validate_url(raw_url)

        # 1. Fast-Path Blacklist Check
        if self.blacklist.contains(normalized):
            return HybridAnalysisResult(
                url=normalized,
                prediction="phishing",
                probability=1.0,
                risk_level=RiskLevel.HIGH,
                detection_mode=DetectionMode.BLACKLIST,
                heuristic_flags=["KNOWN_MALICIOUS_REPUTATION: URL matches verified blacklist feed."],
                blacklist_matched=True,
                summary="Immediate High Risk: URL is cataloged on verified malicious threat lists.",
                execution_time_ms=0.2,
                feature_signals={"blacklist_hit": 1}
            )

        # 2. Heuristic Evaluation
        heuristic_flags = self.heuristics.evaluate(normalized)

        # 3. Machine Learning Inference
        ml_result: MVPResult = self.ml_pipeline.analyze(normalized)

        # 4. Hybrid Consensus & Risk Adjustment
        final_prob = ml_result.probability
        final_risk = ml_result.risk_level
        mode = DetectionMode.MACHINE_LEARNING

        # If severe heuristics trigger, escalate risk if ML was borderline
        if heuristic_flags:
            mode = DetectionMode.HYBRID
            # Boost score based on number of distinct heuristic violations
            boost = min(0.35, len(heuristic_flags) * 0.15)
            final_prob = min(0.99, round(final_prob + boost, 4))
            _, final_risk, _ = self.ml_pipeline.classify_risk(final_prob)

        summary = ml_result.summary
        if heuristic_flags:
            summary += f" [Heuristic Warnings: {len(heuristic_flags)} anomaly rules triggered]"

        return HybridAnalysisResult(
            url=normalized,
            prediction="phishing" if final_risk == RiskLevel.HIGH else ("suspicious" if final_risk == RiskLevel.MEDIUM else "legitimate"),
            probability=final_prob,
            risk_level=final_risk,
            detection_mode=mode,
            heuristic_flags=heuristic_flags,
            blacklist_matched=False,
            summary=summary,
            execution_time_ms=ml_result.execution_time_ms,
            feature_signals=ml_result.extracted_features
        )
