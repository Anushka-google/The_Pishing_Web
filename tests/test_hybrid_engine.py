"""
Unit tests for Phase 2: Hybrid Detection Engine
"""

import pytest
from src.prediction.hybrid_engine import (
    HybridRiskEngine,
    BlacklistStore,
    HeuristicRuleEngine,
    DetectionMode
)
from src.prediction.mvp_pipeline import RiskLevel


@pytest.fixture
def hybrid_engine():
    blacklist = BlacklistStore({"https://verified-phish.com/login", "http://malicious-bank.xyz"})
    return HybridRiskEngine(blacklist=blacklist)


def test_blacklist_match_short_circuits(hybrid_engine):
    # Blacklisted URL should trigger fast path without ML evaluation
    result = hybrid_engine.analyze("https://verified-phish.com/login")
    assert result.blacklist_matched is True
    assert result.detection_mode == DetectionMode.BLACKLIST
    assert result.risk_level == RiskLevel.HIGH
    assert result.probability == 1.0


def test_clean_url_pure_ml(hybrid_engine):
    # Normal URL with no heuristic triggers and no blacklist hit
    result = hybrid_engine.analyze("https://github.com/explore")
    assert result.blacklist_matched is False
    assert result.detection_mode == DetectionMode.MACHINE_LEARNING
    assert result.risk_level == RiskLevel.LOW
    assert result.probability < 0.30
    assert len(result.heuristic_flags) == 0


def test_heuristic_trigger_escalates_to_hybrid(hybrid_engine):
    # Raw IP host triggers heuristic rule
    result = hybrid_engine.analyze("http://192.168.1.1/admin")
    assert result.blacklist_matched is False
    assert result.detection_mode == DetectionMode.HYBRID
    assert any("RAW_IP_HOST" in flag for flag in result.heuristic_flags)
    assert result.probability >= 0.50


def test_credential_delimiter_heuristic(hybrid_engine):
    result = hybrid_engine.analyze("https://google.com@attacker-controlled.com/auth")
    assert any("CREDENTIAL_DELIMITER_ABUSE" in flag for flag in result.heuristic_flags)
