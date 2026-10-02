"""
Phishing Detection & Risk Intelligence Platform
Phase 20.1: Consolidated Core Unit Tests

Covers:
1. URL parser
2. Feature extractor
3. Risk calculator
4. Input validation
"""

import pytest
from src.preprocessing.url_parser import URLParser
from src.features.extractor import FeatureExtractor, calculate_shannon_entropy
from src.evaluation.threshold_optimizer import classify_risk
from api.schemas import PredictRequest


# ==========================================
# 1. URL PARSER TESTS (26.1.1)
# ==========================================
def test_url_parser_components():
    parser = URLParser()
    url = "https://login.example.com:8443/account/verify?id=123#section2"
    parsed = parser.parse(url)

    assert parsed.scheme == "https"
    assert parsed.hostname == "login.example.com"
    assert parsed.subdomain == "login"
    assert parsed.domain == "example.com"
    assert parsed.path == "/account/verify"
    assert parsed.query == "id=123"
    assert parsed.port == 8443
    assert parsed.fragment == "section2"


def test_url_parser_edge_cases():
    parser = URLParser()
    # IP address host
    ip_parsed = parser.parse("http://192.168.1.1/login")
    assert ip_parsed.hostname == "192.168.1.1"

    # Punycode / Internationalized domain
    puny_parsed = parser.parse("https://xn--e1afmkfd.xn--p1ai/path")
    assert puny_parsed.is_punycode is True


# ==========================================
# 2. FEATURE EXTRACTOR TESTS (26.1.2)
# ==========================================
def test_feature_extractor_outputs():
    extractor = FeatureExtractor()
    url = "https://secure.chase-bank.xyz/login/verify?token=1234"
    features = extractor.extract_features_dict(url)

    # Invariant: 22 features present
    assert len(features) == 22

    # Invariant: Specific signals correctly computed
    assert features["url_length"] == len(url)
    assert features["uses_https"] == 1
    assert features["has_query"] == 1
    assert features["suspicious_keyword_count"] >= 2  # 'secure', 'login', 'verify'
    assert features["url_entropy"] > 0.0


def test_shannon_entropy_calculation():
    # Low entropy (uniform characters)
    low_ent = calculate_shannon_entropy("aaaaaaa")
    assert low_ent == 0.0

    # High entropy (diverse characters)
    high_ent = calculate_shannon_entropy("aB3$kL9#mP1!")
    assert high_ent > 3.0


# ==========================================
# 3. RISK CALCULATOR TESTS (26.1.3)
# ==========================================
def test_risk_calculator_tiers_and_actions():
    t1, t2 = 0.40, 0.65

    # Low risk
    low = classify_risk(0.12, t1=t1, t2=t2)
    assert low["risk_level"] == "LOW"
    assert low["action"] == "ALLOW"

    # Medium risk
    med = classify_risk(0.50, t1=t1, t2=t2)
    assert med["risk_level"] == "MEDIUM"
    assert med["action"] == "CAUTION"

    # High risk
    high = classify_risk(0.88, t1=t1, t2=t2)
    assert high["risk_level"] == "HIGH"
    assert high["action"] == "BLOCK"

    # Boundary conditions
    boundary_low = classify_risk(t1, t1=t1, t2=t2)
    assert boundary_low["risk_level"] == "MEDIUM"

    boundary_high = classify_risk(t2, t1=t1, t2=t2)
    assert boundary_high["risk_level"] == "HIGH"


# ==========================================
# 4. INPUT VALIDATION TESTS (26.1.4)
# ==========================================
def test_input_validation_rules():
    # Valid URLs
    valid_req = PredictRequest(url="https://secure.paypal.com/signin")
    assert valid_req.url == "https://secure.paypal.com/signin"

    # Rejection: Empty string
    with pytest.raises(ValueError, match="cannot be empty"):
        PredictRequest(url="   ")

    # Rejection: Unsupported protocol
    with pytest.raises(ValueError, match="Unsupported protocol scheme"):
        PredictRequest(url="ftp://files.malware.com/payload.exe")

    with pytest.raises(ValueError, match="Unsupported protocol scheme"):
        PredictRequest(url="javascript:alert(1)")

    # Rejection: Oversized input (>2048 chars)
    with pytest.raises(ValueError, match="exceeds maximum permissible length"):
        PredictRequest(url="https://example.com/" + "a" * 2100)

    # Rejection: Control characters
    with pytest.raises(ValueError, match="illegal control characters"):
        PredictRequest(url="https://example.com/bad\x00path")
