"""
Phishing Detection & Risk Intelligence Platform
Phase 29: Advanced Extensions Test Suite

Verifies:
1. 35.1 Domain Reputation:
   - Malicious feed detection and ML score escalation
   - Benign authority whitelist damping
   - In-memory TTL caching and cache eviction
2. 35.2 DNS Features:
   - Domain resolution and IP count extraction
   - Unresolvable / NXDOMAIN handling
   - DNS Circuit Breaker fault tolerance
3. 35.3 WHOIS / Domain Age:
   - Domain age calculation
   - Brand new / fresh domain (< 14 days) risk flags
   - Mature domain mitigation
4. 35.4 Multi-Modal Email Phishing Detection:
   - Link extraction and reliable ML pipeline scoring
   - Display name spoofing detection
   - Urgency & credential lure classification
   - Multi-modal risk fusion scoring
5. FastAPI Endpoints:
   - POST /analyze/enhanced
   - POST /analyze/email
"""

import pytest
from fastapi.testclient import TestClient

from api.main import app
from src.extensions.reputation import DomainReputationEngine, ReputationVerdict, ReputationCache
from src.extensions.dns_features import DNSFeatureExtractor, DNSCircuitBreaker
from src.extensions.whois_features import WHOISFeatureExtractor
from src.extensions.email_analyzer import EmailRiskAnalyzer


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# -----------------------------------------------------------------------------
# 1. Domain Reputation Tests (35.1)
# -----------------------------------------------------------------------------

def test_reputation_malicious_feed_escalates_risk():
    """Domain on confirmed threat feed must escalate probability to >= 0.95."""
    rep = DomainReputationEngine()
    url = "https://secure-paypal-verify.cc/login/session"

    res = rep.fuse_with_ml(ml_probability=0.15, url=url)
    assert res["reputation"]["verdict"] == ReputationVerdict.MALICIOUS.value
    assert res["fused_probability"] >= 0.95
    assert res["fused_risk_level"] == "HIGH"
    assert res["override_applied"] is True


def test_reputation_benign_authority_whitelist_damps_risk():
    """Authoritative domain without credential tokens must damp false positive probabilities."""
    rep = DomainReputationEngine()
    url = "https://www.google.com/search?q=machine+learning"

    res = rep.fuse_with_ml(ml_probability=0.70, url=url)
    assert res["reputation"]["verdict"] == ReputationVerdict.BENIGN.value
    assert res["fused_probability"] <= 0.20
    assert res["fused_risk_level"] == "LOW"
    assert res["override_applied"] is True


def test_reputation_cache_ttl():
    """In-memory cache must return stored data without redundant re-resolution."""
    cache = ReputationCache(ttl_seconds=10)
    cache.set("test-domain.com", {"verdict": "BENIGN", "score": -1.0})

    hit = cache.get("test-domain.com")
    assert hit is not None
    assert hit["verdict"] == "BENIGN"

    miss = cache.get("non-existent-domain.com")
    assert miss is None


# -----------------------------------------------------------------------------
# 2. DNS Feature Extraction Tests (35.2)
# -----------------------------------------------------------------------------

def test_dns_feature_extraction_resolvable_domain():
    """Standard internet domain must resolve with positive IP count."""
    dns = DNSFeatureExtractor(timeout_seconds=1.0)
    res = dns.extract_dns_features("https://google.com")

    assert res["resolves"] is True
    assert res["ip_count"] > 0
    assert res["status"] == "SUCCESS"
    assert res["lookup_latency_ms"] >= 0.0


def test_dns_unresolvable_domain_nxdomain():
    """Non-existent domain must gracefully report unresolvable with elevated risk."""
    dns = DNSFeatureExtractor(timeout_seconds=0.5)
    res = dns.extract_dns_features("https://definitely-not-real-fake-nxdomain-999.invalid")

    assert res["resolves"] is False
    assert res["ip_count"] == 0
    assert res["status"] == "NXDOMAIN"
    assert res["dns_risk_score"] >= 0.40


def test_dns_circuit_breaker_behavior():
    """Consecutive failures must open the circuit breaker and return fallback."""
    breaker = DNSCircuitBreaker(failure_threshold=3, recovery_timeout_seconds=10.0)
    assert breaker.is_available() is True

    breaker.record_failure()
    breaker.record_failure()
    assert breaker.is_available() is True

    breaker.record_failure()  # 3rd failure triggers OPEN
    assert breaker.is_available() is False
    assert breaker.state == "OPEN"

    breaker.record_success()
    assert breaker.is_available() is True
    assert breaker.state == "CLOSED"


# -----------------------------------------------------------------------------
# 3. WHOIS / Domain Age Tests (35.3)
# -----------------------------------------------------------------------------

def test_whois_mature_domain():
    """Established domains (Google, Microsoft) must be recognized as mature (> 365 days)."""
    whois = WHOISFeatureExtractor()
    res = whois.extract_whois_features("https://google.com")

    assert res["age_days"] > 365
    assert res["is_mature_domain"] is True
    assert res["is_newly_registered"] is False
    assert res["whois_risk_score"] <= 0.15


def test_whois_fresh_disposable_domain():
    """Disposable / newly minted domain must flag brand new domain risk (< 14 days)."""
    whois = WHOISFeatureExtractor()
    res = whois.extract_whois_features("https://update-account-auth.xyz/verify")

    assert res["age_days"] < 14
    assert res["is_newly_registered"] is True
    assert res["is_fresh_domain"] is True
    assert res["whois_risk_score"] >= 0.60


# -----------------------------------------------------------------------------
# 4. Multi-Modal Email Phishing Tests (35.4)
# -----------------------------------------------------------------------------

def test_email_analyzer_spoofing_and_url_escalation():
    """Email claiming brand in display name with free webmail and malicious link must trigger PHISHING."""
    analyzer = EmailRiskAnalyzer()
    res = analyzer.analyze_email(
        subject="URGENT: Your account has been temporarily restricted",
        body="Security notice: Please verify your identity at https://secure-paypal-verify.cc/login within 24 hours.",
        sender_email="support-team@gmail.com",
        sender_display_name="PayPal Support",
        auth_headers={"Received-SPF": "softfail"}
    )

    assert res["overall_verdict"] == "PHISHING"
    assert res["risk_tier"] == "HIGH"
    assert res["overall_risk_score"] >= 0.80

    # Sender analysis
    sender = res["sender_analysis"]
    assert sender["display_name_spoofing_detected"] is True
    assert len(sender["anomalies_detected"]) >= 2

    # Text analysis
    text = res["text_analysis"]
    assert text["has_urgency_cue"] is True
    assert "within 24 hours" in text["urgency_keywords_found"]

    # URL analysis
    urls = res["url_analysis"]
    assert urls["total_urls_found"] == 1
    assert urls["compromised_urls_count"] == 1


def test_email_analyzer_benign_communication():
    """Benign email without spoofing, urgency, or malicious links must return LEGITIMATE."""
    analyzer = EmailRiskAnalyzer()
    res = analyzer.analyze_email(
        subject="Monthly Engineering Newsletter",
        body="Here are the engineering updates from our sprint. Read the full docs at https://github.com/features.",
        sender_email="newsletter@github.com",
        sender_display_name="GitHub Team",
        auth_headers={"Received-SPF": "pass", "DMARC-Filter": "pass"}
    )

    assert res["overall_verdict"] == "LEGITIMATE"
    assert res["risk_tier"] == "LOW"
    assert res["overall_risk_score"] < 0.40
    assert res["sender_analysis"]["display_name_spoofing_detected"] is False


# -----------------------------------------------------------------------------
# 5. FastAPI Endpoints Integration Tests
# -----------------------------------------------------------------------------

def test_fastapi_enhanced_analyze_endpoint(client):
    """POST /analyze/enhanced must return comprehensive multi-signal inspection."""
    payload = {
        "url": "https://secure-paypal-verify.cc/login",
        "enable_reputation": True,
        "enable_dns": True,
        "enable_whois": True
    }
    response = client.post("/analyze/enhanced", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["final_risk_level"] == "HIGH"
    assert data["final_action"] == "BLOCK"
    assert data["fused_probability"] >= 0.90
    assert "reputation" in data
    assert "dns" in data
    assert "whois" in data
    assert data["execution_time_ms"] > 0.0


def test_fastapi_email_analyze_endpoint(client):
    """POST /analyze/email must return multi-modal email phishing assessment."""
    payload = {
        "subject": "Immediate action required: Suspicious sign-in attempt",
        "body": "We detected an unauthorized login. Click here to confirm identity: https://login-update-auth.xyz/verify",
        "sender_email": "security-alert@gmail.com",
        "sender_display_name": "Google Security Team",
        "auth_headers": {"Received-SPF": "fail"}
    }
    response = client.post("/analyze/email", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["overall_verdict"] == "PHISHING"
    assert data["risk_tier"] == "HIGH"
    assert "multimodal_scores" in data
    assert "url_analysis" in data
    assert "sender_analysis" in data
    assert "text_analysis" in data
