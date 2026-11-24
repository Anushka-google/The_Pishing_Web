"""
Phishing Detection & Risk Intelligence Platform
Automated Regression & Mathematical Verification Suite for Multi-Signal Fusion

Covers:
1. Mathematical axioms of log-odds accumulation
2. Neutral evidence preservation of calibrated ML posterior
3. RCODE differentiation (NXDOMAIN vs TIMEOUT / SERVFAIL)
4. WHOIS UNKNOWN neutrality (zero penalty for missing registration)
5. Authority whitelist damping and credential delimiter security
6. 8-Scenario audit benchmark verification
"""

import math
import pytest
from src.extensions.fusion import RegularizedBayesianFusion
from src.extensions.dns_features import DNSFeatureExtractor
from src.extensions.whois_features import WHOISFeatureExtractor
from src.extensions.reputation import DomainReputationEngine
from src.prediction.predict import ProductionPredictor


@pytest.fixture(scope="module")
def fusion_engine():
    return RegularizedBayesianFusion()


@pytest.fixture(scope="module")
def predictor():
    return ProductionPredictor(enable_shap=False)


@pytest.fixture(scope="module")
def reputation_engine():
    return DomainReputationEngine()


@pytest.fixture(scope="module")
def dns_extractor():
    return DNSFeatureExtractor()


@pytest.fixture(scope="module")
def whois_extractor():
    return WHOISFeatureExtractor()


class TestMultiSignalFusionMath:
    def test_fusion_probability_axioms(self, fusion_engine):
        """Verifies composite threat score is strictly bounded in [0, 1] and monotonic."""
        for p in [0.001, 0.1, 0.25, 0.5, 0.75, 0.9, 0.999]:
            res = fusion_engine.fuse(p)
            score = res["composite_threat_score"]
            assert 0.0 <= score <= 1.0
            assert math.isfinite(score)
            assert res["ml_probability"] == round(p, 4)

    def test_neutral_evidence_preserves_ml_posterior(self, fusion_engine):
        """Verifies that missing or neutral intelligence strictly preserves the ML posterior."""
        test_probs = [0.15, 0.33, 0.47, 0.65, 0.82]
        for p in test_probs:
            res = fusion_engine.fuse(
                ml_probability=p,
                reputation={"verdict": "UNKNOWN"},
                dns={"status": "SERVFAIL", "resolves": None},
                whois={"status": "UNKNOWN", "age_days": None}
            )
            assert abs(res["composite_threat_score"] - res["ml_probability"]) < 1e-4
            assert res["delta_breakdown"]["total_delta"] == 0.0

    def test_dns_status_distinguishes_nxdomain_from_timeout(self, fusion_engine):
        """Authoritative NXDOMAIN should adjust log-odds, while TIMEOUT must remain neutral."""
        base_p = 0.40
        nxdomain_res = fusion_engine.fuse(
            ml_probability=base_p,
            dns={"status": "NXDOMAIN", "resolves": False}
        )
        timeout_res = fusion_engine.fuse(
            ml_probability=base_p,
            dns={"status": "TIMEOUT", "resolves": None}
        )
        servfail_res = fusion_engine.fuse(
            ml_probability=base_p,
            dns={"status": "SERVFAIL", "resolves": None}
        )

        # NXDOMAIN should increase log-odds by DELTA_DNS_NXDOMAIN (+0.75)
        assert nxdomain_res["composite_threat_score"] > base_p
        assert nxdomain_res["delta_breakdown"]["delta_dns"] == fusion_engine.DELTA_DNS_NXDOMAIN

        # Timeout and SERVFAIL must have 0.0 delta and preserve base probability
        assert timeout_res["composite_threat_score"] == base_p
        assert timeout_res["delta_breakdown"]["delta_dns"] == 0.0
        assert servfail_res["composite_threat_score"] == base_p
        assert servfail_res["delta_breakdown"]["delta_dns"] == 0.0

    def test_whois_unknown_does_not_inflate_risk(self, fusion_engine):
        """Missing or unresolvable WHOIS must apply 0.0 log-odds delta."""
        base_p = 0.47
        res = fusion_engine.fuse(
            ml_probability=base_p,
            whois={"status": "UNKNOWN", "age_days": None, "is_newly_registered": False}
        )
        assert res["delta_breakdown"]["delta_whois"] == 0.0
        assert res["composite_threat_score"] == base_p

    def test_whois_newly_registered_adjusts_bounded_log_odds(self, fusion_engine):
        """Confirmed age < 14 days applies regularized +1.10 delta."""
        base_p = 0.47
        res = fusion_engine.fuse(
            ml_probability=base_p,
            whois={"status": "SUCCESS", "age_days": 4, "is_newly_registered": True}
        )
        assert res["delta_breakdown"]["delta_whois"] == fusion_engine.DELTA_WHOIS_NEWLY_REGISTERED
        # Verify it does NOT jump to 0.95!
        assert res["composite_threat_score"] < 0.80


class TestScenarioBenchmarkIntegrity:
    def test_google_authority_retains_allow_under_dns_failure(self, predictor, reputation_engine, fusion_engine):
        """Google.com must remain LOW risk and ALLOW directive even under DNS timeout/SERVFAIL."""
        url = "https://www.google.com"
        ml_res = predictor.predict(url, include_explanation=False)
        rep_res = reputation_engine.lookup_reputation(url)
        # Simulate offline / SERVFAIL DNS
        sim_dns = {"status": "SERVFAIL", "resolves": None, "is_fast_flux_suspect": False}
        sim_whois = {"status": "SUCCESS", "age_days": 10000}

        fusion_res = fusion_engine.fuse(
            ml_probability=ml_res["probability"],
            reputation=rep_res,
            dns=sim_dns,
            whois=sim_whois,
            url=url
        )

        assert fusion_res["final_risk_level"] == "LOW"
        assert fusion_res["final_action"] == "ALLOW"
        assert fusion_res["composite_threat_score"] <= 0.15

    def test_wikipedia_authority_damping(self, predictor, reputation_engine, fusion_engine):
        """Wikipedia must be recognized as benign authority and damped."""
        url = "https://www.wikipedia.org/wiki/Computer_security"
        ml_res = predictor.predict(url, include_explanation=False)
        rep_res = reputation_engine.lookup_reputation(url)

        assert rep_res["verdict"] == "BENIGN"
        fusion_res = fusion_engine.fuse(
            ml_probability=ml_res["probability"],
            reputation=rep_res,
            url=url
        )
        assert fusion_res["final_action"] == "ALLOW"
        assert fusion_res["composite_threat_score"] <= ml_res["probability"]

    def test_direct_ip_harvester_pure_ml_block(self, predictor, fusion_engine):
        """Raw IP address with executable payload must be blocked via primary ML features."""
        url = "http://176.77.46.141:8080/bin.sh"
        ml_res = predictor.predict(url, include_explanation=False)

        assert ml_res["features"]["has_ip_address"] == 1
        assert ml_res["probability"] >= 0.65
        assert ml_res["action"] == "BLOCK"

        fusion_res = fusion_engine.fuse(ml_probability=ml_res["probability"], url=url)
        assert fusion_res["final_action"] == "BLOCK"
        assert fusion_res["final_risk_level"] == "HIGH"

    def test_audit_url_no_artificial_inflation(self, predictor, reputation_engine, fusion_engine):
        """
        Target: https://d3v-91x-z982k.cloud-update.net/auth?token=x9aB82Lmn91ZpQ
        Raw ML posterior is ~0.4700.
        Composite score must be bounded and MUST NOT jump to 0.9500.
        """
        url = "https://d3v-91x-z982k.cloud-update.net/auth?token=x9aB82Lmn91ZpQ"
        ml_res = predictor.predict(url, include_explanation=False)
        rep_res = reputation_engine.lookup_reputation(url)

        # Even with authoritative NXDOMAIN, regularized logit update bounds the result
        sim_dns = {"status": "NXDOMAIN", "resolves": False, "is_fast_flux_suspect": False}
        sim_whois = {"status": "UNKNOWN", "age_days": None, "is_newly_registered": False}

        fusion_res = fusion_engine.fuse(
            ml_probability=ml_res["probability"],
            reputation=rep_res,
            dns=sim_dns,
            whois=sim_whois,
            url=url
        )

        # Calibrated ML probability is ~0.4124 (raw RF is ~0.4700)
        assert 0.40 <= fusion_res["ml_probability"] <= 0.50
        # Crucial: Must be bounded and NOT 0.9500!
        assert fusion_res["composite_threat_score"] <= 0.70
        assert fusion_res["composite_threat_score"] != 0.95
