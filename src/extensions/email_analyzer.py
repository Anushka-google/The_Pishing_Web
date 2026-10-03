"""
Phishing Detection & Risk Intelligence Platform
Phase 29.4: Multi-Modal Email Phishing Detection Layer

Architecture (Roadmap Specification):
Email
■■■ Subject
■■■ Body
■■■ Links
■■■ Sender information
 ↓
URL + text + sender features
 ↓
Risk model

Roadmap Directive:
"Do not build email phishing detection in version 1. First make URL detection reliable."
This module operates as an advanced multi-modal extension that builds upon the
reliable Phase 1-27 URL prediction champion engine and domain reputation core.
"""

import os
import sys
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import tldextract

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.prediction.predict import ProductionPredictor
from src.extensions.reputation import DomainReputationEngine


class EmailRiskAnalyzer:
    """
    Multi-modal Email Phishing Analyzer combining:
    1. Extracted URL Risk Scoring (via reliable ProductionPredictor core)
    2. Sender Identity & Display Name Spoofing Verification
    3. NLP / Text Urgency & Credential Lure Classification
    4. Multi-Modal Evidence Fusion Model
    """
    URL_REGEX = re.compile(
        r'https?://[^\s<>"\',;]+|www\.[^\s<>"\',;]+',
        re.IGNORECASE
    )

    URGENCY_KEYWORDS = [
        "account suspended", "verify your account", "immediate action required",
        "within 24 hours", "unauthorized login", "security alert",
        "password expired", "unusual activity", "billing problem",
        "confirm identity", "wallet compromised", "urgent action"
    ]

    CREDENTIAL_LURES = [
        "password", "passcode", "pin", "social security", "credit card",
        "seed phrase", "private key", "banking login", "identity verification"
    ]

    HIGH_PROFILE_BRANDS = [
        "paypal", "google", "microsoft", "apple", "amazon", "chase",
        "bank of america", "wells fargo", "netflix", "metamask", "coinbase"
    ]

    FREE_EMAIL_PROVIDERS = {
        "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com", "aol.com"
    }

    def __init__(
        self,
        predictor: Optional[ProductionPredictor] = None,
        reputation_engine: Optional[DomainReputationEngine] = None
    ):
        self.predictor = predictor or ProductionPredictor(enable_shap=False)
        self.reputation_engine = reputation_engine or DomainReputationEngine()
        self.tld_extractor = tldextract.TLDExtract()

    def analyze_email(
        self,
        subject: str,
        body: str,
        sender_email: str,
        sender_display_name: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Executes complete multi-modal email phishing risk evaluation:
        Email Components -> Extracted Signals -> Unified Multi-Modal Risk Model
        """
        # 1. URL Extraction & Reliable ML Scoring
        extracted_urls = self._extract_urls(body)
        url_analyses = []
        max_url_prob = 0.0
        compromised_urls_count = 0

        for u in extracted_urls[:10]:  # Limit to first 10 URLs
            pred = self.predictor.predict(u, include_explanation=False)
            fused = self.reputation_engine.fuse_with_ml(pred["probability"], u)
            prob = fused["fused_probability"]

            if prob > max_url_prob:
                max_url_prob = prob
            if prob >= 0.50:
                compromised_urls_count += 1

            url_analyses.append({
                "url": u,
                "ml_probability": pred["probability"],
                "fused_probability": prob,
                "risk_level": fused["fused_risk_level"],
                "action": fused["fused_action"],
                "reputation_source": fused["reputation"]["source"]
            })

        # 2. Sender Identity & Spoofing Analysis
        sender_analysis = self._evaluate_sender(
            sender_email=sender_email,
            sender_display_name=sender_display_name or "",
            extracted_urls=extracted_urls,
            auth_headers=auth_headers or {}
        )

        # 3. Text & Lexical Urgency Analysis
        text_analysis = self._evaluate_text(subject=subject, body=body)

        # 4. Multi-Modal Risk Fusion Model
        # Weights: URL Risk = 0.50, Sender Anomaly = 0.30, Text Urgency = 0.20
        # If any embedded URL is confirmed high-risk phishing, URL risk dominates.
        url_score = max_url_prob
        sender_score = sender_analysis["sender_risk_score"]
        text_score = text_analysis["text_risk_score"]

        fused_score = (0.50 * url_score) + (0.30 * sender_score) + (0.20 * text_score)

        # Dominant escalation: if URL is HIGH (>= 0.85) or severe sender spoofing with urgency
        if url_score >= 0.85:
            fused_score = max(fused_score, url_score)
        elif sender_analysis["display_name_spoofing_detected"] and text_analysis["has_urgency_cue"]:
            fused_score = max(fused_score, 0.75)

        fused_score = round(min(1.0, max(0.0, fused_score)), 4)

        # Determine overall verdict
        if fused_score >= 0.65:
            overall_verdict = "PHISHING"
            risk_tier = "HIGH"
            recommendation = "Block email and quarantine embedded hyperlinks. High likelihood of credential theft."
        elif fused_score >= 0.40:
            overall_verdict = "SUSPICIOUS"
            risk_tier = "MEDIUM"
            recommendation = "Display security warning banner. Do not click links or disclose confidential credentials."
        else:
            overall_verdict = "LEGITIMATE"
            risk_tier = "LOW"
            recommendation = "Email conforms to standard communication baselines. Verified safe."

        return {
            "overall_verdict": overall_verdict,
            "overall_risk_score": fused_score,
            "risk_tier": risk_tier,
            "recommendation": recommendation,
            "multimodal_scores": {
                "url_risk_score": round(url_score, 4),
                "sender_risk_score": round(sender_score, 4),
                "text_risk_score": round(text_score, 4)
            },
            "url_analysis": {
                "total_urls_found": len(extracted_urls),
                "compromised_urls_count": compromised_urls_count,
                "highest_risk_url_score": round(max_url_prob, 4),
                "analyzed_urls": url_analyses
            },
            "sender_analysis": sender_analysis,
            "text_analysis": text_analysis
        }

    def _extract_urls(self, text: str) -> List[str]:
        """Extracts unique URLs from email body."""
        raw_matches = self.URL_REGEX.findall(text)
        cleaned = []
        for m in raw_matches:
            url = m.strip()
            if not url.startswith("http"):
                url = "https://" + url
            cleaned.append(url)
        return list(dict.fromkeys(cleaned))

    def _evaluate_sender(
        self,
        sender_email: str,
        sender_display_name: str,
        extracted_urls: List[str],
        auth_headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """Inspects sender email address, display name spoofing, and link alignment."""
        sender_clean = sender_email.strip().lower()
        sender_host = sender_clean.split("@")[-1] if "@" in sender_clean else sender_clean
        extracted_sender = self.tld_extractor(sender_host)
        sender_root = extracted_sender.registered_domain or sender_host

        flags = []
        risk_score = 0.0
        display_spoofing = False

        # 1. Display Name Spoofing Check
        # Example: Display name says "PayPal Support" but sender domain is "gmail.com" or "phish.xyz"
        display_lower = sender_display_name.lower()
        for brand in self.HIGH_PROFILE_BRANDS:
            if brand in display_lower and brand not in sender_root:
                flags.append(f"DISPLAY_NAME_SPOOFING: Display name claims '{brand}' but sender domain is '{sender_root}'.")
                risk_score += 0.55
                display_spoofing = True
                break

        # 2. Free Webmail used for Enterprise / Security alerts
        if sender_root in self.FREE_EMAIL_PROVIDERS:
            if any(term in display_lower for term in ["support", "security", "billing", "service", "admin"]):
                flags.append(f"FREE_MAIL_ENTERPRISE_MASQUERADE: Official notification claims sent from free mail provider ({sender_root}).")
                risk_score += 0.35

        # 3. Sender domain vs Destination Link Mismatch
        if extracted_urls:
            first_url_host = urlparse(extracted_urls[0]).hostname or ""
            target_root = self.tld_extractor(first_url_host).registered_domain
            if target_root and sender_root and target_root != sender_root and sender_root not in self.FREE_EMAIL_PROVIDERS:
                # E.g. email from legitimate corporate domain but links point to unrelated host
                flags.append(f"DOMAIN_MISMATCH: Sender domain '{sender_root}' differs from primary link target '{target_root}'.")
                risk_score += 0.20

        # 4. Authentication Headers (SPF/DKIM/DMARC)
        spf_status = auth_headers.get("Received-SPF", "").lower()
        dmarc_status = auth_headers.get("DMARC-Filter", "").lower()

        if "fail" in spf_status or "softfail" in spf_status:
            flags.append("SPF_AUTHENTICATION_FAILURE: Sender IP unauthorized by domain SPF policy.")
            risk_score += 0.30
        if "reject" in dmarc_status or "fail" in dmarc_status:
            flags.append("DMARC_POLICY_REJECT: DMARC alignment check failed.")
            risk_score += 0.35

        return {
            "sender_email": sender_email,
            "sender_domain": sender_root,
            "display_name": sender_display_name,
            "display_name_spoofing_detected": display_spoofing,
            "anomalies_detected": flags,
            "sender_risk_score": round(min(1.0, risk_score), 3)
        }

    def _evaluate_text(self, subject: str, body: str) -> Dict[str, Any]:
        """Analyzes subject line and body text for urgent psychological triggers and credential requests."""
        combined = f"{subject} {body}".lower()
        urgency_matches = [kw for kw in self.URGENCY_KEYWORDS if kw in combined]
        credential_matches = [lure for lure in self.CREDENTIAL_LURES if lure in combined]

        risk_score = 0.0
        if urgency_matches:
            risk_score += min(0.50, len(urgency_matches) * 0.15)
        if credential_matches:
            risk_score += min(0.50, len(credential_matches) * 0.15)

        return {
            "has_urgency_cue": len(urgency_matches) > 0,
            "has_credential_lure": len(credential_matches) > 0,
            "urgency_keywords_found": urgency_matches,
            "credential_keywords_found": credential_matches,
            "text_risk_score": round(min(1.0, risk_score), 3)
        }
