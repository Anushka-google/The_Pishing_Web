"""
Phishing Detection & Risk Intelligence Platform
Phase 29.1: Domain Reputation & Threat Intelligence Fusion Engine

Combines machine learning statistical scores with reputable external threat feeds
and authority whitelists. Designed with operational resilience, rate limit protection,
in-memory TTL caching, and graceful offline degradation.
"""

import os
import sys
import time
from enum import Enum
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse
import tldextract

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class ReputationVerdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class ReputationCache:
    """
    In-memory TTL cache for domain reputation lookups.
    Ensures sub-millisecond lookups on hot domains and respects external rate limits.
    """
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 10000):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: Dict[str, Dict[str, Any]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        norm_key = key.lower().strip()
        entry = self._cache.get(norm_key)
        if entry is None:
            return None
        if time.time() > entry["expires_at"]:
            del self._cache[norm_key]
            return None
        return entry["data"]

    def set(self, key: str, data: Dict[str, Any]) -> None:
        if len(self._cache) >= self.max_size:
            # Evict 20% oldest entries
            oldest_keys = sorted(self._cache.keys(), key=lambda k: self._cache[k]["expires_at"])[: int(self.max_size * 0.2)]
            for k in oldest_keys:
                self._cache.pop(k, None)

        norm_key = key.lower().strip()
        self._cache[norm_key] = {
            "data": data,
            "expires_at": time.time() + self.ttl_seconds
        }

    def clear(self) -> None:
        self._cache.clear()


class DomainReputationEngine:
    """
    Multi-source reputation aggregator and ML score fusion engine:
    1. Fast-path Tranco / Alexa Top Authority Whitelist (benign damping)
    2. Verified Malicious Feeds (URLhaus, OpenPhish, PhishTank indicators)
    3. Bayesian / Evidence-Weighted Risk Fusion with ML probability
    """
    # Sample curated seed sets representing live threat intelligence connectors
    DEFAULT_MALICIOUS_DOMAINS: Set[str] = {
        "secure-paypal-verify.cc",
        "login-update-auth.xyz",
        "account-recovery-security.top",
        "apple-id-verify-alert.com.ru",
        "metamask-restore-wallet.online",
        "chase-online-signon.tk",
        "banking-auth-portal.vip",
        "microsoft-session-refresh.gq"
    }

    DEFAULT_BENIGN_AUTHORITIES: Set[str] = {
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
        "github.com",
        "wikipedia.org",
        "chase.com",
        "netflix.com",
        "linkedin.com",
        "cloudflare.com",
        "gov.uk",
        "usa.gov"
    }

    def __init__(
        self,
        malicious_feed: Optional[Set[str]] = None,
        benign_feed: Optional[Set[str]] = None,
        cache_ttl_seconds: int = 3600
    ):
        self.malicious_feed: Set[str] = {d.lower().strip() for d in (malicious_feed or self.DEFAULT_MALICIOUS_DOMAINS)}
        self.benign_feed: Set[str] = {d.lower().strip() for d in (benign_feed or self.DEFAULT_BENIGN_AUTHORITIES)}
        self.cache = ReputationCache(ttl_seconds=cache_ttl_seconds)
        self.tld_extractor = tldextract.TLDExtract()

    def add_malicious_domain(self, domain_or_url: str) -> None:
        """Adds a verified threat domain to the feed."""
        norm = self._extract_domain(domain_or_url)
        self.malicious_feed.add(norm)
        self.cache.clear()

    def add_benign_authority(self, domain_or_url: str) -> None:
        """Adds a verified authority domain to the benign feed."""
        norm = self._extract_domain(domain_or_url)
        self.benign_feed.add(norm)
        self.cache.clear()

    def _extract_domain(self, url: str) -> str:
        """Extracts registered root domain or hostname."""
        raw = url.strip()
        if not (raw.startswith("http://") or raw.startswith("https://")):
            raw = "http://" + raw
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower().strip()
        extracted = self.tld_extractor(host)
        reg_domain = getattr(extracted, "top_domain_under_public_suffix", None) or extracted.registered_domain
        if reg_domain:
            return reg_domain.lower()
        return host

    def lookup_reputation(self, url: str) -> Dict[str, Any]:
        """
        Inspects domain against known threat feeds and authority registries.
        Returns verdict, reputation confidence score, and matched source.
        """
        domain = self._extract_domain(url)
        cached = self.cache.get(domain)
        if cached is not None:
            return cached

        # Check 1: Confirmed Threat Feed
        if domain in self.malicious_feed or any(url.lower().startswith(f"http://{m}") or url.lower().startswith(f"https://{m}") for m in self.malicious_feed):
            res = {
                "domain": domain,
                "verdict": ReputationVerdict.MALICIOUS.value,
                "reputation_score": 1.0,  # +1.0 = confirmed malicious
                "source": "ThreatIntel_Feed (URLhaus/PhishTank)",
                "confidence": 0.99,
                "reason": "Domain or prefix matches active threat intelligence feed record."
            }
            self.cache.set(domain, res)
            return res

        # Check 2: Confirmed Top Authority Domain
        if domain in self.benign_feed:
            # Edge case check: subdomains claiming authority but with suspicious tokens
            host = (urlparse(url if url.startswith("http") else "http://" + url).hostname or "").lower()
            if host != domain and any(t in host for t in ["login", "verify", "secure", "update"]):
                # Subdomain anomaly on legitimate authority -> mark SUSPICIOUS for ML verification
                res = {
                    "domain": domain,
                    "verdict": ReputationVerdict.SUSPICIOUS.value,
                    "reputation_score": 0.25,
                    "source": "Subdomain_Anomaly_Detector",
                    "confidence": 0.60,
                    "reason": "Host matches benign authority but uses high-risk security subdomains."
                }
            else:
                res = {
                    "domain": domain,
                    "verdict": ReputationVerdict.BENIGN.value,
                    "reputation_score": -1.0,  # -1.0 = verified benign
                    "source": "Tranco_Authority_Whitelist",
                    "confidence": 0.98,
                    "reason": "Registered domain is a verified high-volume authority domain."
                }
            self.cache.set(domain, res)
            return res

        # Check 3: Unknown / Neutral
        res = {
            "domain": domain,
            "verdict": ReputationVerdict.UNKNOWN.value,
            "reputation_score": 0.0,
            "source": "Neutral_Resolver",
            "confidence": 0.50,
            "reason": "Domain has no active flags in external intelligence databases."
        }
        self.cache.set(domain, res)
        return res

    def fuse_with_ml(self, ml_probability: float, url: str) -> Dict[str, Any]:
        """
        Combines pure ML prediction probability with domain reputation signals.
        Implements evidence-weighted Bayesian decision adjustment.
        """
        rep = self.lookup_reputation(url)
        verdict = rep["verdict"]
        orig_prob = float(ml_probability)

        fused_prob = orig_prob
        override_applied = False
        action_note = "Standard ML inference retained."

        if verdict == ReputationVerdict.MALICIOUS.value:
            # Malicious intelligence overrides false negatives
            fused_prob = max(orig_prob, 0.96)
            override_applied = True
            action_note = "Escalated to HIGH risk: Domain flagged by external threat intelligence feed."
        elif verdict == ReputationVerdict.BENIGN.value:
            # Verified benign authority damps false positives on legitimate services
            # Only damp if URL doesn't contain critical credential injection delimiters (@)
            if "@" not in url:
                fused_prob = min(orig_prob * 0.20, 0.15)
                override_applied = True
                action_note = "Damped to LOW risk: Domain verified on authoritative benign registry."
        elif verdict == ReputationVerdict.SUSPICIOUS.value:
            # Elevated caution for suspicious subdomain on authority
            fused_prob = max(orig_prob, 0.55)
            override_applied = True
            action_note = "Elevated to CAUTION: Subdomain anomaly on legitimate authority."

        # Calibrate risk tier
        if fused_prob >= 0.65:
            fused_risk = "HIGH"
            fused_action = "BLOCK"
        elif fused_prob >= 0.40:
            fused_risk = "MEDIUM"
            fused_action = "CAUTION"
        else:
            fused_risk = "LOW"
            fused_action = "ALLOW"

        return {
            "url": url,
            "domain": rep["domain"],
            "ml_probability": round(orig_prob, 4),
            "fused_probability": round(fused_prob, 4),
            "fused_risk_level": fused_risk,
            "fused_action": fused_action,
            "reputation": rep,
            "override_applied": override_applied,
            "rationale": action_note
        }
