"""
Phishing Detection & Risk Intelligence Platform
Phase 6 & 7: URL Feature Engineering & Reusable Feature Extractor
Extracts Length, Character, Structural, Lexical, and Shannon Entropy features.
Ensures zero training/serving skew between offline dataset training and online inference.
"""

import math
from collections import Counter
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd

from src.preprocessing.url_parser import URLParser, ParsedURL


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon character entropy: H(X) = - sum(p(x) * log2(p(x)))
    Measures unpredictability / randomness of character distributions.
    High entropy in domain/path indicates DGA (Domain Generation Algorithms) or obfuscated tokens.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(float(entropy), 4)


class FeatureExtractor:
    """
    Stateless, reusable feature extractor for URL security classification.
    Produces identical feature mappings during training and production inference.
    """
    SUSPICIOUS_KEYWORDS = [
        "login", "verify", "account", "security", "update",
        "password", "bank", "payment", "confirm", "wallet",
        "signin", "auth", "recover", "billing", "service"
    ]

    TARGET_BRANDS = [
        "paypal", "microsoft", "apple", "google", "chase",
        "netflix", "wellsfargo", "amazon", "facebook", "coinbase"
    ]

    # Deterministic, ordered feature schema
    FEATURE_NAMES: List[str] = [
        # 1. Length features
        "url_length",
        "domain_length",
        "path_length",
        "query_length",
        # 2. Character counts
        "number_of_digits",
        "number_of_dots",
        "number_of_hyphens",
        "number_of_slashes",
        "number_of_question_marks",
        "number_of_equals",
        "number_of_special_characters",
        # 3. Structural indicators
        "number_of_subdomains",
        "has_ip_address",
        "has_port",
        "has_fragment",
        "has_query",
        "uses_https",
        "is_punycode",
        # 4. Lexical signals
        "suspicious_keyword_count",
        "brand_in_subdomain",
        # 5. Information Entropy
        "url_entropy",
        "domain_entropy"
    ]

    def __init__(self, parser: Optional[URLParser] = None):
        self.parser = parser or URLParser()

    def extract_features_dict(self, raw_url: str) -> Dict[str, Any]:
        """
        Parses a URL and extracts a dictionary of named features.
        """
        parsed: ParsedURL = self.parser.parse(raw_url)
        url_str = parsed.normalized_url

        # 1. Length features
        url_length = len(url_str)
        domain_length = len(parsed.hostname)
        path_length = len(parsed.path)
        query_length = len(parsed.query)

        # 2. Character features
        number_of_digits = sum(c.isdigit() for c in url_str)
        number_of_dots = url_str.count(".")
        number_of_hyphens = url_str.count("-")
        number_of_slashes = url_str.count("/")
        number_of_question_marks = url_str.count("?")
        number_of_equals = url_str.count("=")
        special_chars = sum(1 for c in url_str if not c.isalnum() and c not in ("/", ":", ".", "-", "?", "=", "&", "#"))

        # 3. Structural features
        subdomain_parts = [p for p in parsed.subdomain.split(".") if p]
        number_of_subdomains = len(subdomain_parts)
        has_ip_address = 1 if parsed.is_ip else 0
        has_port = 1 if parsed.has_port else 0
        has_fragment = 1 if bool(parsed.fragment) else 0
        has_query = 1 if bool(parsed.query) else 0
        uses_https = 1 if parsed.scheme == "https" else 0
        is_punycode = 1 if parsed.is_punycode else 0

        # 4. Lexical features
        lowered_url = url_str.lower()
        suspicious_keyword_count = sum(1 for kw in self.SUSPICIOUS_KEYWORDS if kw in lowered_url)
        
        # Check brand name in subdomain (deceptive brand masquerading)
        subdomain_lower = parsed.subdomain.lower()
        brand_in_subdomain = 1 if any(b in subdomain_lower for b in self.TARGET_BRANDS) else 0

        # 5. Shannon Entropy
        url_entropy = calculate_shannon_entropy(url_str)
        domain_entropy = calculate_shannon_entropy(parsed.hostname)

        features = {
            "url_length": url_length,
            "domain_length": domain_length,
            "path_length": path_length,
            "query_length": query_length,
            "number_of_digits": number_of_digits,
            "number_of_dots": number_of_dots,
            "number_of_hyphens": number_of_hyphens,
            "number_of_slashes": number_of_slashes,
            "number_of_question_marks": number_of_question_marks,
            "number_of_equals": number_of_equals,
            "number_of_special_characters": special_chars,
            "number_of_subdomains": number_of_subdomains,
            "has_ip_address": has_ip_address,
            "has_port": has_port,
            "has_fragment": has_fragment,
            "has_query": has_query,
            "uses_https": uses_https,
            "is_punycode": is_punycode,
            "suspicious_keyword_count": suspicious_keyword_count,
            "brand_in_subdomain": brand_in_subdomain,
            "url_entropy": url_entropy,
            "domain_entropy": domain_entropy
        }
        return features

    def extract_features_vector(self, raw_url: str) -> np.ndarray:
        """
        Extracts features as a 1D NumPy array adhering strictly to FEATURE_NAMES ordering.
        """
        f_dict = self.extract_features_dict(raw_url)
        vector = [f_dict[name] for name in self.FEATURE_NAMES]
        return np.array(vector, dtype=np.float32)

    def batch_extract(self, urls: List[str]) -> pd.DataFrame:
        """
        Extracts features for a batch of URLs into a Pandas DataFrame.
        """
        rows = [self.extract_features_dict(u) for u in urls]
        return pd.DataFrame(rows, columns=self.FEATURE_NAMES)
