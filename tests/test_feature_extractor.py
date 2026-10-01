"""
Unit tests for FeatureExtractor (Phase 6 & 7)
"""

import pytest
import numpy as np
import pandas as pd
from src.features.extractor import FeatureExtractor, calculate_shannon_entropy


@pytest.fixture
def extractor():
    return FeatureExtractor()


def test_shannon_entropy_math():
    assert calculate_shannon_entropy("") == 0.0
    # Single repeating character has zero unpredictability
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # 4 distinct characters equally distributed: -4 * (0.25 * log2(0.25)) = 2.0
    assert calculate_shannon_entropy("abcd") == 2.0


def test_feature_extractor_schema(extractor):
    assert len(extractor.FEATURE_NAMES) == 22
    url = "https://login.paypal.com.account-update.xyz/verify?token=123#sec"
    feat_dict = extractor.extract_features_dict(url)

    for name in extractor.FEATURE_NAMES:
        assert name in feat_dict
        assert isinstance(feat_dict[name], (int, float))


def test_extract_features_vector(extractor):
    url = "https://google.com/search?q=security"
    vector = extractor.extract_features_vector(url)

    assert isinstance(vector, np.ndarray)
    assert vector.shape == (22,)
    assert vector.dtype == np.float32


def test_phishing_feature_signals(extractor):
    # IP host + port + brand in subdomain + keywords
    url = "http://paypal.portal.192.168.1.1:8080/bank/login/verify?user=victim"
    f = extractor.extract_features_dict(url)

    assert f["has_port"] == 1
    assert f["has_ip_address"] == 1
    assert f["brand_in_subdomain"] == 1
    assert f["suspicious_keyword_count"] >= 3
    assert f["uses_https"] == 0
    assert f["url_entropy"] > 3.0


def test_batch_extract(extractor):
    urls = [
        "https://google.com",
        "https://github.com/explore",
        "http://phishing-site.xyz/login"
    ]
    df = extractor.batch_extract(urls)

    assert isinstance(df, pd.DataFrame)
    assert len(df) == 3
    assert list(df.columns) == extractor.FEATURE_NAMES
