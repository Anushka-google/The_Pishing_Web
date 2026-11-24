"""
PhishIntel — Feature #2 Verification & Latency Benchmark Tool
Validates the 22-Dimensional Structural, Lexical & Entropy Feature Extraction Engine.
"""

import os
import sys
import time
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.features.extractor import FeatureExtractor


def verify_feature_engineering():
    print("=" * 80)
    print("  PHISHINTEL: 22-DIMENSIONAL FEATURE EXTRACTION VERIFICATION")
    print("=" * 80)

    ext = FeatureExtractor()

    # 1. Feature Catalog Categories
    print("\n[+] FEATURE CATEGORIES IN 22-DIMENSIONAL VECTOR:")
    print("  1. Length Features (4)     : url_length, domain_length, path_length, query_length")
    print("  2. Delimiter Frequencies (7): dots, hyphens, slashes, digits, question marks, equals, special chars")
    print("  3. Adversarial Flags (5)   : has_ip_address, uses_https, is_punycode, has_port, has_query")
    print("  4. Lexical Signals (2)     : suspicious_keyword_count, brand_in_subdomain")
    print("  5. Information Entropy (2) : url_entropy, domain_entropy (Shannon H = -sum(p * log2(p)))")
    print("  6. Advanced Extension Flags: has_at_symbol, path_entropy, digit_ratio")

    # 2. Test 3 Characteristic Attack Vectors
    test_cases = [
        ("HOMOGRAPH ATTACK (Punycode Spoofing)", "https://xn--pple-43d.com/auth/login"),
        ("RAW IP + CREDENTIAL REDIRECTION (@)", "http://google.com@176.77.46.141:8080/bin.sh?session=38291"),
        ("SUBDOMAIN BRAND EVASION", "https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284"),
        ("BENIGN HARD-NEGATIVE (Google Auth)", "https://accounts.google.com/signin/v2/identifier")
    ]

    print("\n" + "-" * 80)
    print("  TEST CASES: EXTRACTION DECOMPOSITION")
    print("-" * 80)

    for title, url in test_cases:
        feats = ext.extract_features_dict(url)
        print(f"\nTarget: {title}")
        print(f"URL   : {url}")
        print(f"  • is_punycode              : {feats.get('is_punycode')} (Punycode Homograph Detected: {'YES' if feats.get('is_punycode')==1 else 'NO'})")
        print(f"  • has_ip_address           : {feats.get('has_ip_address')} (Raw IPv4 Hostname Detected: {'YES' if feats.get('has_ip_address')==1 else 'NO'})")
        print(f"  • brand_in_subdomain       : {feats.get('brand_in_subdomain')} (Brand Spoofed in Subdomain: {'YES' if feats.get('brand_in_subdomain')==1 else 'NO'})")
        print(f"  • url_entropy (Shannon H)  : {feats.get('url_entropy'):.4f} bits/symbol")
        print(f"  • domain_entropy           : {feats.get('domain_entropy'):.4f} bits/symbol")
        print(f"  • number_of_subdomains     : {feats.get('number_of_subdomains')}")
        print(f"  • suspicious_keywords      : {feats.get('suspicious_keyword_count')}")

    # 3. Microsecond Latency Benchmark
    print("\n" + "-" * 80)
    print("  LATENCY BENCHMARK: 1,000 REAL EXTRACTIONS")
    print("-" * 80)
    
    benchmark_urls = [tc[1] for tc in test_cases]
    # Warmup
    for u in benchmark_urls:
        ext.extract_features_dict(u)

    latencies = []
    for _ in range(250):
        for u in benchmark_urls:
            t0 = time.perf_counter()
            ext.extract_features_dict(u)
            latencies.append((time.perf_counter() - t0) * 1000)

    p50 = np.median(latencies)
    p95 = np.percentile(latencies, 95)
    mean = np.mean(latencies)
    min_lat = np.min(latencies)

    print(f"  Total Extraction Runs : {len(latencies):,}")
    print(f"  Median Latency (P50)  : {p50:.4f} ms")
    print(f"  Mean Latency          : {mean:.4f} ms")
    print(f"  P95 Latency           : {p95:.4f} ms")
    print(f"  Min Observed Latency  : {min_lat:.4f} ms")
    print(f"  Target Latency SLA    : < 2.0000 ms (Met: {'YES' if p95 < 2.0 else 'NO'})")
    print("=" * 80)


if __name__ == "__main__":
    verify_feature_engineering()
