"""
Phishing Detection & Risk Intelligence Platform
Phase 25: Performance Measurement & Subsystem Latency Profiler

Empirically benchmarks and profiles actual system performance across:
1. Feature extraction time
2. Model inference time
3. Database latency
4. API response time

Provides bottleneck detection and statistical analysis (mean, p50, p90, p95, p99).
"""

import os
import json
import time
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.features.extractor import FeatureExtractor
from src.prediction.predict import ProductionPredictor
from database.models import Base, PredictionRecord
from database.repository import PredictionRepository


BENCHMARK_SAMPLE_URLS = [
    # Legitimate popular and enterprise domains
    "https://www.google.com/search?q=machine+learning+security",
    "https://github.com/torvalds/linux/blob/master/README.md",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://aws.amazon.com/security/products",
    "https://stackoverflow.com/questions/tagged/python",
    "https://apple.com/support/system-status",
    "https://microsoft.com/en-us/security",
    "https://cloudflare.com/learning/security/what-is-phishing",
    # Phishing patterns: IP-based, deep subdomains, suspicious tokens, credential lures
    "http://192.168.1.100/login/update/account-verification.php?token=xyz",
    "https://secure-login.paypal.com.account-update.xyz/verify/signin.html",
    "http://chase.online-security-banking.alert-99.top/auth/signin?sess=8812",
    "https://netflix.account-billing-reactivation.co/renew?id=992817",
    "http://wellsfargo.verification-center.secure-bank.cc/customer/auth",
    "https://appleid.apple.com-verify-account.info/auth?ref=alert",
    "http://secure-update-bankofamerica.net/online/login.jsp",
    "https://dhl-express-tracking-package-delivery.online/portal?code=4402"
]


def identify_bottleneck(
    feature_extraction_ms: float,
    model_inference_ms: float,
    database_latency_ms: float,
    api_response_time_ms: float
) -> Dict[str, Any]:
    """
    Identifies the primary bottleneck subsystem by computing relative latency contributions.
    """
    total = max(api_response_time_ms, feature_extraction_ms + model_inference_ms + database_latency_ms)
    if total <= 0:
        return {
            "bottleneck": "NONE",
            "bottleneck_share_pct": 0.0,
            "components": {}
        }

    feat_share = (feature_extraction_ms / total) * 100.0
    inf_share = (model_inference_ms / total) * 100.0
    db_share = (database_latency_ms / total) * 100.0
    overhead_ms = max(0.0, total - (feature_extraction_ms + model_inference_ms + database_latency_ms))
    overhead_share = (overhead_ms / total) * 100.0

    components = {
        "FEATURE_EXTRACTION": {
            "latency_ms": round(feature_extraction_ms, 3),
            "share_pct": round(feat_share, 1)
        },
        "MODEL_INFERENCE": {
            "latency_ms": round(model_inference_ms, 3),
            "share_pct": round(inf_share, 1)
        },
        "DATABASE_LATENCY": {
            "latency_ms": round(database_latency_ms, 3),
            "share_pct": round(db_share, 1)
        },
        "PIPELINE_OVERHEAD": {
            "latency_ms": round(overhead_ms, 3),
            "share_pct": round(overhead_share, 1)
        }
    }

    # Find the largest component
    primary = max(
        [
            ("FEATURE_EXTRACTION", feature_extraction_ms),
            ("MODEL_INFERENCE", model_inference_ms),
            ("DATABASE_LATENCY", database_latency_ms),
            ("PIPELINE_OVERHEAD", overhead_ms)
        ],
        key=lambda x: x[1]
    )

    primary_name = primary[0]
    primary_share = (primary[1] / total) * 100.0

    return {
        "bottleneck": primary_name,
        "bottleneck_share_pct": round(primary_share, 1),
        "components": components
    }


def compute_distribution_stats(latencies: List[float]) -> Dict[str, float]:
    """Computes mean, median (p50), p90, p95, p99, min, max, and std."""
    if not latencies:
        return {
            "mean_ms": 0.0,
            "median_p50_ms": 0.0,
            "p90_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
            "std_ms": 0.0
        }
    arr = np.array(latencies, dtype=np.float64)
    return {
        "mean_ms": round(float(np.mean(arr)), 3),
        "median_p50_ms": round(float(np.percentile(arr, 50)), 3),
        "p90_ms": round(float(np.percentile(arr, 90)), 3),
        "p95_ms": round(float(np.percentile(arr, 95)), 3),
        "p99_ms": round(float(np.percentile(arr, 99)), 3),
        "min_ms": round(float(np.min(arr)), 3),
        "max_ms": round(float(np.max(arr)), 3),
        "std_ms": round(float(np.std(arr)), 3)
    }


class SystemPerformanceProfiler:
    """
    Measures empirical performance across all 4 production subsystems.
    """
    def __init__(
        self,
        db_url: str = "sqlite:///:memory:",
        predictor: Optional[ProductionPredictor] = None
    ):
        self.db_engine = create_engine(db_url, connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=self.db_engine)
        self.SessionFactory = sessionmaker(bind=self.db_engine)

        if predictor is not None:
            self.predictor = predictor
        else:
            self.predictor = ProductionPredictor(enable_shap=False)

    def benchmark_subsystems(
        self,
        urls: Optional[List[str]] = None,
        iterations: int = 100,
        warmup_runs: int = 10
    ) -> Dict[str, Any]:
        """
        Executes empirical benchmarking by measuring each subsystem across iterations.
        """
        test_urls = urls or BENCHMARK_SAMPLE_URLS

        # Warmup phase (JIT, disk caching, parser warm-up)
        for _ in range(warmup_runs):
            dummy_u = test_urls[0]
            self.predictor.predict(dummy_u, include_explanation=False)

        feat_times: List[float] = []
        inf_times: List[float] = []
        db_times: List[float] = []
        total_pipeline_times: List[float] = []
        bottleneck_counts: Dict[str, int] = {
            "FEATURE_EXTRACTION": 0,
            "MODEL_INFERENCE": 0,
            "DATABASE_LATENCY": 0,
            "PIPELINE_OVERHEAD": 0
        }

        num_urls = len(test_urls)
        for i in range(iterations):
            url = test_urls[i % num_urls]

            # Measure end-to-end pipeline
            t_total_0 = time.perf_counter()

            # 1. Feature Extraction Time (explicit isolation)
            t_feat_0 = time.perf_counter()
            features = self.predictor.extractor.extract_features_dict(url)
            vector = np.array([features[name] for name in self.predictor.feature_names], dtype=np.float32).reshape(1, -1)
            t_feat_1 = time.perf_counter()
            feat_ms = (t_feat_1 - t_feat_0) * 1000.0

            # 2. Model Inference Time (explicit isolation)
            if self.predictor.scaler is not None:
                scaled = self.predictor.scaler.transform(vector)
                X = pd.DataFrame(scaled, columns=self.predictor.feature_names)
            else:
                X = pd.DataFrame(vector, columns=self.predictor.feature_names)

            t_inf_0 = time.perf_counter()
            proba = float(self.predictor.model.predict_proba(X)[0, 1])
            t_inf_1 = time.perf_counter()
            inf_ms = (t_inf_1 - t_inf_0) * 1000.0

            prediction_label = "phishing" if proba >= self.predictor.t_optimal else "legitimate"
            risk_level = "HIGH" if proba >= self.predictor.t2_high else ("MEDIUM" if proba >= self.predictor.t1_low else "LOW")

            # 3. Database Latency (isolated write & flush)
            db_session = self.SessionFactory()
            try:
                t_db_0 = time.perf_counter()
                rec = PredictionRepository.create_record(
                    db=db_session,
                    url=url,
                    prediction=prediction_label,
                    probability=proba,
                    risk_level=risk_level,
                    model_version=self.predictor.model_version
                )
                t_db_1 = time.perf_counter()
                db_ms = (t_db_1 - t_db_0) * 1000.0
            finally:
                db_session.close()

            t_total_1 = time.perf_counter()
            total_ms = (t_total_1 - t_total_0) * 1000.0

            feat_times.append(feat_ms)
            inf_times.append(inf_ms)
            db_times.append(db_ms)
            total_pipeline_times.append(total_ms)

            # Identify bottleneck for this execution
            b_info = identify_bottleneck(feat_ms, inf_ms, db_ms, total_ms)
            bottleneck_counts[b_info["bottleneck"]] += 1

        # Calculate distributions
        stats_feat = compute_distribution_stats(feat_times)
        stats_inf = compute_distribution_stats(inf_times)
        stats_db = compute_distribution_stats(db_times)
        stats_total = compute_distribution_stats(total_pipeline_times)

        # Global bottleneck analysis
        overall_bottleneck = identify_bottleneck(
            stats_feat["mean_ms"],
            stats_inf["mean_ms"],
            stats_db["mean_ms"],
            stats_total["mean_ms"]
        )

        bottleneck_distribution = {
            k: round((v / iterations) * 100.0, 1)
            for k, v in bottleneck_counts.items()
        }

        report = {
            "metadata": {
                "iterations": iterations,
                "warmup_runs": warmup_runs,
                "model_version": self.predictor.model_version,
                "model_name": self.predictor.model_name,
                "feature_count": len(self.predictor.feature_names)
            },
            "subsystems": {
                "feature_extraction": stats_feat,
                "model_inference": stats_inf,
                "database_latency": stats_db,
                "api_response_time": stats_total
            },
            "bottleneck_analysis": {
                "primary_bottleneck": overall_bottleneck["bottleneck"],
                "primary_bottleneck_share_pct": overall_bottleneck["bottleneck_share_pct"],
                "component_shares": overall_bottleneck["components"],
                "occurrence_distribution_pct": bottleneck_distribution
            },
            "sla_compliance": {
                "target_p95_ms": 50.0,
                "measured_p95_ms": stats_total["p95_ms"],
                "sla_met": stats_total["p95_ms"] < 50.0
            }
        }
        return report

    def save_report(
        self,
        report: Dict[str, Any],
        output_path: str = "data/processed/performance_metrics.json"
    ):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)


def run_profiler():
    print("=" * 70)
    print("RUNNING PHASE 25 PERFORMANCE PROFILER & SUBSYSTEM BENCHMARK")
    print("=" * 70)
    profiler = SystemPerformanceProfiler()
    report = profiler.benchmark_subsystems(iterations=150, warmup_runs=15)
    profiler.save_report(report)

    sub = report["subsystems"]
    b = report["bottleneck_analysis"]

    print(f"\nSubsystem Benchmark Summary ({report['metadata']['iterations']} iterations):")
    print(f"  - Feature Extraction:  mean={sub['feature_extraction']['mean_ms']:>6.3f} ms | p95={sub['feature_extraction']['p95_ms']:>6.3f} ms")
    print(f"  - Model Inference:     mean={sub['model_inference']['mean_ms']:>6.3f} ms | p95={sub['model_inference']['p95_ms']:>6.3f} ms")
    print(f"  - Database Latency:    mean={sub['database_latency']['mean_ms']:>6.3f} ms | p95={sub['database_latency']['p95_ms']:>6.3f} ms")
    print(f"  - API Pipeline Total:  mean={sub['api_response_time']['mean_ms']:>6.3f} ms | p95={sub['api_response_time']['p95_ms']:>6.3f} ms")

    print(f"\nPrimary Bottleneck Identified:")
    print(f"  - Bottleneck: {b['primary_bottleneck']} ({b['primary_bottleneck_share_pct']}% of total latency)")
    sla_str = "[PASSED]" if report['sla_compliance']['sla_met'] else "[BREACHED]"
    print(f"  - SLA Status: {sla_str} (P95 {report['sla_compliance']['measured_p95_ms']}ms < 50ms)")
    print("=" * 70)
    return report


if __name__ == "__main__":
    run_profiler()
