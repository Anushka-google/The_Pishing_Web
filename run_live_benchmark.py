"""
Interactive Live Benchmark Runner
Run this directly to see the real-time calculations with your own eyes!
"""

import time
import pandas as pd
import numpy as np
from src.prediction.mvp_pipeline import MVPPhishingPipeline, RiskLevel
from src.prediction.hybrid_engine import HybridRiskEngine, BlacklistStore, HeuristicRuleEngine

def run_live():
    print("=" * 70)
    print("  LIVE PHISHING DETECTION BENCHMARK (9,450 REAL URLs)")
    print("=" * 70)

    dataset_path = "data/processed/urls.csv"
    print(f"\n[1/4] Loading dataset: {dataset_path} ...")
    df = pd.read_csv(dataset_path)
    total_urls = len(df)
    phish_count = len(df[df["label"] == 1])
    legit_count = len(df[df["label"] == 0])

    print(f"      Total URLs loaded : {total_urls:,}")
    print(f"      Phishing URLs (1) : {phish_count:,}")
    print(f"      Legitimate URLs (0): {legit_count:,}")

    # Set up simulated zero-day holdout
    phish_urls = df[df["label"] == 1]["url"].tolist()
    split_idx = len(phish_urls) // 2
    known_blacklist = set(phish_urls[:split_idx])
    zero_day_phish = set(phish_urls[split_idx:])
    print(f"\n[2/4] Simulating Zero-Day Threat Split:")
    print(f"      Known Blacklist URLs  : {len(known_blacklist):,}")
    print(f"      Unseen Zero-Day URLs  : {len(zero_day_phish):,}")

    # Initialize Hybrid Engine
    blacklist_store = BlacklistStore(known_blacklist)
    heuristic_engine = HeuristicRuleEngine()
    ml_pipeline = MVPPhishingPipeline()
    hybrid_engine = HybridRiskEngine(
        ml_pipeline=ml_pipeline,
        blacklist=blacklist_store,
        heuristics=heuristic_engine
    )

    print(f"\n[3/4] Running Live Inference on all {total_urls:,} URLs...")
    t_start = time.perf_counter()

    tp, fp, tn, fn = 0, 0, 0, 0
    zero_day_caught = 0
    urls = df["url"].tolist()
    labels = df["label"].tolist()

    # Progress reporting intervals
    step = total_urls // 5
    for i, (url, label) in enumerate(zip(urls, labels), 1):
        res = hybrid_engine.analyze(url)
        is_pred_phish = (res.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM)) and (res.probability >= 0.40)

        if label == 1 and is_pred_phish:
            tp += 1
            if url in zero_day_phish:
                zero_day_caught += 1
        elif label == 0 and is_pred_phish:
            fp += 1
        elif label == 0 and not is_pred_phish:
            tn += 1
        elif label == 1 and not is_pred_phish:
            fn += 1

        if i % step == 0 or i == total_urls:
            pct = (i / total_urls) * 100
            print(f"      Progress: {i:,}/{total_urls:,} URLs analyzed ({pct:.0f}%) ...")

    total_time_sec = time.perf_counter() - t_start
    avg_latency_ms = (total_time_sec / total_urls) * 1000

    accuracy = (tp + tn) / total_urls * 100
    precision = tp / max(1, (tp + fp)) * 100
    recall = tp / max(1, (tp + fn)) * 100
    zero_day_recall = zero_day_caught / len(zero_day_phish) * 100

    print("\n" + "=" * 70)
    print("  LIVE RESULTS MEASURED ON YOUR COMPUTER")
    print("=" * 70)
    print(f"  Total Execution Time  : {total_time_sec:.3f} seconds for {total_urls:,} URLs")
    print(f"  Average Latency / URL : {avg_latency_ms:.4f} ms ({avg_latency_ms * 1000:.1f} microseconds)")
    print("-" * 70)
    print(f"  CONFUSION MATRIX:")
    print(f"    True Positives  (TP) : {tp:,}  (Phishing correctly blocked)")
    print(f"    True Negatives  (TN) : {tn:,}  (Safe sites allowed)")
    print(f"    False Positives (FP) : {fp:,}  (False alarms on safe sites)")
    print(f"    False Negatives (FN) : {fn:,}  (Phishing links missed)")
    print("-" * 70)
    print(f"  FINAL METRICS:")
    print(f"    Accuracy         : {accuracy:.2f}%  (({tp} + {tn}) / {total_urls})")
    print(f"    Precision        : {precision:.2f}%  ({tp} / ({tp} + {fp}))")
    print(f"    Overall Recall   : {recall:.2f}%  ({tp} / ({tp} + {fn}))")
    print(f"    Zero-Day Recall  : {zero_day_recall:.2f}%  ({zero_day_caught} / {len(zero_day_phish)})")
    print("=" * 70)

if __name__ == "__main__":
    run_live()
