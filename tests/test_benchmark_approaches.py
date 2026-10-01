"""
Unit tests for detection paradigms benchmark suite
"""

import pytest
from src.evaluation.benchmark_approaches import ApproachesBenchmark


def test_benchmark_runs_successfully():
    benchmark = ApproachesBenchmark(dataset_path="data/processed/urls.csv")
    results = benchmark.run_benchmark()

    assert len(results) == 4
    for r in results:
        assert "paradigm" in r
        assert 0.0 <= r["accuracy"] <= 1.0
        assert 0.0 <= r["precision"] <= 1.0
        assert 0.0 <= r["recall"] <= 1.0
        assert 0.0 <= r["zero_day_recall"] <= 1.0
        assert r["avg_latency_ms"] >= 0.0


def test_blacklist_zero_day_recall_is_zero():
    benchmark = ApproachesBenchmark(dataset_path="data/processed/urls.csv")
    results = benchmark.run_benchmark()

    # Blacklist should have 0% zero-day recall by design
    blacklist_res = next(r for r in results if "Blacklist" in r["paradigm"])
    assert blacklist_res["zero_day_recall"] == 0.0


def test_hybrid_outperforms_single_methods():
    benchmark = ApproachesBenchmark(dataset_path="data/processed/urls.csv")
    results = benchmark.run_benchmark()

    hybrid_res = next(r for r in results if "Hybrid" in r["paradigm"])
    blacklist_res = next(r for r in results if "Blacklist" in r["paradigm"])
    heuristic_res = next(r for r in results if "Heuristic" in r["paradigm"])

    # Hybrid should yield higher overall accuracy and recall than single heuristic/blacklist
    assert hybrid_res["accuracy"] > blacklist_res["accuracy"]
    assert hybrid_res["accuracy"] > heuristic_res["accuracy"]
    assert hybrid_res["recall"] > heuristic_res["recall"]
