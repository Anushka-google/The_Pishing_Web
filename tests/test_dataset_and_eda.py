"""
Unit tests for Phase 3: Dataset Ingestion and Exploratory Data Analysis (EDA)
"""

import os
import pytest
from src.preprocessing.dataset_builder import URLDatasetPipeline
from src.preprocessing.eda import DataExplorer


@pytest.fixture
def sample_records():
    phishing = [
        {"url": "http://192.168.1.1/login.php", "label": 1, "source": "PhishTank"},
        {"url": "https://paypal-verify-account.xyz/auth", "label": 1, "source": "PhishTank"},
        {"url": "http://192.168.1.1/login.php", "label": 1, "source": "PhishTank"}  # Duplicate
    ]
    legit = [
        {"url": "https://google.com/search?q=cybersecurity", "label": 0, "source": "Tranco"},
        {"url": "https://github.com/explore", "label": 0, "source": "Tranco"}
    ]
    return phishing, legit


def test_pipeline_deduplication_and_cleaning(sample_records, tmp_path):
    phishing, legit = sample_records
    pipeline = URLDatasetPipeline(
        raw_phishing_dir=str(tmp_path / "raw_p"),
        raw_legitimate_dir=str(tmp_path / "raw_l"),
        processed_dir=str(tmp_path / "proc"),
        output_filename="test_urls.csv"
    )

    clean_records, metrics = pipeline.process_records(phishing, legit)

    # 1 duplicate dropped from phishing
    assert metrics["exact_duplicates_removed"] == 1
    assert metrics["final_phishing"] == 2
    assert metrics["final_legitimate"] == 2
    assert metrics["total_processed"] == 4

    out_file = pipeline.save_processed(clean_records)
    assert os.path.exists(out_file)


def test_data_explorer_metrics():
    explorer = DataExplorer("data/processed/urls.csv")
    report = explorer.run_full_eda()

    # Check key dimensions
    assert report["class_distribution"]["total_records"] > 0
    assert report["class_distribution"]["phishing_count"] > 0
    assert report["class_distribution"]["legitimate_count"] > 0

    # Check structural & length analysis
    assert "url_length" in report["length_distributions"]
    assert "dot_count_mean" in report["structural_distributions"]
    assert "data_leakage_and_domains" in report
    assert "keyword_signals" in report
    assert report["data_leakage_and_domains"]["unique_phishing_domains"] > 0
