"""
Phishing Detection & Risk Intelligence Platform
End-to-End Dataset Ingestion Pipeline Runner:
Raw sources -> Downloader -> Parser -> Cleaner -> Deduplicator -> Labeler -> Processed dataset
"""

import os
import logging
from typing import Dict, Any
from src.preprocessing.downloaders import PhishTankDownloader, URLhausDownloader, TrancoDownloader
from src.preprocessing.dataset_builder import URLDatasetPipeline

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def run_dataset_ingestion_pipeline(
    target_phishing: int = 5000,
    target_legitimate: int = 5000,
    output_csv: str = "data/processed/urls.csv"
) -> Dict[str, Any]:
    """
    Executes the 5-stage ingestion lifecycle:
    1. Downloader: Fetches raw data from PhishTank, URLhaus, and Tranco.
    2. Parser & Normalizer: Enforces valid URL schemes and structures.
    3. Cleaner: Drops malformed records and out-of-spec lengths.
    4. Deduplicator: Removes exact URL duplicates across sources.
    5. Labeler: Assigns binary labels and metadata, saving to processed storage.
    """
    logger.info("=== STEP 1: DOWNLOADING RAW DATA SOURCES ===")
    phishtank = PhishTankDownloader()
    urlhaus = URLhausDownloader()
    tranco = TrancoDownloader()

    # Split phishing acquisition between PhishTank and URLhaus
    pt_count = target_phishing // 2
    uh_count = target_phishing - pt_count

    pt_records = phishtank.fetch(max_records=pt_count)
    uh_records = urlhaus.fetch(max_records=uh_count)
    raw_phishing = pt_records + uh_records

    raw_legitimate = tranco.fetch(max_records=target_legitimate)

    logger.info(f"Raw Acquisition Complete: {len(raw_phishing)} phishing, {len(raw_legitimate)} legitimate.")

    logger.info("=== STEP 2-5: PARSING, CLEANING, DEDUPLICATING, AND LABELING ===")
    pipeline = URLDatasetPipeline(output_filename=os.path.basename(output_csv))
    clean_records, metrics = pipeline.process_records(raw_phishing, raw_legitimate)

    output_path = pipeline.save_processed(clean_records)
    logger.info(f"Ingestion Finished! Saved clean dataset to: {output_path}")

    return {
        "output_path": output_path,
        "metrics": metrics,
        "sources": {
            "PhishTank": len(pt_records),
            "URLhaus": len(uh_records),
            "Tranco": len(raw_legitimate)
        }
    }


if __name__ == "__main__":
    result = run_dataset_ingestion_pipeline(target_phishing=5000, target_legitimate=5000)
    print("\n--- INGESTION REPORT ---")
    print(f"Output File: {result['output_path']}")
    for k, v in result["metrics"].items():
        print(f"  {k}: {v}")
    print("Sources Breakdown:")
    for k, v in result["sources"].items():
        print(f"  {k}: {v}")
