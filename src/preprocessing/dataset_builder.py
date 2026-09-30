"""
Phishing Detection & Risk Intelligence Platform
Dataset Engineering Pipeline: Ingestion, Normalization, Cleaning, Deduplication, and Labeling
Schema: url, label, source, collection_date
"""

import os
import re
import csv
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional, Set
from urllib.parse import urlparse
import tldextract


class URLDatasetPipeline:
    """
    Reproducible dataset pipeline managing raw downloads, normalization,
    cleaning, deduplication, domain analysis, and labeling.
    """
    def __init__(
        self,
        raw_phishing_dir: str = "data/raw/phishing",
        raw_legitimate_dir: str = "data/raw/legitimate",
        processed_dir: str = "data/processed",
        output_filename: str = "urls.csv"
    ):
        self.raw_phishing_dir = raw_phishing_dir
        self.raw_legitimate_dir = raw_legitimate_dir
        self.processed_dir = processed_dir
        self.output_path = os.path.join(processed_dir, output_filename)
        self.tld_extractor = tldextract.TLDExtract()

        os.makedirs(self.raw_phishing_dir, exist_ok=True)
        os.makedirs(self.raw_legitimate_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)

    def normalize_url(self, raw_url: str) -> Optional[str]:
        """
        Normalizes a URL string:
        - Strips whitespace
        - Lowercases scheme and netloc (preserving case in query/path if needed)
        - Prepend scheme if missing
        - Validates basic URL structure
        """
        if not raw_url or not isinstance(raw_url, str):
            return None
        cleaned = raw_url.strip()
        if len(cleaned) < 4 or len(cleaned) > 2048:
            return None

        # Fix missing scheme
        if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
            cleaned = "https://" + cleaned

        try:
            parsed = urlparse(cleaned)
            if not parsed.netloc:
                return None
            
            # Normalize scheme & netloc to lower case
            normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            if parsed.fragment:
                normalized += f"#{parsed.fragment}"
            return normalized
        except Exception:
            return None

    def extract_registered_domain(self, url: str) -> str:
        """Extracts registered domain (e.g. google.com, example.co.uk)"""
        try:
            ext = self.tld_extractor(url)
            domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
            if domain:
                return domain.lower()
            parsed = urlparse(url)
            return parsed.netloc.split(":")[0].lower()
        except Exception:
            return ""

    def process_records(
        self,
        phishing_records: List[Dict[str, str]],
        legitimate_records: List[Dict[str, str]]
    ) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
        """
        Cleans, validates, deduplicates, and labels records.
        """
        seen_urls: Set[str] = set()
        clean_rows: List[Dict[str, str]] = []
        metrics = {
            "raw_phishing": len(phishing_records),
            "raw_legitimate": len(legitimate_records),
            "invalid_urls_removed": 0,
            "exact_duplicates_removed": 0,
            "final_phishing": 0,
            "final_legitimate": 0,
            "total_processed": 0,
        }

        # Helper to process a record list
        def ingest(records: List[Dict[str, str]], default_label: int, default_source: str):
            for rec in records:
                raw_url = rec.get("url", "")
                norm_url = self.normalize_url(raw_url)
                if not norm_url:
                    metrics["invalid_urls_removed"] += 1
                    continue
                if norm_url in seen_urls:
                    metrics["exact_duplicates_removed"] += 1
                    continue

                seen_urls.add(norm_url)
                label = int(rec.get("label", default_label))
                source = rec.get("source", default_source)
                date_str = rec.get("collection_date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))

                clean_rows.append({
                    "url": norm_url,
                    "label": label,
                    "source": source,
                    "collection_date": date_str
                })
                if label == 1:
                    metrics["final_phishing"] += 1
                else:
                    metrics["final_legitimate"] += 1

        ingest(phishing_records, default_label=1, default_source="PhishTank/URLhaus")
        ingest(legitimate_records, default_label=0, default_source="Tranco/BenignProxy")

        metrics["total_processed"] = len(clean_rows)
        return clean_rows, metrics

    def save_processed(self, records: List[Dict[str, str]]) -> str:
        """Saves clean records to processed CSV file."""
        fieldnames = ["url", "label", "source", "collection_date"]
        with open(self.output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in records:
                writer.writerow(r)
        return self.output_path
