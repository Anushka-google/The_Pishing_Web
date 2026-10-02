"""
Phishing Detection & Risk Intelligence Platform
Acquisition Engine for Real-World Internet URLs:
- Real Phishing/Malicious URLs from URLhaus (abuse.ch) & OpenPhish
- Real Benign/Legitimate URLs from Tranco Top-1M List (Official Research Archive)
"""

import os
import io
import csv
import zipfile
import requests
import logging
from typing import List, Dict, Tuple, Any
from urllib.parse import urlparse
import tldextract

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class RealWorldDatasetAcquirer:
    """
    Acquires, cleans, and standardizes real-world URLs from authoritative security feeds.
    """
    URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    OPENPHISH_TXT = "https://raw.githubusercontent.com/OpenPhish/public_feed/master/feed.txt"
    TRANCO_ZIP = "https://tranco-list.eu/top-1m.csv.zip"

    def __init__(self, output_dir: str = "data/real_world"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.tld_extractor = tldextract.TLDExtract()

    def fetch_real_phishing(self, target_count: int = 5000) -> List[str]:
        phishing_urls = []
        logger.info(f"Downloading real phishing/malware URLs from URLhaus (abuse.ch)...")

        try:
            r = requests.get(self.URLHAUS_CSV, headers={"User-Agent": "PhishDetectResearch/1.0"}, timeout=20)
            if r.status_code == 200:
                lines = [line for line in r.text.splitlines() if not line.startswith("#") and line.strip()]
                reader = csv.reader(lines)
                for row in reader:
                    if len(row) > 2:
                        url = row[2].strip().replace('"', '')
                        if url.startswith("http://") or url.startswith("https://"):
                            phishing_urls.append(url)
                            if len(phishing_urls) >= target_count:
                                break
                logger.info(f"Extracted {len(phishing_urls)} real URLs from URLhaus.")
        except Exception as e:
            logger.warning(f"URLhaus fetch encountered error: {e}")

        # If more needed, fetch from OpenPhish
        if len(phishing_urls) < target_count:
            logger.info("Fetching additional live phishing URLs from OpenPhish...")
            try:
                r = requests.get(self.OPENPHISH_TXT, headers={"User-Agent": "PhishDetectResearch/1.0"}, timeout=15)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        url = line.strip()
                        if url.startswith("http"):
                            phishing_urls.append(url)
                            if len(phishing_urls) >= target_count:
                                break
                    logger.info(f"Total phishing URLs now: {len(phishing_urls)}")
            except Exception as e:
                logger.warning(f"OpenPhish fetch error: {e}")

        return phishing_urls[:target_count]

    def fetch_real_legitimate(self, target_count: int = 5000) -> List[str]:
        legitimate_urls = []
        logger.info(f"Downloading official Tranco Top-1M domains zip...")

        try:
            r = requests.get(self.TRANCO_ZIP, headers={"User-Agent": "PhishDetectResearch/1.0"}, timeout=30)
            if r.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                    # Tranco zip contains top-1m.csv
                    csv_name = z.namelist()[0]
                    with z.open(csv_name) as f:
                        reader = csv.reader(io.TextIOWrapper(f))
                        for row in reader:
                            if len(row) >= 2:
                                domain = row[1].strip().lower()
                                if domain:
                                    # Form valid URLs with standard schemes
                                    url = f"https://{domain}/"
                                    legitimate_urls.append(url)
                                    if len(legitimate_urls) >= target_count:
                                        break
                logger.info(f"Extracted {len(legitimate_urls)} real popular domains from Tranco.")
        except Exception as e:
            logger.warning(f"Tranco zip fetch error: {e}")

        return legitimate_urls[:target_count]

    def build_real_world_dataset(
        self,
        target_phishing: int = 5000,
        target_legitimate: int = 5000
    ) -> Tuple[str, Dict[str, Any]]:
        raw_phish = self.fetch_real_phishing(target_phishing)
        raw_legit = self.fetch_real_legitimate(target_legitimate)

        seen_urls = set()
        clean_records = []

        # Process phishing
        for u in raw_phish:
            cleaned = u.strip()
            if cleaned not in seen_urls and len(cleaned) < 2048:
                seen_urls.add(cleaned)
                clean_records.append({
                    "url": cleaned,
                    "label": 1,
                    "source": "URLhaus/OpenPhish",
                    "dataset_tier": "real_world_validation"
                })

        # Process legitimate
        for u in raw_legit:
            cleaned = u.strip()
            if cleaned not in seen_urls and len(cleaned) < 2048:
                seen_urls.add(cleaned)
                clean_records.append({
                    "url": cleaned,
                    "label": 0,
                    "source": "Tranco-Top1M",
                    "dataset_tier": "real_world_validation"
                })

        output_csv = os.path.join(self.output_dir, "urls_real_world.csv")
        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "label", "source", "dataset_tier"])
            writer.writeheader()
            writer.writerows(clean_records)

        phish_count = sum(1 for r in clean_records if r["label"] == 1)
        legit_count = sum(1 for r in clean_records if r["label"] == 0)

        stats = {
            "total_records": len(clean_records),
            "real_phishing": phish_count,
            "real_legitimate": legit_count,
            "output_path": output_csv
        }
        logger.info(f"Real-world dataset assembled: {stats['total_records']} URLs saved to {output_csv}")
        return output_csv, stats


if __name__ == "__main__":
    acquirer = RealWorldDatasetAcquirer()
    path, stats = acquirer.build_real_world_dataset(target_phishing=5000, target_legitimate=5000)
    print("\n--- REAL-WORLD DATASET SUMMARY ---")
    for k, v in stats.items():
        print(f"  {k}: {v}")
