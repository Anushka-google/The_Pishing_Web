"""
Phishing Detection & Risk Intelligence Platform
Authentic Real-World Dataset Pipeline
1. Ingests genuine URLs from PhishTank, URLhaus, Tranco, and Enterprise Hard Negatives.
2. Normalizes URLs and extracts registered domains via Mozilla PSL (tldextract).
3. Deduplicates exact duplicates and performs near-duplicate clustering.
4. Extracts 22 canonical features via FeatureExtractor.
5. Exports:
   - data/real_world/urls_authentic.csv
   - data/real_world/features_real_world.csv
"""

import os
import re
import csv
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Set, Optional
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import tldextract

from src.features.extractor import FeatureExtractor
from src.data.ingest_authentic_feeds import AuthenticFeedIngester


class AuthenticDatasetPipeline:
    """
    Manages authentic, non-synthetic URL dataset creation with verified provenance.
    """
    def __init__(
        self,
        output_urls_path: str = "data/real_world/urls_authentic.csv",
        output_features_path: str = "data/real_world/features_real_world.csv"
    ):
        self.output_urls_path = output_urls_path
        self.output_features_path = output_features_path
        self.tld_extractor = tldextract.TLDExtract()
        self.extractor = FeatureExtractor()

        os.makedirs(os.path.dirname(output_urls_path), exist_ok=True)
        os.makedirs(os.path.dirname(output_features_path), exist_ok=True)

    def normalize_url(self, raw_url: str) -> Optional[str]:
        """Strict RFC 3986 normalization without data loss."""
        if not raw_url or not isinstance(raw_url, str):
            return None
        cleaned = raw_url.strip()
        if len(cleaned) < 4 or len(cleaned) > 2048:
            return None

        # Standardize scheme
        if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
            cleaned = "https://" + cleaned

        try:
            parsed = urlparse(cleaned)
            if not parsed.netloc:
                return None
            netloc = parsed.netloc.lower()
            scheme = parsed.scheme.lower()
            norm = f"{scheme}://{netloc}{parsed.path}"
            if parsed.query:
                norm += f"?{parsed.query}"
            if parsed.fragment:
                norm += f"#{parsed.fragment}"
            return norm
        except Exception:
            return None

    def extract_registered_domain(self, url: str) -> str:
        """Extracts registrable domain using Mozilla Public Suffix List."""
        try:
            ext = self.tld_extractor(url)
            domain = getattr(ext, "top_domain_under_public_suffix", "") or ext.registered_domain
            if domain:
                return domain.lower()
            return urlparse(url).netloc.split(":")[0].lower()
        except Exception:
            return "unknown"

    def compute_near_duplicate_skeleton(self, url: str) -> str:
        """
        Creates a canonical structural skeleton to identify template duplication.
        Replaces numeric tokens and query parameter values with placeholders.
        """
        try:
            parsed = urlparse(url)
            # Normalize path: replace long numbers with <num>
            path = re.sub(r"\d+", "<num>", parsed.path)
            # Normalize query parameters: keep param keys, wipe values
            if parsed.query:
                params = [p.split("=")[0] + "=<val>" for p in parsed.query.split("&")]
                query_skel = "&".join(sorted(params))
            else:
                query_skel = ""
            return f"{parsed.netloc.lower()}{path}?{query_skel}"
        except Exception:
            return url

    def build_authentic_dataset(
        self,
        phishtank_limit: int = 5000,
        urlhaus_limit: int = 5000,
        tranco_limit: int = 10000
    ) -> Dict[str, Any]:
        """
        Executes end-to-end authentic dataset ingestion, deduplication, and feature extraction.
        """
        ingester = AuthenticFeedIngester()
        phishtank_raw = ingester.fetch_phishtank(limit=phishtank_limit)
        urlhaus_raw = ingester.fetch_urlhaus(limit=urlhaus_limit)
        tranco_raw = ingester.fetch_tranco_legitimate(limit=tranco_limit)
        sso_raw = ingester.fetch_enterprise_hard_negatives()

        all_raw = phishtank_raw + urlhaus_raw + tranco_raw + sso_raw
        print(f"[Pipeline] Total raw records gathered: {len(all_raw):,}")

        # 1. Normalization & Deduplication
        seen_urls: Set[str] = set()
        clean_records = []
        exact_duplicates_removed = 0
        near_duplicate_skeletons: Dict[str, int] = {}

        for rec in all_raw:
            norm_url = self.normalize_url(rec["url"])
            if not norm_url:
                continue

            if norm_url in seen_urls:
                exact_duplicates_removed += 1
                continue
            seen_urls.add(norm_url)

            reg_domain = self.extract_registered_domain(norm_url)
            skeleton = self.compute_near_duplicate_skeleton(norm_url)
            skeleton_hash = hashlib.md5(skeleton.encode("utf-8")).hexdigest()[:10]

            near_duplicate_skeletons[skeleton_hash] = near_duplicate_skeletons.get(skeleton_hash, 0) + 1

            clean_records.append({
                "url": norm_url,
                "registered_domain": reg_domain,
                "label": int(rec["label"]),
                "source": rec["source"],
                "collection_timestamp": rec["collection_timestamp"],
                "skeleton_cluster_id": skeleton_hash
            })

        print(f"[Pipeline] Cleaned unique URLs: {len(clean_records):,} (Exact duplicates removed: {exact_duplicates_removed:,})")

        # Count near-duplicate clusters (skeletons appearing > 1 time)
        near_duplicate_clusters = sum(1 for count in near_duplicate_skeletons.values() if count > 1)
        total_near_duplicate_urls = sum(count for count in near_duplicate_skeletons.values() if count > 1)
        print(f"[Pipeline] Near-duplicate audit: {near_duplicate_clusters:,} clusters containing {total_near_duplicate_urls:,} URLs.")

        # Save clean authentic URLs CSV
        df_urls = pd.DataFrame(clean_records)
        df_urls.to_csv(self.output_urls_path, index=False, encoding="utf-8")
        print(f"[Pipeline] Saved authentic URLs to: {self.output_urls_path}")

        # 2. Extract 22 Features using FeatureExtractor
        print(f"[Pipeline] Extracting 22 security signals via FeatureExtractor...")
        feature_rows = []
        for i, rec in enumerate(clean_records):
            feats = self.extractor.extract_features_dict(rec["url"])
            feats["label"] = rec["label"]
            feats["url"] = rec["url"]
            feats["registered_domain"] = rec["registered_domain"]
            feats["source"] = rec["source"]
            feats["collection_timestamp"] = rec["collection_timestamp"]
            feature_rows.append(feats)

            if (i + 1) % 2500 == 0:
                print(f"  Processed {i+1:,}/{len(clean_records):,} URLs...")

        df_features = pd.DataFrame(feature_rows)

        # Reorder columns: 22 features first, then metadata
        cols = FeatureExtractor.FEATURE_NAMES + ["label", "url", "registered_domain", "source", "collection_timestamp"]
        df_features = df_features[cols]
        df_features.to_csv(self.output_features_path, index=False, encoding="utf-8")
        print(f"[Pipeline] Successfully saved authentic features to: {self.output_features_path}")

        phish_count = int((df_features["label"] == 1).sum())
        legit_count = int((df_features["label"] == 0).sum())
        unique_domains = int(df_features["registered_domain"].nunique())

        audit_summary = {
            "total_authentic_samples": len(df_features),
            "phishing_count": phish_count,
            "legitimate_count": legit_count,
            "phishing_ratio": round(phish_count / len(df_features), 4),
            "unique_registered_domains": unique_domains,
            "exact_duplicates_removed": exact_duplicates_removed,
            "near_duplicate_clusters": near_duplicate_clusters,
            "near_duplicate_urls": total_near_duplicate_urls,
            "sources": df_features["source"].value_counts().to_dict(),
            "output_features_path": self.output_features_path,
            "output_urls_path": self.output_urls_path
        }

        # Save metadata summary
        summary_path = "data/real_world/authentic_dataset_summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(audit_summary, f, indent=2)

        return audit_summary


if __name__ == "__main__":
    pipeline = AuthenticDatasetPipeline()
    summary = pipeline.build_authentic_dataset(
        phishtank_limit=5000,
        urlhaus_limit=5000,
        tranco_limit=10000
    )
    print("\n" + "=" * 70)
    print("AUTHENTIC DATASET PIPELINE COMPLETE")
    print("=" * 70)
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print("=" * 70)
