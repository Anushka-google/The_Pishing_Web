"""
Phishing Detection & Risk Intelligence Platform
Feature Dataset Builder: Extracts feature vectors for all records in data/processed/urls.csv
and saves the structured matrix to data/processed/features.csv.
"""

import os
import time
import pandas as pd
from src.features.extractor import FeatureExtractor


def build_feature_dataset(
    input_csv: str = "data/processed/urls.csv",
    output_csv: str = "data/processed/features.csv"
):
    print("=" * 65)
    print("  PHASE 6 & 7: BUILDING NUMERICAL FEATURE MATRIX")
    print("=" * 65)

    if not os.path.exists(input_csv):
        raise FileNotFoundError(f"Input dataset not found at {input_csv}")

    print(f"Loading raw processed dataset: {input_csv} ...")
    df = pd.read_csv(input_csv)
    total_records = len(df)
    print(f"Total URLs to process: {total_records:,}")

    extractor = FeatureExtractor()
    print(f"Extracting {len(extractor.FEATURE_NAMES)} features per URL...")

    t0 = time.perf_counter()
    feature_df = extractor.batch_extract(df["url"].tolist())
    elapsed = time.perf_counter() - t0

    # Attach labels and metadata
    feature_df["label"] = df["label"].values
    feature_df["source"] = df["source"].values
    feature_df["url"] = df["url"].values
    if "collection_date" in df.columns:
        feature_df["collection_date"] = df["collection_date"].values

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    feature_df.to_csv(output_csv, index=False)

    print(f"Feature extraction completed in {elapsed:.2f} seconds ({elapsed/total_records*1000:.3f} ms/URL).")
    print(f"Saved feature matrix to: {output_csv}")

    # Compute correlation with target label
    numeric_cols = extractor.FEATURE_NAMES + ["label"]
    corr = feature_df[numeric_cols].corr()["label"].sort_values(ascending=False)

    print("\n--- TOP PREDICTIVE FEATURES (Correlation with Phishing Label) ---")
    for feat, val in corr.items():
        if feat != "label":
            print(f"  {feat:30s} : {val:+.4f}")

    return output_csv, feature_df


if __name__ == "__main__":
    build_feature_dataset()
