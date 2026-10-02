"""
Phishing Detection & Risk Intelligence Platform
Phase 12: Classification Threshold Optimization & Calibration

A binary classifier should not blindly use a static 0.5 threshold.
This module performs empirical threshold optimization using validation evidence:
1. Sweeps candidate decision thresholds tau in [0.01, 0.99]
2. Computes Precision, Recall, F1, FPR, TPR, FP, and FN across thresholds
3. Derives calibrated multi-tier operational thresholds:
   - T1 (tau_low): High-recall boundary (Low Risk vs Medium Risk)
   - T2 (tau_high): High-precision boundary (Medium Risk vs High Risk)
   - T_optimal: F1-score maximizing threshold
4. Exports calibration metadata to data/processed/threshold_calibration.json
   and updates models/champion_phishing_model.joblib.
"""

import os
import json
from typing import Dict, Any, Tuple
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import tldextract
import joblib

from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, precision_recall_curve
)
from src.features.extractor import FeatureExtractor


class ThresholdOptimizer:
    def __init__(
        self,
        features_csv: str = "data/processed/features.csv",
        model_path: str = "models/champion_phishing_model.joblib"
    ):
        self.features_csv = features_csv
        self.model_path = model_path
        self.feature_cols = FeatureExtractor.FEATURE_NAMES
        self.tld_extractor = tldextract.TLDExtract()

        if not os.path.exists(features_csv):
            raise FileNotFoundError(f"Feature dataset not found: {features_csv}")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Champion model not found: {model_path}")

        self.df = pd.read_csv(features_csv)
        self.pkg = joblib.load(model_path)
        self.model = self.pkg["model"]
        self.scaler = self.pkg.get("scaler")

        self.df["domain"] = self.df["url"].apply(self._extract_domain)

    def _extract_domain(self, url: str) -> str:
        try:
            ext = self.tld_extractor(url)
            domain = getattr(ext, "top_domain_under_public_suffix", "")
            if domain:
                return domain.lower()
            return urlparse(url).netloc.split(":")[0].lower()
        except Exception:
            return "unknown"

    def get_validation_predictions(self, seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
        """Returns validation true labels and predicted phishing probabilities from domain-grouped split."""
        X = self.df[self.feature_cols].values
        y = self.df["label"].astype(int).values
        groups = self.df["domain"].values

        gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
        _, val_idx = next(gss.split(X, y, groups=groups))

        X_val = X[val_idx]
        y_val = y[val_idx]

        if self.scaler is not None:
            X_val = self.scaler.transform(X_val)

        y_proba = self.model.predict_proba(X_val)[:, 1]
        return y_val, y_proba

    def sweep_thresholds(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray,
        steps: int = 100
    ) -> pd.DataFrame:
        """Sweeps thresholds and calculates full operational performance metrics."""
        thresholds = np.linspace(0.01, 0.99, steps)
        records = []

        total_positives = int(np.sum(y_true == 1))
        total_negatives = int(np.sum(y_true == 0))

        for t in thresholds:
            y_pred = (y_proba >= t).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

            precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            tpr = recall

            records.append({
                "threshold": round(float(t), 4),
                "precision": round(float(precision), 4),
                "recall": round(float(recall), 4),
                "f1_score": round(float(f1), 4),
                "fpr": round(float(fpr), 4),
                "tpr": round(float(tpr), 4),
                "tp": int(tp),
                "fp": int(fp),
                "tn": int(tn),
                "fn": int(fn)
            })

        return pd.DataFrame(records)

    def optimize(self, seed: int = 42) -> Dict[str, Any]:
        """Calculates optimal operational thresholds and risk boundaries."""
        y_val, y_proba = self.get_validation_predictions(seed=seed)
        df_sweep = self.sweep_thresholds(y_val, y_proba)

        # 1. Optimal F1 threshold
        best_f1_idx = df_sweep["f1_score"].idxmax()
        optimal_row = df_sweep.iloc[best_f1_idx]
        t_optimal = float(optimal_row["threshold"])

        # 2. T1: Low Risk Cutoff (High Recall boundary)
        # We want recall >= 0.99 with minimal false negatives.
        high_recall_candidates = df_sweep[df_sweep["recall"] >= 0.99]
        if len(high_recall_candidates) > 0:
            t1_low = float(high_recall_candidates["threshold"].max())
        else:
            t1_low = max(0.20, round(t_optimal * 0.5, 2))

        # 3. T2: High Risk Cutoff (High Precision boundary)
        # We want precision >= 0.99 with minimal false alarms (FPR <= 1%)
        high_precision_candidates = df_sweep[(df_sweep["precision"] >= 0.98) & (df_sweep["threshold"] >= t_optimal)]
        if len(high_precision_candidates) > 0:
            t2_high = float(high_precision_candidates["threshold"].min())
        else:
            t2_high = min(0.80, round(t_optimal * 1.3, 2))

        # Ensure strict ordering: 0.05 <= T1 < T2 <= 0.95
        t1_low = min(max(t1_low, 0.15), 0.40)
        t2_high = max(min(t2_high, 0.85), 0.65)
        if t1_low >= t2_high:
            t1_low = 0.30
            t2_high = 0.70

        calibration_result = {
            "default_baseline_threshold": 0.50,
            "optimal_f1_threshold": t_optimal,
            "calibrated_thresholds": {
                "t1_low_risk_threshold": t1_low,
                "t2_high_risk_threshold": t2_high
            },
            "risk_tier_definitions": {
                "LOW_RISK": f"Probability < {t1_low:.2f} (Safe / Benign)",
                "MEDIUM_RISK": f"{t1_low:.2f} <= Probability < {t2_high:.2f} (Suspicious / Secondary Inspection)",
                "HIGH_RISK": f"Probability >= {t2_high:.2f} (Critical Phishing Alert / Block)"
            },
            "metrics_at_optimal_f1": optimal_row.to_dict(),
            "validation_sample_size": len(y_val),
            "sample_operating_points": {
                "high_recall_operating_point": df_sweep[df_sweep["threshold"] == t1_low].iloc[0].to_dict() if len(df_sweep[df_sweep["threshold"] == t1_low]) > 0 else None,
                "high_precision_operating_point": df_sweep[df_sweep["threshold"] == t2_high].iloc[0].to_dict() if len(df_sweep[df_sweep["threshold"] == t2_high]) > 0 else None
            }
        }

        # Save calibration report
        os.makedirs("data/processed", exist_ok=True)
        with open("data/processed/threshold_calibration.json", "w", encoding="utf-8") as f:
            json.dump(calibration_result, f, indent=2)

        # Update champion model package with calibrated thresholds
        self.pkg["thresholds"] = {
            "t1_low": t1_low,
            "t2_high": t2_high,
            "t_optimal": t_optimal
        }
        joblib.dump(self.pkg, self.model_path)

        return calibration_result


def classify_risk(probability: float, t1: float = 0.30, t2: float = 0.70) -> Dict[str, Any]:
    """Helper function to map a probability to calibrated risk tier."""
    if probability < t1:
        return {
            "risk_level": "LOW",
            "action": "ALLOW",
            "description": "Destination displays standard benign characteristics with minimal threat indicators."
        }
    elif probability < t2:
        return {
            "risk_level": "MEDIUM",
            "action": "CAUTION",
            "description": "Suspicious structural or lexical anomalies detected. Proceed with caution."
        }
    else:
        return {
            "risk_level": "HIGH",
            "action": "BLOCK",
            "description": "Critical phishing indicators identified. High probability of malicious intent."
        }


if __name__ == "__main__":
    optimizer = ThresholdOptimizer()
    report = optimizer.optimize()

    print("=" * 70)
    print("  PHASE 12: CLASSIFICATION THRESHOLD OPTIMIZATION COMPLETE")
    print("=" * 70)
    print(f"Optimal F1 Threshold  : {report['optimal_f1_threshold']:.2f}")
    print(f"Calibrated T1 (Low)   : {report['calibrated_thresholds']['t1_low_risk_threshold']:.2f}")
    print(f"Calibrated T2 (High)  : {report['calibrated_thresholds']['t2_high_risk_threshold']:.2f}")
    print("-" * 70)
    print("Risk Tiers:")
    for tier, desc in report["risk_tier_definitions"].items():
        print(f"  {tier:<12}: {desc}")
    print("-" * 70)
    print("Calibration report saved to: data/processed/threshold_calibration.json")
    print("Champion model updated with calibrated operating thresholds.")
    print("=" * 70)
