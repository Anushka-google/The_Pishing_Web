"""
Phishing Detection & Risk Intelligence Platform
Platt Scaling Calibration Engine

Fits Sigmoid Platt Scaling on a domain-disjoint calibration partition
to calibrate raw tree ensemble voting ratios into true empirical posterior probabilities.
Evaluates calibration metrics (Brier, Log Loss, ECE, ROC-AUC, PR-AUC, Reliability Bins)
on untouched domain-disjoint test data and independent real-world holdouts.
"""

import os
import json
from typing import Dict, Any, Tuple, List
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import tldextract
import joblib

from sklearn.frozen import FrozenEstimator
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    brier_score_loss, log_loss, roc_auc_score, average_precision_score,
    confusion_matrix, precision_score, recall_score
)
from src.features.extractor import FeatureExtractor


def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> Tuple[float, List[Dict[str, Any]]]:
    """Computes Expected Calibration Error (ECE) and reliability bin statistics."""
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    bins_data = []

    for i in range(n_bins):
        low, high = bin_edges[i], bin_edges[i + 1]
        if i == n_bins - 1:
            mask = (y_prob >= low) & (y_prob <= high)
        else:
            mask = (y_prob >= low) & (y_prob < high)

        count = int(np.sum(mask))
        if count > 0:
            acc = float(np.mean(y_true[mask]))
            conf = float(np.mean(y_prob[mask]))
            gap = abs(acc - conf)
            ece += (count / len(y_true)) * gap
        else:
            acc = 0.0
            conf = (low + high) / 2.0
            gap = 0.0

        bins_data.append({
            "bin_index": i + 1,
            "range": f"[{low:.2f}, {high:.2f}]",
            "count": count,
            "accuracy": round(acc, 4),
            "confidence": round(conf, 4),
            "gap": round(gap, 4)
        })

    return round(float(ece), 5), bins_data


def evaluate_calibration_partition(
    name: str,
    y_true: np.ndarray,
    y_raw: np.ndarray,
    y_cal: np.ndarray
) -> Dict[str, Any]:
    """Calculates comprehensive calibration and ranking metrics for raw vs calibrated predictions."""
    raw_brier = brier_score_loss(y_true, y_raw)
    raw_logloss = log_loss(y_true, np.clip(y_raw, 1e-15, 1 - 1e-15))
    raw_ece, raw_bins = compute_ece(y_true, y_raw)
    raw_roc = roc_auc_score(y_true, y_raw)
    raw_pr = average_precision_score(y_true, y_raw)

    cal_brier = brier_score_loss(y_true, y_cal)
    cal_logloss = log_loss(y_true, np.clip(y_cal, 1e-15, 1 - 1e-15))
    cal_ece, cal_bins = compute_ece(y_true, y_cal)
    cal_roc = roc_auc_score(y_true, y_cal)
    cal_pr = average_precision_score(y_true, y_cal)

    return {
        "dataset_name": name,
        "sample_count": len(y_true),
        "raw_metrics": {
            "brier_score": round(float(raw_brier), 5),
            "log_loss": round(float(raw_logloss), 5),
            "ece": raw_ece,
            "roc_auc": round(float(raw_roc), 4),
            "pr_auc": round(float(raw_pr), 4),
            "reliability_bins": raw_bins
        },
        "calibrated_metrics": {
            "brier_score": round(float(cal_brier), 5),
            "log_loss": round(float(cal_logloss), 5),
            "ece": cal_ece,
            "roc_auc": round(float(cal_roc), 4),
            "pr_auc": round(float(cal_pr), 4),
            "reliability_bins": cal_bins
        },
        "improvements": {
            "brier_score_delta": round(float(raw_brier - cal_brier), 5),
            "log_loss_delta": round(float(raw_logloss - cal_logloss), 5),
            "ece_delta": round(float(raw_ece - cal_ece), 5)
        }
    }


def evaluate_directives(y_true: np.ndarray, y_prob: np.ndarray) -> Dict[str, Any]:
    """Evaluates operational risk directive thresholds (ALLOW < 0.40, CAUTION 0.40-0.65, BLOCK >= 0.65)."""
    # Binary classification at optimal threshold 0.50
    pred_binary = (y_prob >= 0.50).astype(int)
    tn_b, fp_b, fn_b, tp_b = confusion_matrix(y_true, pred_binary, labels=[0, 1]).ravel()
    prec_b = tp_b / (tp_b + fp_b) if (tp_b + fp_b) > 0 else 0.0
    rec_b = tp_b / (tp_b + fn_b) if (tp_b + fn_b) > 0 else 0.0
    fpr_b = fp_b / (fp_b + tn_b) if (fp_b + tn_b) > 0 else 0.0
    fnr_b = fn_b / (fn_b + tp_b) if (fn_b + tp_b) > 0 else 0.0

    # Policy BLOCK threshold (>= 0.65): High Precision
    pred_block = (y_prob >= 0.65).astype(int)
    tn_65, fp_65, fn_65, tp_65 = confusion_matrix(y_true, pred_block, labels=[0, 1]).ravel()
    prec_65 = tp_65 / (tp_65 + fp_65) if (tp_65 + fp_65) > 0 else 1.0
    rec_65 = tp_65 / (tp_65 + fn_65) if (tp_65 + fn_65) > 0 else 0.0
    fpr_65 = fp_65 / (fp_65 + tn_65) if (fp_65 + tn_65) > 0 else 0.0
    fnr_65 = fn_65 / (fn_65 + tp_65) if (fn_65 + tp_65) > 0 else 0.0

    # Policy ALLOW threshold (< 0.40): High Recall / Low Miss Rate
    pred_allow_neg = (y_prob < 0.40).astype(int)  # predicted benign
    true_benign = (y_true == 0).astype(int)
    
    return {
        "threshold_0_50_standard": {
            "tp": int(tp_b), "fp": int(fp_b), "tn": int(tn_b), "fn": int(fn_b),
            "precision": round(float(prec_b), 4),
            "recall": round(float(rec_b), 4),
            "fpr": round(float(fpr_b), 4),
            "fnr": round(float(fnr_b), 4)
        },
        "block_policy_threshold_0_65": {
            "description": "BLOCK (probability >= 0.65): Zero-tolerance automated blocking",
            "tp": int(tp_65), "fp": int(fp_65), "tn": int(tn_65), "fn": int(fn_65),
            "precision": round(float(prec_65), 4),
            "recall": round(float(rec_65), 4),
            "fpr": round(float(fpr_65), 4),
            "fnr": round(float(fnr_65), 4)
        },
        "caution_tier": {
            "description": "CAUTION (0.40 <= probability < 0.65): Quarantined for SOC inspection",
            "count": int(np.sum((y_prob >= 0.40) & (y_prob < 0.65)))
        },
        "allow_tier": {
            "description": "ALLOW (probability < 0.40): Permitted web browsing",
            "count": int(np.sum(y_prob < 0.40))
        }
    }


def fit_and_export_platt_calibrator(
    features_csv: str = "data/processed/features.csv",
    model_path: str = "models/champion_phishing_model.joblib",
    real_world_features_csv: str = "data/real_world/features_real_world.csv"
) -> Dict[str, Any]:
    """Fits Platt calibrator on domain-disjoint validation partition and updates champion model bundle."""
    pkg = joblib.load(model_path)
    model = pkg["model"]
    feature_names = pkg.get("feature_names", FeatureExtractor.FEATURE_NAMES)
    scaler = pkg.get("scaler")

    df = pd.read_csv(features_csv)
    extractor = tldextract.TLDExtract()

    def get_domain(u):
        try:
            ext = extractor(u)
            d = getattr(ext, "top_domain_under_public_suffix", "")
            if not d and ext.domain and ext.suffix:
                d = f"{ext.domain}.{ext.suffix}"
            return d.lower() if d else urlparse(u).netloc.split(":")[0].lower()
        except Exception:
            return "unknown"

    df["domain"] = df["url"].apply(get_domain)

    X_all = df[feature_names].copy().fillna(0)
    y_all = df["label"].astype(int).values
    groups = df["domain"].values

    # Step 1: Split into Train+Calib (80%) and Untouched Test (20%) using Domain Grouping
    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    dev_idx, test_idx = next(gss1.split(X_all, y_all, groups=groups))

    X_dev = X_all.iloc[dev_idx]
    y_dev = y_all[dev_idx]
    groups_dev = groups[dev_idx]

    X_test = X_all.iloc[test_idx]
    y_test = y_all[test_idx]
    test_domains = set(groups[test_idx])

    # Step 2: Split dev into Model Training (75% of dev = 60% total) and Calibration (25% of dev = 20% total)
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_sub_idx, calib_sub_idx = next(gss2.split(X_dev, y_dev, groups=groups_dev))

    X_calib = X_dev.iloc[calib_sub_idx]
    y_calib = y_dev[calib_sub_idx]
    calib_domains = set(groups_dev[calib_sub_idx])

    train_domains = set(groups_dev[train_sub_idx])

    # Verify zero domain overlap
    assert len(train_domains.intersection(calib_domains)) == 0, "Domain leakage between Train and Calib!"
    assert len(train_domains.intersection(test_domains)) == 0, "Domain leakage between Train and Test!"
    assert len(calib_domains.intersection(test_domains)) == 0, "Domain leakage between Calib and Test!"

    print(f"Domain-Disjoint Partitions:")
    print(f"  Train: {len(train_domains)} domains, {len(train_sub_idx)} samples")
    print(f"  Calib: {len(calib_domains)} domains, {len(calib_sub_idx)} samples")
    print(f"  Test : {len(test_domains)} domains, {len(test_idx)} samples (UNTOUCHED)")

    # Fit Platt Calibrator on Calibration partition using FrozenEstimator
    calibrator = CalibratedClassifierCV(FrozenEstimator(model), method="sigmoid")
    calibrator.fit(X_calib, y_calib)

    # Evaluate on Untouched Domain-Disjoint Test partition
    y_test_raw = model.predict_proba(X_test)[:, 1]
    y_test_cal = calibrator.predict_proba(X_test)[:, 1]

    dev_eval = evaluate_calibration_partition("Domain-Disjoint Test Set (features.csv)", y_test, y_test_raw, y_test_cal)
    dev_directives = evaluate_directives(y_test, y_test_cal)

    # Evaluate on untouched Real-World Holdout if available
    rw_eval = None
    rw_directives = None
    if os.path.exists(real_world_features_csv):
        df_rw = pd.read_csv(real_world_features_csv)
        X_rw = df_rw[feature_names].copy().fillna(0)
        y_rw = df_rw["label"].astype(int).values

        y_rw_raw = model.predict_proba(X_rw)[:, 1]
        y_rw_cal = calibrator.predict_proba(X_rw)[:, 1]

        rw_eval = evaluate_calibration_partition("Real-World Untouched Holdout (URLhaus + Tranco)", y_rw, y_rw_raw, y_rw_cal)
        rw_directives = evaluate_directives(y_rw, y_rw_cal)

    # Package and save to champion model
    pkg["calibrator"] = calibrator
    pkg["calibration_metadata"] = {
        "method": "sigmoid_platt_scaling",
        "estimator": "CalibratedClassifierCV(FrozenEstimator(RandomForestClassifier))",
        "calib_samples": len(y_calib),
        "calib_domains": len(calib_domains),
        "domain_disjoint_verified": True
    }
    joblib.dump(pkg, model_path)
    print(f"Updated {model_path} with fitted Platt Calibrator.")

    full_report = {
        "metadata": {
            "method": "Sigmoid Platt Scaling",
            "calibration_samples": len(y_calib),
            "calibration_domains": len(calib_domains),
            "test_samples": len(y_test),
            "test_domains": len(test_domains),
            "zero_domain_leakage": True
        },
        "domain_disjoint_test_evaluation": dev_eval,
        "domain_disjoint_directives": dev_directives,
        "real_world_evaluation": rw_eval,
        "real_world_directives": rw_directives
    }

    os.makedirs("data/processed", exist_ok=True)
    with open("data/processed/platt_calibration_report.json", "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    return full_report


if __name__ == "__main__":
    rep = fit_and_export_platt_calibrator()
    print("\n" + "=" * 70)
    print("  PLATT SCALING CALIBRATION BENCHMARK RESULTS")
    print("=" * 70)
    for part in ["domain_disjoint_test_evaluation", "real_world_evaluation"]:
        d = rep.get(part)
        if not d:
            continue
        print(f"\nDataset: {d['dataset_name']} ({d['sample_count']} samples)")
        print(f"  Raw RF    : Brier={d['raw_metrics']['brier_score']:.5f} | LogLoss={d['raw_metrics']['log_loss']:.5f} | ECE={d['raw_metrics']['ece']:.5f} | ROC-AUC={d['raw_metrics']['roc_auc']:.4f}")
        print(f"  Calibrated: Brier={d['calibrated_metrics']['brier_score']:.5f} | LogLoss={d['calibrated_metrics']['log_loss']:.5f} | ECE={d['calibrated_metrics']['ece']:.5f} | ROC-AUC={d['calibrated_metrics']['roc_auc']:.4f}")
        print(f"  Delta     : dBrier={d['improvements']['brier_score_delta']:+.5f} | dLogLoss={d['improvements']['log_loss_delta']:+.5f} | dECE={d['improvements']['ece_delta']:+.5f}")
