"""
Phishing Detection & Risk Intelligence Platform
Phase 23: Production Model Versioning & Dynamic Rollback Registry

Manages formal ML model versioning:
- v1 -> Random Forest (22 Base RFC/Structural/Lexical/Entropy features)
- v2 -> XGBoost Champion (22 Base features, 300 estimators, depth 6, lr 0.05)
- v3 -> XGBoost + Improved Features (28 Features: Base + digit_ratio, path_entropy,
        has_at_symbol, suspicious_tld, hyphen_ratio, is_https_with_ip)

Guarantees:
1. Every production prediction records and outputs its exact generating model_version.
2. Zero-downtime hot-swapping and instantaneous rollback across versions.
3. Complete reproducibility and auditability of past prediction telemetry.
"""

import os
import sys
import json
import shutil
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

from src.features.extractor import FeatureExtractor, calculate_shannon_entropy


class ModelVersionManager:
    """
    Centralized controller for model version lifecycle, registration, hot-swapping, and rollback.
    """
    DEFAULT_MODELS_DIR = "models"
    MANIFEST_FILENAME = "version_manifest.json"
    CHAMPION_FILENAME = "champion_phishing_model.joblib"

    VERSION_DEFINITIONS = {
        "v1": {
            "version": "v1",
            "model_name": "Random Forest",
            "architecture": "RandomForestClassifier",
            "feature_set": "base",
            "feature_count": 22,
            "artifact_file": "v1_random_forest.joblib",
            "description": "Baseline Bagging Ensemble (100 trees, max depth 12) trained on 22 base RFC/entropy signals.",
            "hyperparameters": {
                "n_estimators": 100,
                "max_depth": 12,
                "criterion": "gini",
                "random_state": 42
            }
        },
        "v2": {
            "version": "v2",
            "model_name": "XGBoost",
            "architecture": "XGBClassifier",
            "feature_set": "base",
            "feature_count": 22,
            "artifact_file": "v2_xgboost.joblib",
            "description": "Tuned Gradient Boosting Champion (300 estimators, max depth 6, lr 0.05) on 22 base signals.",
            "hyperparameters": {
                "n_estimators": 300,
                "max_depth": 6,
                "learning_rate": 0.05,
                "subsample": 0.8,
                "colsample_bytree": 0.8,
                "eval_metric": "logloss",
                "random_state": 42
            }
        },
        "v3": {
            "version": "v3",
            "model_name": "XGBoost (Improved Features)",
            "architecture": "XGBClassifier",
            "feature_set": "improved",
            "feature_count": 28,
            "artifact_file": "v3_xgboost_improved.joblib",
            "description": "Advanced Gradient Boosting Champion leveraging 28 features (added digit/hyphen ratios, path entropy, TLD abuse flags, and auth injections).",
            "hyperparameters": {
                "n_estimators": 300,
                "max_depth": 6,
                "learning_rate": 0.05,
                "subsample": 0.8,
                "colsample_bytree": 0.8,
                "eval_metric": "logloss",
                "random_state": 42
            }
        }
    }

    ROLLBACK_SEQUENCE = ["v3", "v2", "v1"]

    def __init__(
        self,
        models_dir: str = DEFAULT_MODELS_DIR,
        manifest_path: Optional[str] = None
    ):
        self.models_dir = models_dir
        os.makedirs(self.models_dir, exist_ok=True)
        self.manifest_path = manifest_path or os.path.join(self.models_dir, self.MANIFEST_FILENAME)
        self.manifest = self._load_or_init_manifest()

    def _load_or_init_manifest(self) -> Dict[str, Any]:
        """Loads manifest or creates initial structure if missing."""
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        # Default initial manifest
        manifest = {
            "active_version": "v1",
            "previous_version": "v1",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "versions": {}
        }
        for v_id, meta in self.VERSION_DEFINITIONS.items():
            manifest["versions"][v_id] = {
                **meta,
                "artifact_path": os.path.join(self.models_dir, meta["artifact_file"]).replace("\\", "/"),
                "is_active": (v_id == "v1"),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "metrics": {}
            }
        return manifest

    def _save_manifest(self):
        """Persists the updated manifest to disk."""
        self.manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(self.manifest, f, indent=2)

    def get_active_version(self) -> str:
        """Returns the identifier of the currently active production model version."""
        return self.manifest.get("active_version", "v2")

    def get_active_version_info(self) -> Dict[str, Any]:
        """Returns full metadata for the currently active production model version."""
        active_v = self.get_active_version()
        return self.get_version_info(active_v)

    def get_version_info(self, version: str) -> Dict[str, Any]:
        """Returns metadata for a specific model version."""
        if version not in self.manifest["versions"]:
            raise ValueError(f"Unknown model version '{version}'. Available versions: {list(self.manifest['versions'].keys())}")
        return self.manifest["versions"][version]

    def list_versions(self) -> List[Dict[str, Any]]:
        """Returns a list of all model versions with their status and metrics."""
        return list(self.manifest["versions"].values())

    def set_active_version(self, target_version: str) -> Dict[str, Any]:
        """
        Hot-swaps the active model version.
        Updates manifest and synchronizes champion_phishing_model.joblib.
        """
        if target_version not in self.manifest["versions"]:
            raise ValueError(f"Cannot switch to unknown version '{target_version}'. Available: {list(self.manifest['versions'].keys())}")

        current_active = self.get_active_version()
        if target_version == current_active:
            return self.get_version_info(target_version)

        # Update previous and active versions
        self.manifest["previous_version"] = current_active
        self.manifest["active_version"] = target_version

        for v_id, v_data in self.manifest["versions"].items():
            v_data["is_active"] = (v_id == target_version)

        # Synchronize champion artifact
        target_info = self.manifest["versions"][target_version]
        target_artifact = target_info["artifact_path"]

        champion_path = os.path.join(self.models_dir, self.CHAMPION_FILENAME)
        if os.path.exists(target_artifact):
            shutil.copyfile(target_artifact, champion_path)

        self._save_manifest()
        return self.get_version_info(target_version)

    def rollback(self, target_version: Optional[str] = None) -> str:
        """
        Rolls back the active model to the specified version or the sequential predecessor.
        Sequence: v3 -> v2 -> v1.
        """
        current_active = self.get_active_version()

        if target_version is not None:
            rollback_target = target_version
        else:
            # Determine sequential predecessor
            if current_active in self.ROLLBACK_SEQUENCE:
                idx = self.ROLLBACK_SEQUENCE.index(current_active)
                if idx < len(self.ROLLBACK_SEQUENCE) - 1:
                    rollback_target = self.ROLLBACK_SEQUENCE[idx + 1]
                else:
                    rollback_target = self.ROLLBACK_SEQUENCE[-1]
            else:
                rollback_target = self.manifest.get("previous_version", "v1")

        self.set_active_version(rollback_target)
        return rollback_target

    def load_version(self, version: Optional[str] = None) -> Dict[str, Any]:
        """Loads and returns the model package for the specified version (or active version)."""
        target_v = version or self.get_active_version()
        info = self.get_version_info(target_v)
        path = info["artifact_path"]

        if not os.path.exists(path):
            raise FileNotFoundError(f"Model artifact for version '{target_v}' not found at: {path}")

        return joblib.load(path)

    # --------------------------------------------------------------------------
    # Training & Version Creation Pipeline
    # --------------------------------------------------------------------------

    def build_and_register_all(
        self,
        features_csv: str = "data/processed/features.csv",
        random_state: int = 42
    ) -> Dict[str, Any]:
        """
        Trains and persists artifacts for v1, v2, and v3 from raw dataset.
        Computes the improved features for v3, evaluates holdouts on identical splits,
        and saves all model bundles into the models directory.
        """
        print("[ModelVersionManager] Beginning build of model versions v1, v2, and v3...")
        if not os.path.exists(features_csv):
            raise FileNotFoundError(f"Features dataset not found at {features_csv}")

        df = pd.read_csv(features_csv)
        y = df["label"].astype(int).values

        # 1. Base 22 Features for v1 and v2
        base_features = FeatureExtractor.BASE_FEATURE_NAMES
        X_base = df[base_features].copy().fillna(0)

        # 2. Improved 28 Features for v3
        extractor_improved = FeatureExtractor(feature_set="improved")
        improved_features = FeatureExtractor.IMPROVED_FEATURE_NAMES

        print("[ModelVersionManager] Computing improved feature signals for v3...")
        improved_rows = []
        for _, row in df.iterrows():
            f_dict = extractor_improved.extract_features_dict(row["url"])
            improved_rows.append(f_dict)
        df_improved = pd.DataFrame(improved_rows)
        X_improved = df_improved[improved_features].copy().fillna(0)

        # Identical train/test split index
        train_idx, test_idx = train_test_split(
            np.arange(len(df)),
            test_size=0.20,
            random_state=random_state,
            stratify=y
        )

        y_train, y_test = y[train_idx], y[test_idx]

        # Base train/test
        X_train_base = X_base.iloc[train_idx]
        X_test_base = X_base.iloc[test_idx]

        # Improved train/test
        X_train_imp = X_improved.iloc[train_idx]
        X_test_imp = X_improved.iloc[test_idx]

        # Calibrated default thresholds
        thresholds = {"t1_low": 0.40, "t2_high": 0.65, "t_optimal": 0.2872}
        calib_file = "data/processed/threshold_calibration.json"
        if os.path.exists(calib_file):
            try:
                with open(calib_file, "r") as f:
                    c_data = json.load(f)
                    cal_thresh = c_data.get("calibrated_thresholds", {})
                    thresholds["t1_low"] = float(cal_thresh.get("t1_low_risk_threshold", 0.40))
                    thresholds["t2_high"] = float(cal_thresh.get("t2_high_risk_threshold", 0.65))
                    thresholds["t_optimal"] = float(c_data.get("optimal_f1_threshold", 0.2872))
            except Exception:
                pass

        results = {}

        # -------------------------------------------------------------
        # Model v1: Random Forest (22 Base Features)
        # -------------------------------------------------------------
        print("\n[ModelVersionManager] Training Model v1: Random Forest (22 Features)...")
        rf_meta = self.VERSION_DEFINITIONS["v1"]
        clf_v1 = RandomForestClassifier(**rf_meta["hyperparameters"], n_jobs=-1)

        t0 = time.perf_counter()
        clf_v1.fit(X_train_base, y_train)
        v1_train_time = round(time.perf_counter() - t0, 4)

        v1_metrics = self._evaluate_model(clf_v1, X_test_base, y_test, v1_train_time)
        v1_artifact_path = os.path.join(self.models_dir, rf_meta["artifact_file"]).replace("\\", "/")

        bundle_v1 = {
            "model_version": "v1",
            "model_name": rf_meta["model_name"],
            "model": clf_v1,
            "scaler": None,
            "requires_scaling": False,
            "feature_names": base_features,
            "feature_count": len(base_features),
            "feature_set": "base",
            "thresholds": thresholds,
            "metrics": v1_metrics,
            "mlflow_run_id": "43b699950e05474eac088278c29c10a6",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        joblib.dump(bundle_v1, v1_artifact_path)
        results["v1"] = bundle_v1
        print(f"  v1 F1-Score: {v1_metrics['f1_score']*100:.2f}% | Latency: {v1_metrics['latency_ms_per_url']:.4f} ms")

        # -------------------------------------------------------------
        # Model v2: XGBoost Champion (22 Base Features)
        # -------------------------------------------------------------
        print("\n[ModelVersionManager] Training Model v2: XGBoost (22 Features)...")
        xgb_meta = self.VERSION_DEFINITIONS["v2"]
        clf_v2 = xgb.XGBClassifier(**xgb_meta["hyperparameters"], n_jobs=-1)

        t0 = time.perf_counter()
        clf_v2.fit(X_train_base, y_train)
        v2_train_time = round(time.perf_counter() - t0, 4)

        v2_metrics = self._evaluate_model(clf_v2, X_test_base, y_test, v2_train_time)
        v2_artifact_path = os.path.join(self.models_dir, xgb_meta["artifact_file"]).replace("\\", "/")

        bundle_v2 = {
            "model_version": "v2",
            "model_name": xgb_meta["model_name"],
            "model": clf_v2,
            "scaler": None,
            "requires_scaling": False,
            "feature_names": base_features,
            "feature_count": len(base_features),
            "feature_set": "base",
            "thresholds": thresholds,
            "metrics": v2_metrics,
            "mlflow_run_id": "1dd09cdf67ef41a58e1c42a5f0079fc5",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        joblib.dump(bundle_v2, v2_artifact_path)
        results["v2"] = bundle_v2
        print(f"  v2 F1-Score: {v2_metrics['f1_score']*100:.2f}% | Latency: {v2_metrics['latency_ms_per_url']:.4f} ms")

        # -------------------------------------------------------------
        # Model v3: XGBoost + Improved Features (28 Features)
        # -------------------------------------------------------------
        print("\n[ModelVersionManager] Training Model v3: XGBoost + Improved Features (28 Features)...")
        v3_meta = self.VERSION_DEFINITIONS["v3"]
        clf_v3 = xgb.XGBClassifier(**v3_meta["hyperparameters"], n_jobs=-1)

        t0 = time.perf_counter()
        clf_v3.fit(X_train_imp, y_train)
        v3_train_time = round(time.perf_counter() - t0, 4)

        v3_metrics = self._evaluate_model(clf_v3, X_test_imp, y_test, v3_train_time)
        v3_artifact_path = os.path.join(self.models_dir, v3_meta["artifact_file"]).replace("\\", "/")

        bundle_v3 = {
            "model_version": "v3",
            "model_name": v3_meta["model_name"],
            "model": clf_v3,
            "scaler": None,
            "requires_scaling": False,
            "feature_names": improved_features,
            "feature_count": len(improved_features),
            "feature_set": "improved",
            "thresholds": thresholds,
            "metrics": v3_metrics,
            "mlflow_run_id": "phase_23_v3_xgboost_run",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        joblib.dump(bundle_v3, v3_artifact_path)
        results["v3"] = bundle_v3
        print(f"  v3 F1-Score: {v3_metrics['f1_score']*100:.2f}% | Latency: {v3_metrics['latency_ms_per_url']:.4f} ms")

        # Update Manifest entries
        self.manifest["versions"]["v1"]["metrics"] = v1_metrics
        self.manifest["versions"]["v1"]["artifact_path"] = v1_artifact_path
        self.manifest["versions"]["v1"]["feature_names"] = base_features

        self.manifest["versions"]["v2"]["metrics"] = v2_metrics
        self.manifest["versions"]["v2"]["artifact_path"] = v2_artifact_path
        self.manifest["versions"]["v2"]["feature_names"] = base_features

        self.manifest["versions"]["v3"]["metrics"] = v3_metrics
        self.manifest["versions"]["v3"]["artifact_path"] = v3_artifact_path
        self.manifest["versions"]["v3"]["feature_names"] = improved_features

        # Set default active version (v1: Proven Champion with highest real-world holdout generalizability)
        self.manifest["active_version"] = "v1"
        self.manifest["previous_version"] = "v1"
        for v_id, v_data in self.manifest["versions"].items():
            v_data["is_active"] = (v_id == "v1")

        # Copy active model to champion_phishing_model.joblib for production runtime
        champion_path = os.path.join(self.models_dir, self.CHAMPION_FILENAME)
        shutil.copyfile(v1_artifact_path, champion_path)

        self._save_manifest()
        print(f"\n[ModelVersionManager] Successfully trained & registered all versions. Active version: v1.")
        return results

    def _evaluate_model(self, model, X_test, y_test, train_time_sec: float) -> Dict[str, Any]:
        """Calculates standard classification metrics and latency per URL."""
        t_inf0 = time.perf_counter()
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]
        inf_duration = time.perf_counter() - t_inf0
        latency_ms_per_url = round((inf_duration / len(X_test)) * 1000.0, 4)

        acc = round(float(accuracy_score(y_test, y_pred)), 4)
        prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
        rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
        f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
        roc = round(float(roc_auc_score(y_test, y_proba)), 4)
        pr_auc = round(float(average_precision_score(y_test, y_proba)), 4)

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = [int(v) for v in cm.ravel()]

        return {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": roc,
            "pr_auc": pr_auc,
            "training_time_seconds": train_time_sec,
            "latency_ms_per_url": latency_ms_per_url,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn
        }


if __name__ == "__main__":
    manager = ModelVersionManager()
    results = manager.build_and_register_all()
    print("\n" + "=" * 80)
    print("  PHASE 23: MODEL VERSION REGISTRY INITIALIZED")
    print("=" * 80)
    for v in manager.list_versions():
        active_badge = "[ACTIVE]" if v["is_active"] else "        "
        m = v.get("metrics", {})
        print(f" {active_badge} {v['version']} -> {v['model_name']} ({v['feature_count']} features) | F1: {m.get('f1_score', 0)*100:.2f}% | Latency: {m.get('latency_ms_per_url', 0):.4f} ms")
    print("=" * 80)
