"""
Phishing Detection & Risk Intelligence Platform
Phase 8: Baseline Model Training (Logistic Regression)
Computes Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC, and Confusion Matrix.
Serializes trained baseline model and preprocessing artifacts into models/.
"""

import os
import json
import time
from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

from src.features.extractor import FeatureExtractor


class BaselineTrainer:
    """
    Trains and evaluates a Logistic Regression baseline model
    establishing a reference benchmark for URL phishing classification.
    """
    def __init__(
        self,
        features_csv: str = "data/processed/features.csv",
        models_dir: str = "models",
        random_state: int = 42
    ):
        self.features_csv = features_csv
        self.models_dir = models_dir
        self.random_state = random_state
        os.makedirs(self.models_dir, exist_ok=True)

        if not os.path.exists(features_csv):
            raise FileNotFoundError(f"Feature dataset not found at {features_csv}")

    def load_and_split_data(self, test_size: float = 0.20):
        df = pd.read_csv(self.features_csv)
        feature_cols = FeatureExtractor.FEATURE_NAMES

        # Ensure all required features are present
        X = df[feature_cols].copy()
        y = df["label"].astype(int).values

        # Handle any possible NaN values by filling with 0
        X = X.fillna(0)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=test_size,
            random_state=self.random_state,
            stratify=y
        )
        return X_train, X_test, y_train, y_test, feature_cols

    def train_and_evaluate(self) -> Tuple[Dict[str, Any], str]:
        X_train, X_test, y_train, y_test, feature_cols = self.load_and_split_data()

        # Scale features for numerical stability in linear models
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Train Logistic Regression
        t0 = time.perf_counter()
        model = LogisticRegression(
            max_iter=1000,
            C=1.0,
            solver="lbfgs",
            random_state=self.random_state
        )
        model.fit(X_train_scaled, y_train)
        train_time = round(time.perf_counter() - t0, 4)

        # Predict classes and continuous probabilities
        t_inf0 = time.perf_counter()
        y_pred = model.predict(X_test_scaled)
        y_proba = model.predict_proba(X_test_scaled)[:, 1]
        t_inf = round((time.perf_counter() - t_inf0) / len(X_test) * 1000, 4)

        # Calculate security evaluation metrics
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        metrics = {
            "model_name": "Logistic Regression (Baseline)",
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
            "precision": round(float(precision_score(y_test, y_pred)), 4),
            "recall": round(float(recall_score(y_test, y_pred)), 4),
            "f1_score": round(float(f1_score(y_test, y_pred)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
            "pr_auc": round(float(average_precision_score(y_test, y_proba)), 4),
            "train_time_sec": train_time,
            "inference_latency_ms": t_inf,
            "confusion_matrix": {
                "tp": int(tp),
                "fp": int(fp),
                "tn": int(tn),
                "fn": int(fn)
            },
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test))
        }

        # Save artifacts (model + scaler + feature_names)
        artifact_path = os.path.join(self.models_dir, "baseline_logistic_regression.joblib")
        joblib.dump({
            "model": model,
            "scaler": scaler,
            "feature_names": feature_cols,
            "metrics": metrics
        }, artifact_path)

        # Save metrics JSON
        metrics_path = os.path.join(self.models_dir, "baseline_metrics.json")
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        return metrics, artifact_path


if __name__ == "__main__":
    trainer = BaselineTrainer()
    metrics, path = trainer.train_and_evaluate()
    print("=" * 65)
    print("  PHASE 8: BASELINE LOGISTIC REGRESSION BENCHMARK")
    print("=" * 65)
    print(f"Artifact Saved to   : {path}")
    print(f"Training Time       : {metrics['train_time_sec']}s")
    print(f"Inference Latency   : {metrics['inference_latency_ms']} ms/URL")
    print("-" * 65)
    print(f"Accuracy            : {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision           : {metrics['precision'] * 100:.2f}%")
    print(f"Recall              : {metrics['recall'] * 100:.2f}%")
    print(f"F1-Score            : {metrics['f1_score'] * 100:.2f}%")
    print(f"ROC-AUC             : {metrics['roc_auc']:.4f}")
    print(f"PR-AUC              : {metrics['pr_auc']:.4f}")
    print("-" * 65)
    print(f"Confusion Matrix    : TP={metrics['confusion_matrix']['tp']}, FP={metrics['confusion_matrix']['fp']}, "
          f"TN={metrics['confusion_matrix']['tn']}, FN={metrics['confusion_matrix']['fn']}")
    print("=" * 65)
