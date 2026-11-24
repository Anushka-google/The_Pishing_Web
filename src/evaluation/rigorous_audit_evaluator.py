"""
PhishIntel — Comprehensive Model Evaluation & Generalization Stress-Test Engine
Phase 6 & 7: Calculates all 11 evaluation metrics from raw y_test and y_pred.
Enforces:
1. Zero domain leakage via GroupShuffleSplit
2. Separate preprocessing (StandardScaler fit on train only)
3. Evaluates Logistic Regression, Decision Tree, Random Forest, and XGBoost.
"""

import os
import sys
import json
import time
from typing import Dict, Any, List

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pandas as pd
import numpy as np
import tldextract
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    balanced_accuracy_score
)

from src.features.extractor import FeatureExtractor


class RigorousAuditEvaluator:
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.feature_cols = FeatureExtractor.FEATURE_NAMES
        self.cache_dir = os.path.join(PROJECT_ROOT, ".cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.tld_extractor = tldextract.TLDExtract(cache_dir=self.cache_dir, suffix_list_urls=None)

    def _extract_domain(self, url: str) -> str:
        try:
            ext = self.tld_extractor(url)
            reg = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
            if reg:
                return reg.lower()
            return "unknown"
        except Exception:
            return "unknown"

    def _compute_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray, model_name: str, split_name: str, train_time: float, inf_time: float) -> Dict[str, Any]:
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = [int(v) for v in cm.ravel()]

        accuracy = float(accuracy_score(y_true, y_pred))
        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))
        roc_auc = float(roc_auc_score(y_true, y_proba))
        pr_auc = float(average_precision_score(y_true, y_proba))
        balanced_acc = float(balanced_accuracy_score(y_true, y_pred))

        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        specificity = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0

        return {
            "split_strategy": split_name,
            "model": model_name,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "balanced_accuracy": round(balanced_acc, 4),
            "specificity": round(specificity, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "train_time_sec": round(train_time, 4),
            "inference_latency_ms": round(inf_time, 4),
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
        }

    def _train_and_evaluate(self, X_tr: np.ndarray, X_te: np.ndarray, y_tr: np.ndarray, y_te: np.ndarray, split_name: str) -> List[Dict[str, Any]]:
        scaler = StandardScaler()
        X_tr_scaled = scaler.fit_transform(X_tr)
        X_te_scaled = scaler.transform(X_te)

        models = [
            ("Logistic Regression", LogisticRegression(max_iter=1000, random_state=self.random_state), True),
            ("Decision Tree", DecisionTreeClassifier(max_depth=10, min_samples_split=5, random_state=self.random_state), False),
            ("Random Forest", RandomForestClassifier(n_estimators=100, max_depth=12, random_state=self.random_state, n_jobs=-1), False),
            ("XGBoost", xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, eval_metric="logloss", random_state=self.random_state, n_jobs=-1), False)
        ]

        results = []
        for name, clf, requires_scale in models:
            X_train = X_tr_scaled if requires_scale else X_tr
            X_test = X_te_scaled if requires_scale else X_te

            t0 = time.perf_counter()
            clf.fit(X_train, y_tr)
            t_train = time.perf_counter() - t0

            t1 = time.perf_counter()
            y_pred = clf.predict(X_test)
            y_proba = clf.predict_proba(X_test)[:, 1]
            t_inf = ((time.perf_counter() - t1) / len(X_test)) * 1000

            metrics = self._compute_metrics(y_te, y_pred, y_proba, name, split_name, t_train, t_inf)
            results.append(metrics)

        return results

    def audit_dataset(self, csv_path: str, dataset_label: str) -> Dict[str, Any]:
        df = pd.read_csv(csv_path)
        
        if "registered_domain" not in df.columns:
            df["registered_domain"] = df["url"].apply(self._extract_domain)

        X = df[self.feature_cols].copy().fillna(0).values
        y = df["label"].astype(int).values
        groups = df["registered_domain"].fillna("unknown").values

        # 1. Naive Random Split
        X_tr_rnd, X_te_rnd, y_tr_rnd, y_te_rnd = train_test_split(
            X, y, test_size=0.20, random_state=self.random_state, stratify=y
        )
        naive_results = self._train_and_evaluate(X_tr_rnd, X_te_rnd, y_tr_rnd, y_te_rnd, "Naive Random Split")

        # 2. Domain-Grouped Split (Leakage-Safe)
        gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=self.random_state)
        train_idx, test_idx = next(gss.split(X, y, groups=groups))

        train_domains = set(groups[train_idx])
        test_domains = set(groups[test_idx])
        domain_overlap = len(train_domains.intersection(test_domains))
        assert domain_overlap == 0, f"Domain leakage detected: {domain_overlap} overlapping domains!"

        # Assert no shared URLs
        train_urls = set(df.iloc[train_idx]["url"].str.strip().str.lower())
        test_urls = set(df.iloc[test_idx]["url"].str.strip().str.lower())
        assert train_urls.isdisjoint(test_urls), "Duplicate URLs leaked across train and test partitions!"

        grouped_results = self._train_and_evaluate(X[train_idx], X[test_idx], y[train_idx], y[test_idx], "Domain-Grouped Split")

        return {
            "dataset_label": dataset_label,
            "dataset_path": csv_path,
            "total_samples": len(df),
            "unique_domains": len(set(groups)),
            "train_samples": len(train_idx),
            "test_samples": len(test_idx),
            "train_domains_count": len(train_domains),
            "test_domains_count": len(test_domains),
            "domain_overlap": domain_overlap,
            "naive_random_results": naive_results,
            "domain_grouped_results": grouped_results
        }


def run_full_audit():
    evaluator = RigorousAuditEvaluator()

    # 1. Audit Synthetic Dataset
    synth_path = os.path.join(PROJECT_ROOT, "data", "processed", "features.csv")
    synth_audit = evaluator.audit_dataset(synth_path, "Synthetic Template Dataset")

    # 2. Audit Authentic Real-World Dataset
    auth_path = os.path.join(PROJECT_ROOT, "data", "real_world", "features_real_world.csv")
    auth_audit = evaluator.audit_dataset(auth_path, "Authentic Real-World Dataset")

    # Compile Master Audit
    master_audit = {
        "audit_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "synthetic_benchmark": synth_audit,
        "authentic_benchmark": auth_audit
    }

    out_file = os.path.join(PROJECT_ROOT, "data", "processed", "complete_audit_report.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(master_audit, f, indent=2)

    print(f"Master Audit Report saved to: {out_file}")
    return master_audit


if __name__ == "__main__":
    run_full_audit()
