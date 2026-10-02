"""
Phishing Detection & Risk Intelligence Platform
Phase 11: Leakage-Safe Evaluation with Domain-Grouped Splitting
Compares Naive Random Train/Test Split (Overfitting) vs. Domain-Grouped Split (Leakage-Safe).
Enforces: Train Domains ∩ Test Domains = Ø (Zero Domain Leakage).
"""

import os
import json
import time
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import tldextract

from sklearn.model_selection import train_test_split, GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)

from src.features.extractor import FeatureExtractor


class LeakageSafeEvaluator:
    """
    Evaluates models under both:
    1. Naive Random Split (Demonstrates over-optimistic leakage / memorization)
    2. Domain-Grouped Split (Proves true generalization to unseen zero-day domains)
    """
    def __init__(self, features_csv: str = "data/processed/features.csv", random_state: int = 42):
        self.features_csv = features_csv
        self.random_state = random_state
        self.tld_extractor = tldextract.TLDExtract()

        if not os.path.exists(features_csv):
            raise FileNotFoundError(f"Feature dataset not found at {features_csv}")

        self.df = pd.read_csv(features_csv)
        self.feature_cols = FeatureExtractor.FEATURE_NAMES

        # Extract registered domain for each URL to serve as group identifier
        self.df["domain_group"] = self.df["url"].apply(self._extract_domain)

    def _extract_domain(self, url: str) -> str:
        try:
            ext = self.tld_extractor(url)
            domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
            if domain:
                return domain.lower()
            return urlparse(url).netloc.split(":")[0].lower()
        except Exception:
            return "unknown"

    def evaluate_split(
        self,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_train: np.ndarray,
        y_test: np.ndarray,
        split_name: str
    ) -> List[Dict[str, Any]]:
        # Scaler for linear model
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        models = [
            ("Logistic Regression", LogisticRegression(max_iter=1000, random_state=self.random_state), True),
            ("Decision Tree", DecisionTreeClassifier(max_depth=10, min_samples_split=5, random_state=self.random_state), False),
            ("Random Forest", RandomForestClassifier(n_estimators=100, max_depth=12, random_state=self.random_state, n_jobs=-1), False),
            ("XGBoost", xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, eval_metric="logloss", random_state=self.random_state, n_jobs=-1), False)
        ]

        results = []
        for name, clf, requires_scaling in models:
            X_tr = X_train_scaled if requires_scaling else X_train
            X_te = X_test_scaled if requires_scaling else X_test

            clf.fit(X_tr, y_train)
            y_pred = clf.predict(X_te)
            y_proba = clf.predict_proba(X_te)[:, 1]

            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = cm.ravel()

            results.append({
                "split_strategy": split_name,
                "model": name,
                "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
                "precision": round(float(precision_score(y_test, y_pred)), 4),
                "recall": round(float(recall_score(y_test, y_pred)), 4),
                "f1_score": round(float(f1_score(y_test, y_pred)), 4),
                "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
                "pr_auc": round(float(average_precision_score(y_test, y_proba)), 4),
                "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}
            })
        return results

    def run_comparative_audit(self) -> Dict[str, Any]:
        X = self.df[self.feature_cols].copy().fillna(0).values
        y = self.df["label"].astype(int).values
        groups = self.df["domain_group"].values

        # 1. Naive Random Split (Vulnerable to domain leakage)
        X_tr_rnd, X_te_rnd, y_tr_rnd, y_te_rnd = train_test_split(
            X, y, test_size=0.20, random_state=self.random_state, stratify=y
        )
        naive_results = self.evaluate_split(X_tr_rnd, X_te_rnd, y_tr_rnd, y_te_rnd, "Naive Random Split (Leakage Prone)")

        # 2. Domain-Grouped Split (Leakage-Safe, 100% disjoint domain spaces)
        gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=self.random_state)
        train_idx, test_idx = next(gss.split(X, y, groups=groups))

        X_tr_grp, X_te_grp = X[train_idx], X[test_idx]
        y_tr_grp, y_te_grp = y[train_idx], y[test_idx]

        train_domains = set(groups[train_idx])
        test_domains = set(groups[test_idx])
        domain_overlap = len(train_domains.intersection(test_domains))

        grouped_results = self.evaluate_split(X_tr_grp, X_te_grp, y_tr_grp, y_te_grp, "Domain-Grouped Split (Leakage Safe)")

        audit = {
            "total_samples": len(self.df),
            "unique_domains": len(set(groups)),
            "train_domains_count": len(train_domains),
            "test_domains_count": len(test_domains),
            "domain_leakage_overlap": domain_overlap,
            "naive_random_results": naive_results,
            "leakage_safe_results": grouped_results
        }

        # Export audit to disk
        out_path = "data/processed/leakage_audit.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(audit, f, indent=2)

        return audit


if __name__ == "__main__":
    evaluator = LeakageSafeEvaluator()
    audit = evaluator.run_comparative_audit()

    print("=" * 80)
    print("  LEAKAGE-SAFE EVALUATION AUDIT (DOMAIN GENERALIZATION)")
    print("=" * 80)
    print(f"Total Records     : {audit['total_samples']:,}")
    print(f"Unique Domains    : {audit['unique_domains']:,}")
    print(f"Domain Overlap    : {audit['domain_leakage_overlap']} (Zero Leakage Guaranteed!)")
    print("-" * 80)

    print("\n--- 1. NAIVE RANDOM SPLIT (Prone to Overfitting & Memorization) ---")
    print(f"{'Model':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'ROC-AUC':<8}")
    for r in audit["naive_random_results"]:
        print(f"{r['model']:<22} | {r['accuracy']*100:6.2f}%   | {r['precision']*100:6.2f}%   | {r['recall']*100:6.2f}%  | {r['f1_score']*100:6.2f}%  | {r['roc_auc']:<8.4f}")

    print("\n--- 2. LEAKAGE-SAFE DOMAIN-GROUPED SPLIT (True Unseen Domain Generalization) ---")
    print(f"{'Model':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'ROC-AUC':<8}")
    for r in audit["leakage_safe_results"]:
        print(f"{r['model']:<22} | {r['accuracy']*100:6.2f}%   | {r['precision']*100:6.2f}%   | {r['recall']*100:6.2f}%  | {r['f1_score']*100:6.2f}%  | {r['roc_auc']:<8.4f}")
    print("=" * 80)
