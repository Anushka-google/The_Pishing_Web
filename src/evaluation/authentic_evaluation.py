"""
Phishing Detection & Risk Intelligence Platform
Authentic Evaluation Engine
Evaluates Logistic Regression, Decision Tree, Random Forest, and XGBoost across:
1. Domain-Grouped Split (Zero Domain Overlap via GroupShuffleSplit)
2. Time-Based Chronological Split (Train on Past, Test on Future)
3. Independent External Holdout (Model trained on Dev Set tested on 100% Unseen Authentic Wild Data)

Reports: Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, Latency, and Confusion Matrix.
"""

import os
import json
import time
from typing import Dict, Any, List, Tuple, Set
import pandas as pd
import numpy as np

from sklearn.model_selection import GroupShuffleSplit
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


class AuthenticEvaluator:
    """
    Executes rigorous evaluation across domain-grouped, time-based, and holdout splits.
    """
    def __init__(
        self,
        authentic_features_csv: str = "data/real_world/features_real_world.csv",
        dev_features_csv: str = "data/processed/features.csv",
        random_state: int = 42
    ):
        self.authentic_features_csv = authentic_features_csv
        self.dev_features_csv = dev_features_csv
        self.random_state = random_state
        self.feature_cols = FeatureExtractor.FEATURE_NAMES

        if not os.path.exists(authentic_features_csv):
            raise FileNotFoundError(f"Authentic features dataset not found at {authentic_features_csv}")

        self.df_auth = pd.read_csv(authentic_features_csv)
        self.df_dev = pd.read_csv(dev_features_csv) if os.path.exists(dev_features_csv) else None

    def _evaluate_models(
        self,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_train: np.ndarray,
        y_test: np.ndarray,
        split_name: str
    ) -> List[Dict[str, Any]]:
        """Fits and benchmarks the 4 target classifier architectures."""
        scaler = StandardScaler()
        X_tr_scaled = scaler.fit_transform(X_train)
        X_te_scaled = scaler.transform(X_test)

        models = [
            ("Logistic Regression", LogisticRegression(max_iter=1000, random_state=self.random_state), True),
            ("Decision Tree", DecisionTreeClassifier(max_depth=10, min_samples_split=5, random_state=self.random_state), False),
            ("Random Forest", RandomForestClassifier(n_estimators=100, max_depth=12, random_state=self.random_state, n_jobs=-1), False),
            ("XGBoost", xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, eval_metric="logloss", random_state=self.random_state, n_jobs=-1), False)
        ]

        results = []
        for name, clf, requires_scaling in models:
            X_tr = X_tr_scaled if requires_scaling else X_train
            X_te = X_te_scaled if requires_scaling else X_test

            t0 = time.perf_counter()
            clf.fit(X_tr, y_train)
            train_time = round(time.perf_counter() - t0, 4)

            t1 = time.perf_counter()
            y_pred = clf.predict(X_te)
            y_proba = clf.predict_proba(X_te)[:, 1]
            inf_time_per_url = round(((time.perf_counter() - t1) / len(X_test)) * 1000, 4)

            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = [int(v) for v in cm.ravel()]

            fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
            fnr = round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0

            results.append({
                "split_strategy": split_name,
                "model": name,
                "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
                "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
                "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
                "f1_score": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
                "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
                "pr_auc": round(float(average_precision_score(y_test, y_proba)), 4),
                "false_positive_rate": fpr,
                "false_negative_rate": fnr,
                "train_time_sec": train_time,
                "inference_latency_ms": inf_time_per_url,
                "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
            })
        return results

    def run_domain_grouped_evaluation(self) -> Dict[str, Any]:
        """Strategy 1: Domain-Grouped Split (Zero Domain Overlap)."""
        X = self.df_auth[self.feature_cols].copy().fillna(0).values
        y = self.df_auth["label"].astype(int).values
        groups = self.df_auth["registered_domain"].fillna("unknown").values

        gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=self.random_state)
        train_idx, test_idx = next(gss.split(X, y, groups=groups))

        train_domains = set(groups[train_idx])
        test_domains = set(groups[test_idx])
        domain_overlap = len(train_domains.intersection(test_domains))
        assert domain_overlap == 0, f"Domain leakage detected: {domain_overlap} overlapping domains!"

        results = self._evaluate_models(
            X[train_idx], X[test_idx], y[train_idx], y[test_idx],
            "Domain-Grouped Split (Zero Domain Overlap)"
        )

        return {
            "strategy": "domain_grouped",
            "train_samples": len(train_idx),
            "test_samples": len(test_idx),
            "train_domains_count": len(train_domains),
            "test_domains_count": len(test_domains),
            "domain_overlap": domain_overlap,
            "models": results
        }

    def run_time_based_evaluation(self) -> Dict[str, Any]:
        """Strategy 2: Time-Based Chronological Split (Train on Past, Test on Future)."""
        df_sorted = self.df_auth.sort_values(by="collection_timestamp", ascending=True).reset_index(drop=True)
        split_idx = int(len(df_sorted) * 0.80)

        train_df = df_sorted.iloc[:split_idx]
        test_df = df_sorted.iloc[split_idx:]

        earliest_train = str(train_df["collection_timestamp"].min())
        latest_train = str(train_df["collection_timestamp"].max())
        earliest_test = str(test_df["collection_timestamp"].min())
        latest_test = str(test_df["collection_timestamp"].max())

        X_tr = train_df[self.feature_cols].copy().fillna(0).values
        y_tr = train_df["label"].astype(int).values
        X_te = test_df[self.feature_cols].copy().fillna(0).values
        y_te = test_df["label"].astype(int).values

        results = self._evaluate_models(
            X_tr, X_te, y_tr, y_te,
            "Time-Based Chronological Split (Temporal Generalization)"
        )

        return {
            "strategy": "time_based_chronological",
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "train_date_range": f"{earliest_train} to {latest_train}",
            "test_date_range": f"{earliest_test} to {latest_test}",
            "models": results
        }

    def run_independent_external_holdout(self) -> Dict[str, Any]:
        """Strategy 3: Independent External Holdout (Model trained on Dev Set tested on Authentic Wild Data)."""
        if self.df_dev is None:
            return {"error": "Development features dataset not found for holdout comparison."}

        # Train on Development Dataset
        X_dev = self.df_dev[self.feature_cols].copy().fillna(0).values
        y_dev = self.df_dev["label"].astype(int).values

        # Ensure test holdout is 100% disjoint in domains from Dev
        dev_domains = set(self.df_dev["url"].apply(lambda u: u.split("/")[2].split(":")[0].lower() if "://" in u else u))
        auth_domains = set(self.df_auth["registered_domain"].fillna("unknown"))
        overlapping = dev_domains.intersection(auth_domains)

        # Filter out any domains that were in Dev
        df_test_disjoint = self.df_auth[~self.df_auth["registered_domain"].isin(overlapping)].copy()

        X_auth = df_test_disjoint[self.feature_cols].copy().fillna(0).values
        y_auth = df_test_disjoint["label"].astype(int).values

        results = self._evaluate_models(
            X_dev, X_auth, y_dev, y_auth,
            "Independent External Holdout (Dev -> Authentic Wild)"
        )

        return {
            "strategy": "independent_external_holdout",
            "train_samples_dev": len(X_dev),
            "test_samples_authentic": len(X_auth),
            "disjoint_domains_evaluated": df_test_disjoint["registered_domain"].nunique(),
            "models": results
        }

    def run_full_suite(self) -> Dict[str, Any]:
        """Executes all 3 evaluation strategies and saves comprehensive report."""
        print("[Evaluator] Executing Strategy 1: Domain-Grouped Split...")
        domain_report = self.run_domain_grouped_evaluation()

        print("[Evaluator] Executing Strategy 2: Time-Based Chronological Split...")
        time_report = self.run_time_based_evaluation()

        print("[Evaluator] Executing Strategy 3: Independent External Holdout...")
        holdout_report = self.run_independent_external_holdout()

        full_report = {
            "audit_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "total_authentic_samples": len(self.df_auth),
            "unique_registered_domains": int(self.df_auth["registered_domain"].nunique()),
            "domain_grouped_split": domain_report,
            "time_based_split": time_report,
            "independent_external_holdout": holdout_report
        }

        out_path = "data/real_world/authentic_benchmark_report.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(full_report, f, indent=2)
        print(f"[Evaluator] Saved full benchmark report to: {out_path}")

        return full_report


def print_table(results: List[Dict[str, Any]], title: str):
    print("\n" + "=" * 92)
    print(f"  {title.upper()}")
    print("=" * 92)
    header = f"{'Model':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'ROC-AUC':<8} | {'FPR':<7} | {'FNR':<7}"
    print(header)
    print("-" * 92)
    for r in results:
        print(
            f"{r['model']:<22} | "
            f"{r['accuracy']*100:6.2f}%   | "
            f"{r['precision']*100:6.2f}%   | "
            f"{r['recall']*100:6.2f}%  | "
            f"{r['f1_score']*100:6.2f}%  | "
            f"{r['roc_auc']:<8.4f} | "
            f"{r['false_positive_rate']*100:5.2f}%  | "
            f"{r['false_negative_rate']*100:5.2f}%"
        )
    print("=" * 92)


if __name__ == "__main__":
    evaluator = AuthenticEvaluator()
    report = evaluator.run_full_suite()

    print_table(report["domain_grouped_split"]["models"], "Strategy 1: Domain-Grouped Split (0% Domain Overlap)")
    print_table(report["time_based_split"]["models"], "Strategy 2: Time-Based Chronological Split (Past -> Future)")
    print_table(report["independent_external_holdout"]["models"], "Strategy 3: Independent External Holdout (Dev -> Authentic Wild)")
