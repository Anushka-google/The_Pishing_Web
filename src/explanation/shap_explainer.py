"""
Phishing Detection & Risk Intelligence Platform
Phase 13: Model Explainability Engine (Global Feature Importance & Local SHAP Attributions)

Provides transparent, human-auditable explanations for every prediction using
SHapley Additive exPlanations (SHAP) TreeExplainer:
1. Global Feature Importance: Mean absolute impact of each feature across representative data.
2. Local Attributions: For any incoming URL, precisely attributes which features increased
   the phishing risk (positive contributors) vs. which decreased it (mitigating factors).
3. Human-Readable Security Verdict: Translates mathematical SHAP values into actionable advice.
"""

import os
import json
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
import joblib
import shap

from src.features.extractor import FeatureExtractor


class PhishingExplainer:
    def __init__(
        self,
        model_path: str = "models/champion_phishing_model.joblib",
        features_csv: str = "data/processed/features.csv"
    ):
        self.model_path = model_path
        self.features_csv = features_csv

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Champion model not found at {model_path}")

        self.pkg = joblib.load(model_path)
        self.model = self.pkg["model"]
        self.scaler = self.pkg.get("scaler")
        self.feature_names = self.pkg.get("feature_names", FeatureExtractor.FEATURE_NAMES)
        feature_set = "improved" if len(self.feature_names) > 22 else "base"
        self.extractor = FeatureExtractor(feature_set=feature_set)
        self.thresholds = self.pkg.get("thresholds", {"t1_low": 0.40, "t2_high": 0.65, "t_optimal": 0.50})

        # Initialize SHAP TreeExplainer
        # For RandomForest / Tree ensembles, TreeExplainer is exact and fast
        self.explainer = shap.TreeExplainer(self.model)

    def compute_global_importance(self, sample_size: int = 500) -> Dict[str, Any]:
        """Calculates global mean |SHAP| feature importance on a background sample."""
        if not os.path.exists(self.features_csv):
            raise FileNotFoundError(f"Feature dataset not found at {self.features_csv}")

        df = pd.read_csv(self.features_csv)
        sample_df = df[self.feature_names].sample(min(sample_size, len(df)), random_state=42)
        X_sample = sample_df.values

        if self.scaler is not None:
            X_sample = self.scaler.transform(X_sample)

        shap_values = self.explainer.shap_values(X_sample)

        # For binary classification:
        # shap_values can be a list [class_0, class_1] or a 3D array (samples, features, 2)
        if isinstance(shap_values, list):
            vals_phish = shap_values[1]  # positive class (phishing)
        elif len(shap_values.shape) == 3:
            vals_phish = shap_values[:, :, 1]
        else:
            vals_phish = shap_values

        mean_abs_shap = np.mean(np.abs(vals_phish), axis=0)
        importance_ranking = []
        for name, score in zip(self.feature_names, mean_abs_shap):
            importance_ranking.append({
                "feature": name,
                "mean_abs_shap": round(float(score), 4)
            })

        importance_ranking.sort(key=lambda x: x["mean_abs_shap"], reverse=True)

        global_report = {
            "model_name": self.pkg.get("model_name", "ChampionModel"),
            "sample_size": len(sample_df),
            "rankings": importance_ranking
        }

        os.makedirs("data/processed", exist_ok=True)
        with open("data/processed/global_shap_importance.json", "w", encoding="utf-8") as f:
            json.dump(global_report, f, indent=2)

        return global_report

    def explain_vector(self, feature_vector: List[float], top_k: int = 5) -> Dict[str, Any]:
        """Generates local SHAP explanation for a given 22-dimensional feature vector."""
        X = np.array(feature_vector, dtype=float).reshape(1, -1)
        if self.scaler is not None:
            X = self.scaler.transform(X)

        proba = float(self.model.predict_proba(X)[0, 1])

        # SHAP attribution
        shap_vals = self.explainer.shap_values(X)
        if isinstance(shap_vals, list):
            sv = shap_vals[1][0]
        elif len(shap_vals.shape) == 3:
            sv = shap_vals[0, :, 1]
        else:
            sv = shap_vals[0]

        expected_val = self.explainer.expected_value
        if isinstance(expected_val, (list, np.ndarray)):
            base_value = float(expected_val[1])
        else:
            base_value = float(expected_val)

        attributions = []
        for name, raw_val, shap_val in zip(self.feature_names, feature_vector, sv):
            attributions.append({
                "feature": name,
                "value": float(raw_val),
                "shap_impact": round(float(shap_val), 4),
                "direction": "RISK_INCREASING" if shap_val > 0 else "RISK_DECREASING"
            })

        # Rank contributors
        pos_contributors = sorted([a for a in attributions if a["shap_impact"] > 0],
                                  key=lambda x: x["shap_impact"], reverse=True)[:top_k]
        neg_contributors = sorted([a for a in attributions if a["shap_impact"] < 0],
                                  key=lambda x: abs(x["shap_impact"]), reverse=True)[:top_k]

        # Determine risk level
        t1 = self.thresholds.get("t1_low", 0.40)
        t2 = self.thresholds.get("t2_high", 0.65)
        if proba < t1:
            risk_level = "LOW"
            action = "ALLOW"
        elif proba < t2:
            risk_level = "MEDIUM"
            action = "CAUTION"
        else:
            risk_level = "HIGH"
            action = "BLOCK"

        # Generate human-readable narrative
        signals_summary = [
            f"{c['feature'].replace('_', ' ').capitalize()} (+{c['shap_impact']:.3f})"
            for c in pos_contributors[:3]
        ]
        mitigators_summary = [
            f"{c['feature'].replace('_', ' ').capitalize()} ({c['shap_impact']:.3f})"
            for c in neg_contributors[:2]
        ]

        return {
            "phishing_probability": round(proba, 4),
            "risk_level": risk_level,
            "action": action,
            "base_value": round(base_value, 4),
            "top_risk_contributors": pos_contributors,
            "top_mitigating_factors": neg_contributors,
            "narrative_signals": signals_summary,
            "narrative_mitigators": mitigators_summary,
            "recommendation": (
                "Do not submit sensitive credentials or download files from this origin until verified."
                if risk_level == "HIGH" else
                "Exercise caution and verify domain spelling."
                if risk_level == "MEDIUM" else
                "URL conforms to expected benign web standards."
            )
        }

    def explain_url(self, url: str, top_k: int = 5) -> Dict[str, Any]:
        """Convenience method: Extracts features from URL and returns full explanation."""
        vector = self.extractor.extract_features_vector(url)
        result = self.explain_vector(vector.tolist(), top_k=top_k)
        result["url"] = url
        return result


if __name__ == "__main__":
    explainer = PhishingExplainer()

    print("=" * 70)
    print("  PHASE 13: COMPUTING GLOBAL SHAP FEATURE IMPORTANCE")
    print("=" * 70)
    global_res = explainer.compute_global_importance(sample_size=300)
    print("Top 5 Globally Most Influential Features:")
    for rank, item in enumerate(global_res["rankings"][:5], 1):
        print(f"  {rank}. {item['feature']:<28} : Mean |SHAP| = {item['mean_abs_shap']:.4f}")

    print("\n" + "=" * 70)
    print("  PHASE 13: LOCAL PREDICTION EXPLANATIONS (TEST EXAMPLES)")
    print("=" * 70)

    test_urls = [
        "https://accounts.google.com/signin/v2/identifier",
        "https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284"
    ]

    for test_url in test_urls:
        explanation = explainer.explain_url(test_url)
        print(f"\nURL: {test_url}")
        print(f"Probability : {explanation['phishing_probability']:.4f} | Risk: {explanation['risk_level']} | Action: {explanation['action']}")
        print("Primary Risk Indicators:")
        for r in explanation["top_risk_contributors"][:3]:
            print(f"  + {r['feature']:<25} (val={r['value']}): impact = +{r['shap_impact']:.4f}")
        print("Primary Mitigating Factors:")
        for m in explanation["top_mitigating_factors"][:2]:
            print(f"  - {m['feature']:<25} (val={m['value']}): impact = {m['shap_impact']:.4f}")
        print(f"Recommendation: {explanation['recommendation']}")

    print("\n" + "=" * 70)
    print("Global SHAP importance exported to: data/processed/global_shap_importance.json")
    print("=" * 70)
