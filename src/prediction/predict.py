"""
Phishing Detection & Risk Intelligence Platform
Phase 14: Production Inference Pipeline

Encapsulates the end-to-end inference flow:
Raw URL -> Feature Extraction -> Standardized Scaling (if applicable)
        -> Model Inference -> Calibrated Risk Tiering -> SHAP Attribution

Strict separation of inference logic from training code to prevent training/serving skew.
"""

import os
import sys
import time
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
import joblib

from src.features.extractor import FeatureExtractor
from src.explanation.shap_explainer import PhishingExplainer
from src.models.version_manager import ModelVersionManager


class ProductionPredictor:
    def __init__(
        self,
        model_path: Optional[str] = None,
        version: Optional[str] = None,
        enable_shap: bool = True
    ):
        self.enable_shap = enable_shap
        self.manager = ModelVersionManager()

        if version is not None:
            self.model_version = version
            self.model_path = self.manager.get_version_info(version)["artifact_path"]
        elif model_path is not None:
            self.model_path = model_path
            self.model_version = None
        else:
            active_info = self.manager.get_active_version_info()
            self.model_path = active_info["artifact_path"]
            self.model_version = active_info["version"]

        self._explainer: Optional[PhishingExplainer] = None
        self._load_model_bundle()

    def _load_model_bundle(self):
        if not os.path.exists(self.model_path):
            champion_fallback = "models/champion_phishing_model.joblib"
            if os.path.exists(champion_fallback):
                self.model_path = champion_fallback
            else:
                raise FileNotFoundError(f"Trained model artifact not found at: {self.model_path}")

        self.pkg = joblib.load(self.model_path)
        self.model = self.pkg["model"]
        self.scaler = self.pkg.get("scaler")
        self.model_name = self.pkg.get("model_name", "RandomForestClassifier")
        self.model_version = self.pkg.get("model_version", self.model_version or "v1")
        self.feature_names = self.pkg.get("feature_names", FeatureExtractor.FEATURE_NAMES)

        # Automatically select appropriate feature extractor configuration
        feature_set = "improved" if len(self.feature_names) > 22 else "base"
        self.extractor = FeatureExtractor(feature_set=feature_set)

        # Load calibrated thresholds
        thresholds = self.pkg.get("thresholds", {})
        self.t1_low = float(thresholds.get("t1_low", 0.40))
        self.t2_high = float(thresholds.get("t2_high", 0.65))
        self.t_optimal = float(thresholds.get("t_optimal", 0.50))

        # Invalidate cached explainer to bind to current weights
        self._explainer = None

    def switch_version(self, target_version: str) -> Dict[str, Any]:
        """Dynamically hot-swaps active production model version with zero downtime."""
        info = self.manager.set_active_version(target_version)
        self.model_path = info["artifact_path"]
        self.model_version = info["version"]
        self._load_model_bundle()
        return info

    def rollback(self) -> str:
        """Rolls back to the previous model version dynamically."""
        new_version = self.manager.rollback()
        info = self.manager.get_version_info(new_version)
        self.model_path = info["artifact_path"]
        self.model_version = info["version"]
        self._load_model_bundle()
        return new_version

    @property
    def explainer(self) -> PhishingExplainer:
        if self._explainer is None:
            self._explainer = PhishingExplainer(model_path=self.model_path)
        return self._explainer

    def predict(self, url: str, include_explanation: bool = True) -> Dict[str, Any]:
        """Runs the complete production inference pipeline for a single URL."""
        t0 = time.perf_counter()

        # 1. Feature Extraction (identical logic used during training)
        t_feat0 = time.perf_counter()
        raw_feature_dict = self.extractor.extract_features_dict(url)
        vector = np.array([raw_feature_dict[name] for name in self.feature_names], dtype=np.float32).reshape(1, -1)
        feat_time_ms = (time.perf_counter() - t_feat0) * 1000

        # 2. Scaling (if applicable) and DataFrame formatting
        if self.scaler is not None:
            scaled = self.scaler.transform(vector)
            X = pd.DataFrame(scaled, columns=self.feature_names)
        else:
            X = pd.DataFrame(vector, columns=self.feature_names)

        # 3. Model Inference
        t_inf0 = time.perf_counter()
        proba = float(self.model.predict_proba(X)[0, 1])
        model_time_ms = (time.perf_counter() - t_inf0) * 1000

        # 4. Calibrated Decision & Risk Classification
        is_phishing = proba >= self.t_optimal
        prediction_label = "phishing" if is_phishing else "legitimate"

        if proba < self.t1_low:
            risk_level = "LOW"
            action = "ALLOW"
            recommendation = "Destination conforms to expected benign web patterns. Safe to browse."
        elif proba < self.t2_high:
            risk_level = "MEDIUM"
            action = "CAUTION"
            recommendation = "Anomalies detected. Inspect domain spelling and SSL certificate before submitting credentials."
        else:
            risk_level = "HIGH"
            action = "BLOCK"
            recommendation = "Critical phishing signals confirmed. High risk of credential harvesting or malware. Block access."

        # 5. Explainability (SHAP attributions)
        explanation_data: Dict[str, Any] = {}
        if include_explanation and self.enable_shap:
            shap_res = self.explainer.explain_vector(vector[0].tolist(), top_k=4)
            explanation_data = {
                "top_risk_contributors": shap_res["top_risk_contributors"],
                "top_mitigating_factors": shap_res["top_mitigating_factors"],
                "narrative_signals": shap_res["narrative_signals"],
                "narrative_mitigators": shap_res["narrative_mitigators"]
            }

        total_time_ms = (time.perf_counter() - t0) * 1000

        return {
            "url": url,
            "prediction": prediction_label,
            "probability": round(proba, 4),
            "risk_level": risk_level,
            "action": action,
            "recommendation": recommendation,
            "thresholds": {
                "t1_low": self.t1_low,
                "t2_high": self.t2_high,
                "t_optimal": self.t_optimal
            },
            "features": raw_feature_dict,
            "explanation": explanation_data,
            "metadata": {
                "model_name": self.model_name,
                "model_version": self.model_version,
                "feature_extraction_time_ms": round(feat_time_ms, 3),
                "model_inference_time_ms": round(model_time_ms, 3),
                "total_latency_ms": round(total_time_ms, 3)
            }
        }

    def predict_batch(self, urls: List[str], include_explanation: bool = False) -> List[Dict[str, Any]]:
        """High-throughput batch inference."""
        return [self.predict(u, include_explanation=include_explanation) for u in urls]


def main():
    if len(sys.argv) < 2:
        test_url = "https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284"
        print(f"No URL provided. Evaluating default test URL:\n  {test_url}\n")
    else:
        test_url = sys.argv[1]

    predictor = ProductionPredictor()
    result = predictor.predict(test_url, include_explanation=True)

    print("=" * 70)
    print("  PRODUCTION INFERENCE PIPELINE RESULT")
    print("=" * 70)
    print(f"URL            : {result['url']}")
    print(f"Prediction     : {result['prediction'].upper()}")
    print(f"Probability    : {result['probability']:.4f}")
    print(f"Risk Tier      : {result['risk_level']} (Action: {result['action']})")
    print(f"Total Latency  : {result['metadata']['total_latency_ms']:.2f} ms")
    print("-" * 70)
    print(f"Recommendation : {result['recommendation']}")

    if result.get("explanation"):
        print("\nPrimary Risk Drivers (SHAP):")
        for c in result["explanation"]["top_risk_contributors"]:
            print(f"  + {c['feature']:<25} (val={c['value']}): +{c['shap_impact']:.4f}")
        print("\nPrimary Mitigating Factors (SHAP):")
        for m in result["explanation"]["top_mitigating_factors"]:
            print(f"  - {m['feature']:<25} (val={m['value']}): {m['shap_impact']:.4f}")
    print("=" * 70)


if __name__ == "__main__":
    main()
