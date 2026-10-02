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
import joblib

from src.features.extractor import FeatureExtractor
from src.explanation.shap_explainer import PhishingExplainer


class ProductionPredictor:
    def __init__(
        self,
        model_path: str = "models/champion_phishing_model.joblib",
        enable_shap: bool = True
    ):
        self.model_path = model_path
        self.enable_shap = enable_shap
        self.feature_names = FeatureExtractor.FEATURE_NAMES
        self.extractor = FeatureExtractor()

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Trained model artifact not found at: {model_path}")

        self.pkg = joblib.load(model_path)
        self.model = self.pkg["model"]
        self.scaler = self.pkg.get("scaler")
        self.model_name = self.pkg.get("model_name", "RandomForestClassifier")
        self.model_version = self.pkg.get("model_version", "v1.0.0")

        # Load calibrated thresholds
        thresholds = self.pkg.get("thresholds", {})
        self.t1_low = float(thresholds.get("t1_low", 0.40))
        self.t2_high = float(thresholds.get("t2_high", 0.65))
        self.t_optimal = float(thresholds.get("t_optimal", 0.50))

        # Lazy load SHAP explainer for inference speed if needed
        self._explainer: Optional[PhishingExplainer] = None

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

        # 2. Scaling (if applicable)
        X = vector
        if self.scaler is not None:
            X = self.scaler.transform(X)

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
