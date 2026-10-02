# Phase 14: Production Inference Pipeline

## Overview
A common pitfall in production machine learning systems is **training/serving skew**—where data preprocessing, feature calculations, or normalization transformations differ between the offline training environment and the real-time inference service.

Phase 14 delivers an isolated, lightweight, and deterministic inference pipeline encapsulated in [`src/prediction/predict.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/src/prediction/predict.py) that strictly reuses the exact feature definitions and calibrated decision boundaries.

---

## Architecture Flow

```
Raw Incoming URL
       │
       ▼
1. Feature Extraction (src/features/extractor.py: FeatureExtractor)
       │  - Deterministic 22-dimensional feature vector extraction
       │  - Latency: ~0.05 ms
       ▼
2. Transformation (StandardScaler if flagged in model artifact)
       │  - Strictly transforms using saved training statistics (never fits)
       ▼
3. Champion Ensemble Inference (models/champion_phishing_model.joblib)
       │  - Predicts posterior probability p(phishing | x)
       │  - Latency: ~0.5 ms
       ▼
4. Calibrated Multi-Tier Risk Mapping
       │  - Low Risk (< 0.40): Action ALLOW
       │  - Medium Risk (0.40 - 0.65): Action CAUTION
       │  - High Risk (>= 0.65): Action BLOCK
       ▼
5. Local Explainability (SHAP TreeExplainer)
       │  - Mathematical Shapley attributions
       │  - Top risk drivers & mitigating factors
       ▼
Structured Security Intelligence Response
```

---

## Output Schema Example
```json
{
  "url": "https://accounts.google.com/signin/v2/identifier",
  "prediction": "legitimate",
  "probability": 0.0300,
  "risk_level": "LOW",
  "action": "ALLOW",
  "recommendation": "Destination conforms to expected benign web patterns. Safe to browse.",
  "thresholds": {
    "t1_low": 0.40,
    "t2_high": 0.65,
    "t_optimal": 0.50
  },
  "explanation": {
    "top_risk_contributors": [
      {"feature": "suspicious_keyword_count", "value": 2.0, "shap_impact": 0.0576}
    ],
    "top_mitigating_factors": [
      {"feature": "number_of_digits", "value": 1.0, "shap_impact": -0.1431},
      {"feature": "domain_length", "value": 19.0, "shap_impact": -0.0963}
    ]
  },
  "metadata": {
    "model_name": "RandomForestClassifier",
    "model_version": "v1.0.0",
    "feature_extraction_time_ms": 0.058,
    "model_inference_time_ms": 0.450,
    "total_latency_ms": 118.37
  }
}
```

---

## CLI & Programmatic Usage
```bash
python -m src.prediction.predict "https://example.com"
```
Or programmatically in Python:
```python
from src.prediction.predict import ProductionPredictor

predictor = ProductionPredictor()
result = predictor.predict("https://paypal-update.online/auth")
```
