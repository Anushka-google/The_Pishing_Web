# Phase 22: MLflow Experiment Tracking & Model Registry

## 🎯 Objective
Establish rigorous MLOps experiment tracking and model governance using **MLflow 3.x**. Every candidate model is systematically trained, evaluated, and tracked with its complete lineage:
- **Architecture & Frameworks**: Scikit-Learn and XGBoost
- **Hyperparameter Configurations**: Depth, estimators, learning rate, subsampling, regularization
- **Dataset Provenance**: Version `v1.2.0-curated`, SHA-256 fingerprint, feature schema
- **Standardized Metrics**: Precision, Recall, F1, ROC-AUC, PR-AUC, Accuracy, Latency, Confusion Matrix
- **Model Artifacts & Signatures**: Input examples, model artifacts, feature importances, and Model Registry registration

---

## 📊 Experiment Results Summary

- **Experiment Name**: `Phishing_Detection_Intelligence`
- **Tracking Database**: `sqlite:///data/mlflow.db`
- **Dataset Fingerprint**: `ba80ea8f91953c6e...` (9206 samples, 22 signals)

| Run Name | Model | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | Accuracy | Train Time | Latency / URL |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| XGBoost_Tuned | XGBoost | 99.70% | 99.90% | 99.80% | 1.0000 | 1.0000 | 99.78% | 0.475s | 0.0114 ms |
| XGBoost_Baseline | XGBoost | 99.90% | 99.80% | 99.85% | 1.0000 | 1.0000 | 99.84% | 0.232s | 0.0075 ms |
| **Random_Forest** | Random Forest | 100.00% | 99.80% | **99.90%** | 1.0000 | 1.0000 | 99.89% | 0.298s | 0.0455 ms |
| Decision_Tree | Decision Tree | 99.70% | 99.70% | 99.70% | 0.9977 | 0.9965 | 99.67% | 0.013s | 0.0015 ms |
| Logistic_Regression | Logistic Regression | 92.19% | 93.86% | 93.02% | 0.9780 | 0.9809 | 92.40% | 0.039s | 0.0010 ms |

---

## 🏆 Champion Model Selection

- **Champion Run**: `Random_Forest`
- **Model Architecture**: `Random Forest`
- **MLflow Run ID**: `43b699950e05474eac088278c29c10a6`
- **Registered Model Name**: `Phishing_Detection_Intelligence`

### Hyperparameter Metadata:
```json
{
  "model_type": "Random Forest",
  "n_estimators": 100,
  "max_depth": 12,
  "criterion": "gini",
  "random_state": 42
}
```

### Measured Performance:
- **Precision**: `100.00%`
- **Recall**: `99.80%`
- **F1-Score**: `99.90%`
- **ROC-AUC**: `1.0000`
- **PR-AUC**: `1.0000`
- **Inference Latency**: `0.0455 ms / URL`

---

## 🔍 Model Artifacts & Governance

Each tracked run in MLflow includes:
1. **Model Signature**: Strictly typed input schema (22 URL feature signals) and binary output tensor.
2. **Input Example**: 5 sample URL feature rows demonstrating expected production payload.
3. **Artifacts**:
   - `metrics.json`: Full metric breakdown including False Positive Rate and False Negative Rate.
   - `confusion_matrix.json`: Raw confusion counts (`tp`, `fp`, `tn`, `fn`).
   - `feature_importance.json`: Ranked feature weight attributions.
4. **Model Registry**: Automated promotion of champion model with tags `is_champion=true` and `dataset_version=v1.2.0-curated`.

---

## 💻 How to View Experiments in MLflow UI

To launch the local MLflow dashboard:
```bash
mlflow ui --backend-store-uri sqlite:///data/mlflow.db --port 5000
```
Then navigate to `http://localhost:5000` to inspect runs, compare parameters, plot metric curves, and audit registered models.
