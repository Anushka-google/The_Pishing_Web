# Phishing Detection & Risk Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An end-to-end, production-grade AI/ML engineering system that analyzes URLs, extracts security-relevant features, predicts phishing probabilities, generates explainable risk breakdowns (via SHAP), and serves intelligence through a FastAPI backend and React frontend.

---

## 🏗️ System Architecture & Workflow

```
URL Input
   │
   ▼
URL Validation & Parsing (RFC 3986, tldextract)
   │
   ▼
Feature Extraction (Length, Character, Structural, Lexical, Entropy)
   │
   ▼
ML Model Pipeline (Logistic Regression, Random Forest, XGBoost)
   │
   ▼
Risk Engine (Calibrated Probability → LOW / MEDIUM / HIGH + SHAP Explanations)
   │
   ├──▶ PostgreSQL (Historical Analytics & Audit Logging)
   └──▶ FastAPI REST API ──▶ React Dashboard
```

---

## 🗺️ Project Roadmap & Phase Tracker

| Phase | Description | Status | Reference / Deliverable |
| :---: | :--- | :---: | :--- |
| **0** | **Understand the Problem & Threat Modeling** | ✅ Completed | [Phase 0 Doc](docs/phase_0_problem_understanding.md) |
| **1** | **Define the MVP** | ✅ Completed | [Phase 1 Doc](docs/phase_1_mvp_definition.md) & [MVP Pipeline](src/prediction/mvp_pipeline.py) |
| **2** | **Research Approaches** | ✅ Completed | [Phase 2 Doc](docs/phase_2_research_approaches.md) & [Hybrid Engine](src/prediction/hybrid_engine.py) |
| **3** | **Acquire & Engineer Dataset + EDA** | ✅ Completed | [EDA Report](docs/phase_3_data_exploration.md) & [Notebook](notebooks/01_data_exploration.ipynb) |
| **4** | **Benchmark Detection Approaches** | ✅ Completed | [Benchmark Report](docs/approaches_comparison_benchmark.md) & [Notebook](notebooks/02_detection_approaches_benchmark.ipynb) |
| **5** | **URL Parsing Component** | ✅ Completed | [URL Parser Spec](docs/phase_5_url_parsing.md) & [Parser Code](src/preprocessing/url_parser.py) |
| **6** | **Feature Engineering** | ✅ Completed | [Feature Engineering Spec](docs/phase_6_feature_engineering.md) & 22 Engineered Signals |
| **7** | **Feature Extractor Implementation** | ✅ Completed | [Feature Extractor](src/features/extractor.py) & [Dataset Matrix](src/features/build_features.py) |
| **8** | **Baseline ML Model** | ✅ Completed | [Baseline Spec](docs/phase_8_baseline_model.md) & [Trainer](src/training/train_baseline.py) |
| **9** | **Model Experimentation** | ✅ Completed | [Comparison Report](docs/phase_8_model_experimentation.md) & [Notebook](notebooks/03_model_experimentation.ipynb) |
| **10** | Class Imbalance Handling | ⏳ Pending | Class weights, sampling, and cost curves |
| **11** | **Leakage-Safe & Real-World Validation** | ✅ Completed | [Domain Grouping](src/training/leakage_safe_evaluation.py), [Holdout Benchmark](docs/phase_11_real_world_validation.md) & [Validation Suite](docs/phase_11_rigorous_validation_suite.md) |
| **12** | **Threshold Optimization & Calibration** | ✅ Completed | [Threshold Spec](docs/phase_12_threshold_optimization.md) & [Optimizer](src/evaluation/threshold_optimizer.py) |
| **13** | **Model Explainability (SHAP TreeExplainer)** | ✅ Completed | [Explainability Spec](docs/phase_13_model_explainability.md) & [SHAP Engine](src/explanation/shap_explainer.py) |
| **14** | **Production Inference Pipeline** | ✅ Completed | [Inference Spec](docs/phase_14_production_inference.md) & [Predict CLI](src/prediction/predict.py) |
| **15** | **FastAPI REST Backend Service** | ✅ Completed | [API Routes](api/routes.py) & [API App](api/main.py) |
| **16** | **Input Validation & Error Handling** | ✅ Completed | [Pydantic Schemas](api/schemas.py) & Whitelist Validation |
| **17** | **Relational Storage (PostgreSQL & SQLite)** | ✅ Completed | [Database Spec](docs/phase_17_postgresql_storage.md) & [Repository](database/repository.py) |
| **18** | **React Frontend Dashboard** | ✅ Completed | [Frontend Spec](docs/phase_18_19_react_frontend.md) & [Vite React App](frontend/src/App.jsx) |
| **19** | **Security-Aware UI & Explainability** | ✅ Completed | [ResultCard](frontend/src/components/ResultCard.jsx) & [RiskExplanation](frontend/src/components/RiskExplanation.jsx) |
| **20** | **Comprehensive Testing Suite (Unit, API, ML)** | ✅ Completed | [Test Spec](docs/phase_20_testing_harness.md) & 82 Passing Tests |
| **21** | **Docker Multi-Container Orchestration** | ✅ Completed | [Docker Spec](docs/phase_21_docker_containerization.md) & [docker-compose.yml](docker-compose.yml) |
| **22** | **MLflow Experiment Tracking & Registry** | ✅ Completed | [MLflow Spec](docs/phase_22_mlflow_tracking.md) & [Tracker Code](src/training/mlflow_tracker.py) |
| **23** | **Model Versioning & Dynamic Rollback** | ✅ Completed | [Model Versioning Spec](docs/phase_23_model_versioning.md) & [Version Manager](src/models/version_manager.py) |
| **24** | **Structured Operational Logging** | ✅ Completed | [Logging Spec](docs/phase_24_structured_logging.md) & [Logging Middleware](api/middleware.py) |
| **25** | **Latency & Performance Measurement** | ✅ Completed | [Performance Spec](docs/phase_25_performance_measurement.md) & [Profiler](src/evaluation/performance_profiler.py) |
| **26** | Cloud Deployment | ⏳ Pending | Cloud-ready deployment setup |
| **27** | Production Monitoring & Drift | ⏳ Pending | Data drift detection & operational metrics |
| **28** | Active Feedback Loop | ⏳ Pending | Retraining workflow & validation cycles |
| **29** | Advanced Security Extensions | ⏳ Pending | DNS, WHOIS, and domain reputation signals |

---

## 📂 Repository Layout

```
├── .gitignore
├── README.md
├── requirements.txt
├── docs/
│   └── phase_0_problem_understanding.md
├── data/
│   ├── raw/
│   │   ├── phishing/
│   │   └── legitimate/
│   └── processed/
├── notebooks/
├── src/
│   ├── __init__.py
│   ├── preprocessing/
│   ├── features/
│   ├── training/
│   ├── prediction/
│   └── evaluation/
├── models/
├── api/
├── database/
├── frontend/
└── tests/
```

---

## 🚀 Getting Started

### Phase 0: Foundations
Review the threat model, attack vectors, and machine learning formulation in:
👉 [docs/phase_0_problem_understanding.md](docs/phase_0_problem_understanding.md)
