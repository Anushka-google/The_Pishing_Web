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
| **3** | Acquire & Engineer Dataset | ⏳ Pending | PhishTank, URLhaus, Tranco reproducible pipeline |
| **4** | Exploratory Data Analysis (EDA) | ⏳ Pending | Distributions, correlations, leakage checks |
| **5** | URL Parsing Component | ⏳ Pending | Modular RFC-compliant parser with unit tests |
| **6** | Feature Engineering | ⏳ Pending | Structural, character, lexical, entropy metrics |
| **7** | Feature Extractor Implementation | ⏳ Pending | Skew-free reusable extractor with unit tests |
| **8** | Baseline ML Model | ⏳ Pending | Logistic Regression benchmark & metrics |
| **9** | Model Experimentation | ⏳ Pending | Decision Tree, Random Forest, XGBoost comparison |
| **10** | Class Imbalance Handling | ⏳ Pending | Class weights, sampling, and cost curves |
| **11** | Leakage-Safe Evaluation | ⏳ Pending | Domain-level splitting & duplicate control |
| **12** | Threshold Optimization | ⏳ Pending | Multi-tier operating threshold calibration |
| **13** | Model Explainability (SHAP) | ⏳ Pending | Global & local feature attribution |
| **14** | Production Inference Pipeline | ⏳ Pending | Production prediction pipeline & artifact packaging |
| **15** | FastAPI Backend Service | ⏳ Pending | `/predict`, `/health`, `/history`, `/stats` |
| **16** | Input Validation & Error Handling | ⏳ Pending | Pydantic validation & resilience |
| **17** | PostgreSQL Storage | ⏳ Pending | Schema, migrations, and prediction audit log |
| **18** | React Frontend Dashboard | ⏳ Pending | Interactive URL analyzer & visualizer |
| **19** | Security-Aware UI | ⏳ Pending | Risk indicators & actionable security guidance |
| **20** | Testing Suite | ⏳ Pending | Unit, integration, and ML validation tests |
| **21** | Docker Containerization | ⏳ Pending | Multi-container docker-compose setup |
| **22** | MLflow Experiment Tracking | ⏳ Pending | Metric logging & artifact registry |
| **23** | Model Versioning & Rollback | ⏳ Pending | Version management & deployment safety |
| **24** | Structured Logging | ⏳ Pending | JSON audit logging & tracing |
| **25** | Latency & Performance Measurement| ⏳ Pending | Benchmarks across extraction, inference, DB |
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
