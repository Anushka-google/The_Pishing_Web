# Phase 17: Relational Database Storage (PostgreSQL & SQLite)

## Overview
A production-grade cybersecurity platform must persist real-time URL risk analyses for threat intelligence auditing, SOC historical review, and longitudinal analytics.

Phase 17 implements a clean, un-overengineered relational persistence layer using **SQLAlchemy 2.0 ORM** that seamlessly supports:
1. **Production Deployment:** PostgreSQL via connection pooling.
2. **Local Development:** Zero-setup fallback to SQLite (`data/phishing_intelligence.db`).

---

## Database Schema: `prediction` Table

```
prediction
-----------------------------------------------------------
id            : Integer (Primary Key, Autoincrement)
url           : String(2048, Indexed, Not Null)
prediction    : String(32, 'phishing' | 'legitimate')
probability   : Float (Calibrated posterior risk score)
risk_level    : String(16, 'LOW' | 'MEDIUM' | 'HIGH')
created_at    : DateTime (UTC timestamp, Indexed)
model_version : String(32, default 'v1.0.0')
-----------------------------------------------------------
```

---

## Architectural Integration Flow

```
[User / React Frontend]
        │
        ▼ (POST /predict)
[FastAPI REST Router]
        │
        ├──▶ Feature Extraction & Model Inference (~0.5 ms)
        │
        ▼
[PredictionRepository]
        │
        ├──▶ Saves record to PostgreSQL / SQLite
        │
        ▼ (Response)
[Return Prediction + SHAP Attribution to User]
```

---

## Query Capabilities
- **`get_history(limit=50)`**: Retrieves the latest scans sorted in descending chronological order.
- **`get_stats()`**: Aggregates total scans, phishing detection counts, legitimate classification counts, phishing percentage, and risk tier distribution directly via SQL aggregation functions (`func.count`).

---

## Code References
- Models: [`database/models.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/database/models.py)
- Engine & Session: [`database/connection.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/database/connection.py)
- Repository: [`database/repository.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/database/repository.py)
- Unit Tests: [`tests/test_database.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/tests/test_database.py)
