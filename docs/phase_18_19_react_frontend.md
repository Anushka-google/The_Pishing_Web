# Phase 18 & 19: React Frontend & Security-Aware UI Dashboard

## Overview
Phase 18 and 19 deliver a clean, responsive, and professional cybersecurity intelligence web dashboard built with **React (Vite)** and modern glassmorphism UI principles.

---

## Complete End-to-End User Flow

```
[User enters URL in React]
            │
            ▼ (HTTP POST /predict)
[FastAPI REST API]
            │
            ▼ (RFC 3986 & Whitelist Validation)
[22-Feature Extractor]
            │
            ▼ (Vector: [length, dots, entropy, ...])
[Random Forest Champion Model]
            │
            ├──▶ [Posterior Probability f(X) -> 0.00 to 1.00]
            │
            ├──▶ [Calibrated Risk Engine: LOW / MEDIUM / HIGH]
            │
            ├──▶ [SHAP TreeExplainer Attributions]
            │
            ▼
[PostgreSQL / SQLite Database Persistence]
            │
            ▼ (JSON Intelligence Response)
[React Dashboard Renders Real-Time Risk Gauge, Attributions & Scan History]
```

---

## Dashboard Components

1. **Top Analytics Banner (`StatsOverview.jsx`):**
   - Live telemetry: Total Scans, Phishing Threats Detected, Legitimate Domains Verified, Mean Pipeline Latency.
2. **URL Threat Analyzer (`UrlAnalyzer.jsx`):**
   - High-throughput input bar with Clear button.
   - 4 Instant Benchmark Presets:
     - 🟢 Google Auth (Hard Negative authentication portal)
     - 🔵 Oracle Tech Docs (Standard legitimate domain)
     - 🔴 PayPal Deceptive Subdomain (`login.paypal.com.cloud-node-402.cc`)
     - 🟠 IP Host Harvesting Attack (`http://176.77.46.141:...`)
3. **Calibrated Result Card (`ResultCard.jsx`):**
   - Calibrated Risk Level Badge (`LOW` [Green], `MEDIUM` [Amber], `HIGH` [Red]).
   - Security Enforcement Action (`ALLOW`, `CAUTION`, `BLOCK`).
   - Phishing Probability Meter with threshold markers ($T_1=0.40$, $T_2=0.65$).
   - SOC Security Directive recommendation box.
   - Precise millisecond latency breakdown.
4. **SHAP Explainability Engine (`RiskExplanation.jsx`):**
   - Top Risk Drivers (positive $\phi$ impact bars pushing toward phishing).
   - Top Mitigating Factors (negative $\phi$ impact bars pulling toward legitimate).
   - Collapsible 22-dimensional numerical feature inspector.
5. **Historical Scan Log (`HistoryTable.jsx`):**
   - Real-time audit table of recent scans stored in the database.
   - Timestamps, URL, Risk Level Badge, Probability, and "Re-Inspect" action button.

---

## Local Development Execution
- **Run Backend:**
  ```bash
  uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
  ```
- **Run Frontend:**
  ```bash
  cd frontend
  npm run dev
  ```
- Frontend available at `http://localhost:3000`.
- Backend documentation available at `http://localhost:8000/docs`.
