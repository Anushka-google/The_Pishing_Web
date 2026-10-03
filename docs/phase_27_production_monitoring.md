# Phase 27: Production Monitoring & Data Drift Detection

## 1. Executive Summary & Objective

> **Guiding Principle**: *"Data drift means that the statistical properties of incoming production data change relative to the data used during model development."*

In machine learning security systems, static model evaluation is insufficient. Adversaries continuously mutate evasion tactics—such as switching from long tokenized URLs to link shorteners, deploying Domain Generation Algorithms (DGA), or registering novel top-level domains (TLDs). Simultaneously, user traffic patterns and platform infrastructure undergo organic shifts.

**Phase 27** implements an automated, mathematically rigorous **Production Monitoring & Data Drift Detection Framework** following the complete 5-step operational lifecycle:

```
Production Data ──► Monitoring ──► Detect Changes ──► Investigate ──► Retrain when justified
```

---

## 2. The 5-Step Operational Lifecycle Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       1. Production Data Telemetry                          │
│  Live /predict payloads, database records, latency timers, error logs       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          2. Monitoring Engine                               │
│  Compares live production window against baseline empirical profile         │
│  Models: URL length, domain entropy, subdomains, TLDs, probabilities, ratio │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         3. Detect Changes (Math)                            │
│  • PSI < 0.10  : STABLE (No drift)                                          │
│  • 0.10 <= PSI < 0.25 : MODERATE_DRIFT (Investigate)                        │
│  • PSI >= 0.25 : CRITICAL_DRIFT (Trigger retraining)                        │
│  • Two-sample KS test (p < 0.05), Total Variation Distance (TVD > 0.35)     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    4. Investigate (Automated RCA)                           │
│  Formulates root-cause hypotheses:                                          │
│  - URL compression -> Adversarial link shortening (bit.ly, t.co)           │
│  - Entropy surge   -> DGA (Domain Generation Algorithm) attack              │
│  - Emergent TLDs   -> Threat actor infrastructure migration                 │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   5. Retrain When Justified Engine                          │
│  Multi-condition trigger logic prevents unnecessary retraining churn:       │
│  Triggers only if PSI >= 0.25 OR class shift > 25% with adequate sample size │
│  Generates actionable Retraining Plan (P1/P2 priority, steps, safety checks)│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. The 6 Monitored Production Dimensions

The monitoring engine evaluates production traffic across six isolated dimensions:

| # | Dimension | Metric / Statistical Test | Alert Threshold | Operational Meaning |
| :- | :--- | :--- | :--- | :--- |
| **1** | **URL-Length Distribution** | Population Stability Index (PSI) & Kolmogorov-Smirnov (KS) | $PSI \ge 0.10$ (Warn)<br>$PSI \ge 0.25$ (Crit) | Detects link shortener evasion ($< 25$ chars) or query padding ($> 150$ chars). |
| **2** | **Domain Characteristics** | • Shannon Entropy ($H$)<br>• Subdomain Count<br>• IP-Host Ratio<br>• TLD Total Variation Distance (TVD) | $PSI \ge 0.25$<br>$\Delta \text{IP} > 0.05$<br>$\text{TVD} > 0.35$ | Identifies DGA domains, bulletproof hosting, direct-to-IP credential harvesting, and novel TLD campaigns. |
| **3** | **Prediction Distribution** | Probability PSI, Two-Sample KS Test, and Risk Tier Distribution | $PSI \ge 0.25$<br>$p < 0.05$ | Detects model score degradation, overconfidence shifts, and boundary uncertainty. |
| **4** | **Phishing / Legitimate Ratio** | Class Ratio Shift ($\Delta P_{\text{phish}}$) | $|\Delta| > 12\%$ (Warn)<br>$|\Delta| > 25\%$ (Crit) | Captures concept drift, targeted phishing campaigns, or shifts in client base. |
| **5** | **API Latency & SLA** | Mean, Median, P95, P99, and SLA violation rate ($> 100\text{ ms}$) | $\text{P95} > 50\text{ ms}$ (Warn)<br>$\text{P95} > 100\text{ ms}$ (Crit) | Protects inline gateway latency budget and upstream client SLAs. |
| **6** | **System Error Rate** | Error percentage ($\% = \frac{\text{errors}}{\text{requests}} \times 100$) | $> 0.5\%$ (Warn)<br>$> 2.0\%$ (Crit) | Uncovers runtime crashes, network timeouts, or malformed input payloads. |

---

## 4. Mathematical Formulations

### A. Population Stability Index (PSI)

Given baseline reference distribution $B$ with expected proportions $E_i$ and live production window $A$ with actual proportions $A_i$ across $K$ quantile bins:

$$\text{PSI} = \sum_{i=1}^{K} (A_i - E_i) \times \ln\left(\frac{A_i}{E_i}\right)$$

An adaptive binning strategy is employed:
- $N < 250$: $K = 5$ bins (avoids small-sample count variance).
- $N \ge 250$: $K = 10$ bins.
- Smoothing: Laplace epsilon ($\epsilon = 10^{-4}$) prevents undefined log-odds on zero-count bins.

**Interpretation:**
- $\text{PSI} < 0.10$: **STABLE** (No meaningful distribution shift).
- $0.10 \le \text{PSI} < 0.25$: **MODERATE_DRIFT** (Distribution shift detected; investigate).
- $\text{PSI} \ge 0.25$: **CRITICAL_DRIFT** (Significant distribution shift; retraining candidate).

### B. Two-Sample Kolmogorov-Smirnov (KS) Test

For continuous variables (URL length, Shannon entropy, prediction probability), the two-sample KS test compares empirical cumulative distribution functions $F_{\text{base}}(x)$ and $F_{\text{prod}}(x)$:

$$D = \sup_{x} |F_{\text{base}}(x) - F_{\text{prod}}(x)|$$

A $p$-value $< 0.05$ indicates rejection of the null hypothesis that production and baseline share the identical underlying continuous distribution.

### C. Total Variation Distance (TVD) for Categorical TLDs

For categorical top-level domain distributions $P$ and $Q$:

$$\text{TVD}(P, Q) = \frac{1}{2} \sum_{x \in \mathcal{X}} |P(x) - Q(x)| \in [0, 1]$$

---

## 5. Automated Root Cause Analysis (RCA) Hypotheses

When drift is detected, `DataDriftDetector` synthesizes automated diagnostic findings and actionable threat intelligence hypotheses:

| Observed Drift Signal | Automated Root Cause Hypothesis |
| :--- | :--- |
| **URL Length Compression** ($\Delta \mu < -15$ chars, $PSI \ge 0.25$) | Adversaries aggressively leveraging URL shortening platforms (`bit.ly`, `t.co`, `tinyurl`) to evade lexical length filters. |
| **URL Length Inflation** ($\Delta \mu > +25$ chars, $PSI \ge 0.25$) | Phishing campaigns appending deep tokenized path padding or nested query parameter tracking strings. |
| **Shannon Entropy Surge** ($PSI \ge 0.25$) | Emergence of automated Domain Generation Algorithms (DGA) generating randomized hostnames. |
| **Emergent Unseen TLDs** ($\ge 3$ new extensions) | Campaign operators shifting infrastructure to newly active, low-cost, or bulletproof registrar extensions. |
| **Direct IP Host Surge** ($\Delta \text{IP} > 5\%$) | Direct-to-IP credential harvesting surge bypassing public DNS resolution. |
| **Latency SLA Breach** (P95 $> 100$ ms) | Model inference saturation or external threat intelligence lookup timeouts. |

---

## 6. Retraining Justification Engine ("Retrain when justified")

Retraining machine learning models incurs computational expense, deployment risk, and validation overhead. The platform enforces strict multi-condition triggers before recommending retraining:

```python
# Retraining is justified ONLY when:
# 1. Structural feature drift (URL length or entropy PSI >= 0.25), OR
# 2. Prediction score drift (PSI >= 0.25) AND class ratio shift > 25%, OR
# 3. Severe score distribution divergence (PSI >= 0.35)
# WITH minimum statistically significant sample size (N >= 25)
is_justified = (len(triggers_fired) >= 2 or psi_prob >= 0.35) and sample_size >= 25
```

When justified, the engine outputs an executable **Retraining Plan**:
```json
{
  "action": "Execute Phase 23 Retraining Pipeline",
  "target_model_version": "v4",
  "retraining_priority": "P1 - HIGH",
  "recommended_steps": [
    "1. Sample recent 1,000 production URLs showing distribution drift.",
    "2. Augment training dataset with confirmed zero-day labels from Threat Intelligence feeds.",
    "3. Retrain XGBoost Champion with updated feature distributions.",
    "4. Validate zero-leakage holdout metrics before registering new model version.",
    "5. Promote v4 to production with automated rollback safety to v3/v2."
  ]
}
```

---

## 7. REST API Endpoints & Usage

### A. GET `/monitoring/drift`
Audits production database inference records or evaluates synthetic simulation scenarios (`healthy`, `short_urls`, `phishing_surge`, `critical_drift`).

```bash
# Evaluate live database records
curl -X GET "http://localhost:8000/monitoring/drift?sample_limit=250"

# Simulate critical drift scenario
curl -X GET "http://localhost:8000/monitoring/drift?scenario=critical_drift"
```

**Example Response**:
```json
{
  "timestamp": "2026-10-03T17:48:44.925938+00:00",
  "window_size": 100,
  "overall_status": "HEALTHY",
  "metrics": {
    "url_length": {
      "psi": 0.0121,
      "status": "STABLE",
      "baseline": { "mean": 56.19, "p50": 56.0, "p95": 80.0 },
      "current": { "mean": 56.42, "p50": 56.0, "p95": 79.0 }
    },
    "prediction_distribution": {
      "probability_psi": 0.0068,
      "status": "STABLE",
      "current_risk_tiers": { "LOW": 0.42, "MEDIUM": 0.12, "HIGH": 0.46 }
    },
    "phishing_legitimate_ratio": {
      "baseline_phishing_pct": 53.99,
      "current_phishing_pct": 54.0,
      "shift_percentage_points": 0.01,
      "status": "STABLE"
    },
    "api_latency": {
      "mean_latency_ms": 0.41,
      "p95_latency_ms": 0.54,
      "sla_target_ms": 100.0,
      "status": "HEALTHY"
    },
    "error_rate": {
      "error_rate_pct": 0.0,
      "status": "HEALTHY"
    }
  },
  "investigation": {
    "findings": [],
    "root_cause_hypotheses": []
  },
  "retraining_evaluation": {
    "retrain_justified": false,
    "severity": "LOW",
    "recommended_action": "MAINTAIN_CURRENT_MODEL",
    "triggers_fired_count": 0,
    "triggers_fired": [],
    "retraining_plan": {
      "action": "No Retraining Required",
      "target_model_version": "v1 (Active)",
      "retraining_priority": "NONE"
    }
  }
}
```

### B. POST `/monitoring/evaluate-retrain`
Evaluates whether model retraining is justified based on observed drift signals.

```bash
curl -X POST "http://localhost:8000/monitoring/evaluate-retrain" \
     -H "Content-Type: application/json" \
     -d '{"sample_window_size": 100, "scenario": "critical_drift"}'
```

**Example Response**:
```json
{
  "timestamp": "2026-10-03T17:48:45.063250+00:00",
  "retrain_justified": true,
  "severity": "CRITICAL",
  "recommended_action": "TRIGGER_RETRAINING",
  "triggers_fired": [
    "URL-length distribution drift (PSI=11.7257 >= 0.25)",
    "Shannon entropy distribution drift (PSI=3.106 >= 0.25)",
    "Prediction probability score drift (PSI=11.6069 >= 0.25)",
    "Phishing/Legitimate class ratio deviation (46.0% > 25.0%)"
  ],
  "retraining_plan": {
    "action": "Execute Phase 23 Retraining Pipeline",
    "target_model_version": "v4",
    "retraining_priority": "P1 - HIGH",
    "recommended_steps": [
      "1. Sample recent 1,000 production URLs showing distribution drift.",
      "2. Augment training dataset with confirmed zero-day labels from Threat Intelligence feeds.",
      "3. Retrain XGBoost Champion with updated feature distributions.",
      "4. Validate zero-leakage holdout metrics before registering new model version.",
      "5. Promote v4 to production with automated rollback safety to v3/v2."
    ]
  },
  "metrics_summary": {
    "url_length_psi": 11.7257,
    "probability_psi": 11.6069,
    "entropy_psi": 3.106,
    "phishing_shift_pct": 46.0,
    "p95_latency_ms": 115.0,
    "error_rate_pct": 0.0,
    "overall_status": "CRITICAL_DRIFT"
  }
}
```

---

## 8. Verification & Test Suite Coverage

The implementation includes a dedicated test suite (`tests/test_production_monitoring.py`) containing 12 unit and integration tests:

1. `test_psi_identical_distributions`: Confirms $PSI < 0.10$ for identical distributions.
2. `test_psi_drastic_shift`: Confirms $PSI \ge 0.25$ for shifted distributions.
3. `test_ks_test_divergence`: Validates $p < 0.01$ and statistic divergence.
4. `test_tvd_categorical_distance`: Validates categorical distance bounds $[0, 1]$.
5. `test_baseline_profile_structure`: Verifies presence of all 6 monitoring dimensions in baseline profile.
6. `test_healthy_production_traffic_scenario`: Confirms `HEALTHY` tier and no retraining recommendation.
7. `test_short_url_evasion_drift_scenario`: Verifies URL length compression detection and link shortener RCA hypothesis.
8. `test_phishing_surge_ratio_drift_scenario`: Verifies class ratio shift detection.
9. `test_critical_multi_dimensional_drift_retraining_trigger`: Confirms retraining justification, triggers fired $\ge 2$, and P1 action plan.
10. `test_api_latency_and_error_drift_detection`: Validates detection of SLA violations ($> 100\text{ ms}$) and error rates.
11. `test_api_get_monitoring_drift_endpoint`: Verifies `GET /monitoring/drift` schema and response.
12. `test_api_post_evaluate_retrain_endpoint`: Verifies `POST /monitoring/evaluate-retrain` schema and response.
