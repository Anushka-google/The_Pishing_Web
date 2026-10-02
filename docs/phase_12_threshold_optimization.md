# Phase 12: Decision Threshold Optimization & Risk Tier Calibration

## Overview
Default binary classifiers hardcode an arbitrary decision threshold of $\tau = 0.50$. In cybersecurity applications, treating False Positives (FPs: legitimate enterprise login pages flagged as malicious) and False Negatives (FNs: stealthy phishing attacks slipping past defenses) equally creates operational friction and alert fatigue.

Phase 12 replaces static thresholding with **empirical validation-driven calibration**:
1. Sweeps $\tau \in [0.01, 0.99]$ across domain-grouped holdout folds.
2. Evaluates the Precision-Recall and ROC-AUC tradeoff curves.
3. Partitions probabilities into 3 calibrated risk operating tiers:
   - **LOW RISK**: $\hat{p} < T_1$
   - **MEDIUM RISK**: $T_1 \le \hat{p} < T_2$
   - **HIGH RISK**: $\hat{p} \ge T_2$

---

## Operating Thresholds

| Metric / Parameter | Value | Rationale |
|-------------------|-------|-----------|
| **Optimal $F_1$ Threshold ($\tau^*$)** | **0.29** | Maximizes the harmonic balance of precision and recall. |
| **$T_1$ (Low Risk Cutoff)** | **0.40** | High-Recall operating boundary ensuring near-zero false negatives. |
| **$T_2$ (High Risk Cutoff)** | **0.65** | High-Precision operating boundary ensuring false-positive rate is negligible. |

### Visual Risk Tier Scheme
```
0.00 -------------- [T1 = 0.40] -------------- [T2 = 0.65] -------------- 1.00
       LOW RISK                   MEDIUM RISK                  HIGH RISK
    (Allow Access)           (Secondary Caution)            (Block URL)
```

---

## Calibrated Decision Policy
- **LOW ($p < 0.40$):**
  - **Action:** ALLOW.
  - **Verdict:** URL shows normal domain patterns, standard structure, and absence of deceptive keywords.
- **MEDIUM ($0.40 \le p < 0.65$):**
  - **Action:** CAUTION / INSPECT.
  - **Verdict:** URL contains ambiguous signals (e.g., suspicious lexical tokens on non-reputable TLDs, or mild structural anomalies). User is advised to verify domain spelling before submitting credentials.
- **HIGH ($p \ge 0.65$):**
  - **Action:** BLOCK / WARN.
  - **Verdict:** High-confidence malicious signals (IP address in URL, severe entropy spikes, brand typosquatting, deceptive login paths).

---

## Artifacts & Reproducibility
- Optimizer script: [`src/evaluation/threshold_optimizer.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/src/evaluation/threshold_optimizer.py)
- Calibration report: `data/processed/threshold_calibration.json`
- Model package enriched: `models/champion_phishing_model.joblib`
- Unit tests: [`tests/test_threshold_optimizer.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/tests/test_threshold_optimizer.py)
