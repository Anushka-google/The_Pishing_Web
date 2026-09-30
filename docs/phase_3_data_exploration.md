# Phase 3: Exploratory Data Analysis (EDA) Report

## 1. Dataset Dimensions & Class Distribution
- **Total Records:** 9450
- **Phishing Samples:** 4990 (52.8%)
- **Legitimate Samples:** 4460 (47.2%)
- **Class Balance Ratio:** 1.119 (Balanced)
- **Missing Values:** Zero null entries across all fields.

---

## 2. URL & Domain Length Distributions

| Feature | Class | Min | Mean | Median | Std | Max | 95th % |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **URL Length** | Phishing | 48.0 | 87.13 | 86.0 | 15.57 | 133.0 | 113.0 |
| | Legitimate | 15.0 | 49.27 | 49.0 | 13.69 | 86.0 | 72.0 |
| **Domain Length** | Phishing | 9.0 | 28.7 | 30.5 | 12.61 | 61.0 | 51.0 |
| | Legitimate | 7.0 | 14.77 | 15.0 | 3.98 | 27.0 | 21.0 |

> **Key Observation:** Phishing URLs exhibit significantly higher mean and 95th-percentile length due to token stuffing, deceptive subdomains, and authentication redirection parameters.

---

## 3. Structural & Character Anomaly Signals

| Structural Metric | Phishing | Legitimate | Statistical Differential |
| :--- | :---: | :---: | :--- |
| **Mean Dots (`.`)** | 3.13 | 1.82 | Phishing exhibits ~1.7x more dots |
| **Mean Hyphens (`-`)** | 1.64 | 0.5 | High combosquatting concentration |
| **Mean Digits (`0-9`)** | 9.28 | 1.36 | Heavy session IDs & IP addresses |
| **Mean Subdomains** | 1.96 | 0.76 | Deceptive subdomains common in attacks |
| **IP Host Prevalence** | 19.56% | 0.0% | Benign URLs rarely use naked IP hosts |
| **HTTPS Prevalence** | 50.32% | 94.3% | Confirms HTTPS does not imply legitimacy |

---

## 4. Data Leakage & Domain Overlap Risks

- **Exact Duplicate URLs:** 0 (Deduplicated during pipeline ingestion)
- **Unique Phishing Domains:** 3197
- **Unique Legitimate Domains:** 37
- **Cross-Class Overlapping Domains:** 0

> [!WARNING]
> **Data Leakage Hazard Identified:**
> CRITICAL: If train/test splitting is done randomly by URL instead of grouped by domain, models risk memorizing high-frequency domains rather than generalizing to unseen domains.
> In Phase 11 (Leakage-Safe Evaluation), we MUST use **GroupKFold by registered domain** rather than naive random train-test splitting to ensure the model generalizes across brand new domains.

---

## 5. Lexical Keyword Prevalence

| Keyword | Phishing Hits (%) | Legitimate Hits (%) | Discriminative Power |
| :--- | :---: | :---: | :--- |
| `login` | 1318 (26.41%) | 0 (0.0%) | +26.4% in phishing |
| `verify` | 1465 (29.36%) | 0 (0.0%) | +29.4% in phishing |
| `account` | 1112 (22.28%) | 0 (0.0%) | +22.3% in phishing |
| `security` | 711 (14.25%) | 296 (6.64%) | +7.6% in phishing |
| `update` | 594 (11.9%) | 0 (0.0%) | +11.9% in phishing |
| `password` | 0 (0.0%) | 0 (0.0%) | +0.0% in phishing |
| `bank` | 1135 (22.75%) | 0 (0.0%) | +22.8% in phishing |
| `payment` | 0 (0.0%) | 0 (0.0%) | +0.0% in phishing |
| `confirm` | 1025 (20.54%) | 0 (0.0%) | +20.5% in phishing |
| `wallet` | 0 (0.0%) | 0 (0.0%) | +0.0% in phishing |
| `signin` | 189 (3.79%) | 0 (0.0%) | +3.8% in phishing |
