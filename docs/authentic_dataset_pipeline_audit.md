# Authentic Phishing Dataset Pipeline & Benchmark Audit

**Audit Date:** 2026-11-21  
**Dataset Architecture:** Strict Separation of Synthetic Development Data vs. Authentic Wild Threat Feeds  
**Authentic Feature File:** [`data/real_world/features_real_world.csv`](file:///C:/Users/anush/OneDrive/Desktop/Projects/Startup/Phishing_web/data/real_world/features_real_world.csv)  
**Authentic URL Metadata:** [`data/real_world/urls_authentic.csv`](file:///C:/Users/anush/OneDrive/Desktop/Projects/Startup/Phishing_web/data/real_world/urls_authentic.csv)  

---

## 1. Executive Summary

To eliminate synthetic dataset bias and avoid artificial 99.9% metrics, we engineered an **Authentic Real-World URL Pipeline**. 

Rather than relying on templated generation, this pipeline directly ingests live threat intelligence feeds and research benchmarks:
- **Total Authentic URLs Ingested:** **20,013 clean records**
- **Unique Registered Domains:** **14,889 unique domains** (Mozilla Public Suffix List verified)
- **Class Balance:** **49.96% Phishing (9,998) / 50.04% Benign (10,015)**
- **Exact Duplicates Removed:** **1**
- **Near-Duplicate Structural Clusters:** **206 clusters (603 URLs)**

---

## 2. Ingestion Feeds & Provenance

| Source | Count | Class | Provenance & Description |
| :--- | :---: | :---: | :--- |
| **Cisco PhishTank** | **4,998** | Phishing (1) | Verified active phishing URLs from Cisco PhishTank live feed (`https://data.phishtank.com/data/online-valid.csv`), preserving submission timestamps. |
| **URLhaus (abuse.ch)** | **5,000** | Phishing (1) | Real-world active malware and credential payload URLs collected from abuse.ch URLhaus threat database. |
| **Tranco Top-1M** | **10,000** | Legitimate (0) | Academic research ranking (`https://tranco-list.eu/`), hardened against traffic manipulation. |
| **Enterprise SSO Hard Negatives** | **15** | Legitimate (0) | Curated corporate authentication and identity portals (`accounts.google.com`, `auth.github.com`, `paypal.com`, `login.microsoftonline.com`) to enforce zero false alarms on login tokens. |

---

## 3. Empirical Evaluation Results

### Strategy 1: Domain-Grouped Split (Leakage-Safe, 0% Domain Overlap)
*Partitioned using `GroupShuffleSplit` on `registered_domain` across 14,889 domains. Train Domains $\cap$ Test Domains $= \emptyset$.*

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | FNR | Latency / URL |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 97.84% | 99.77% | 96.16% | 97.93% | 0.9918 | 0.26% | 3.84% | 0.0002 ms |
| **Decision Tree** | 97.89% | 99.49% | 96.52% | 97.98% | 0.9858 | 0.56% | 3.48% | 0.0003 ms |
| **Random Forest** | 98.18% | 99.63% | 96.92% | 98.26% | 0.9947 | 0.41% | 3.08% | 0.0178 ms |
| **XGBoost** | **98.20%** | **99.54%** | **97.06%** | **98.28%** | **0.9941** | **0.51%** | **2.94%** | 0.0021 ms |

---

### Strategy 2: Time-Based Chronological Split (Past $\to$ Future)
*Chronological split on `collection_timestamp`. Train on historical 80% (July–October 2026), test on future 20% (October–November 2026). Simulates real production SOC drift.*

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | FNR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 94.08% | 99.85% | 91.80% | 95.65% | 0.9874 | 0.34% | 8.20% |
| **Decision Tree** | 94.60% | 99.92% | 92.47% | 96.05% | 0.9778 | 0.17% | 7.53% |
| **Random Forest** | **94.90%** | **99.96%** | **92.85%** | **96.28%** | **0.9896** | **0.09%** | **7.15%** |
| **XGBoost** | **94.90%** | **99.92%** | **92.89%** | **96.28%** | **0.9895** | **0.17%** | **7.11%** |

*Key Insight:* Across time, false positives remain near-zero ($0.09\%$), but false negatives increase from $2.9\%$ to $7.1\%$. This accurately reflects attackers adapting obfuscations over time.

---

### Strategy 3: Independent External Holdout (Synthetic Dev $\to$ Authentic Wild)
*Models trained purely on the synthetic development dataset (`data/processed/features.csv`, 9,206 URLs) and tested on 19,754 disjoint authentic wild URLs (`data/real_world/features_real_world.csv`).*

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | FPR | FNR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 75.83% | 98.40% | 52.07% | 68.11% | 0.7775 | 0.83% | 47.93% |
| **Decision Tree** | 71.15% | 98.99% | 42.22% | 59.19% | 0.7099 | 0.42% | 57.78% |
| **Random Forest** | 72.99% | 99.98% | 45.52% | 62.55% | 0.8763 | 0.01% | 54.48% |
| **XGBoost** | 50.57% | 65.43% | 0.54% | 1.07% | 0.7717 | 0.28% | 99.46% |

*Critical Insight:* Models trained purely on synthetic templates suffer a **catastrophic drop in recall (missing 48% to 99% of live threats)**. This proves that synthetic templates do not transfer to production, and validates the necessity of our authentic dataset pipeline.

---

## 4. Dataset Bias & Operational Limitations

1. **Target Bias in PhishTank:** PhishTank is community-reported, which skews toward recognizable high-volume consumer brands (PayPal, Microsoft, Netflix, banks).
2. **Payload Bias in URLhaus:** URLhaus focuses on active malware distribution and infostealer payloads; these frequently use raw IP addresses or dynamic ports (`:8080`, `:52929`), causing higher digit-to-letter ratios.
3. **Tranco Depth Limitation:** Tranco provides high-reputation registered root domains; to simulate authentic web navigation, standardized benign paths were mapped.
