# Real-World Generalization Benchmark: URLhaus & Tranco Validation

### Independent Validation on Live Internet Security Feeds
- **Total Samples:** 10,000 URLs
- **Real Phishing Source:** URLhaus (abuse.ch) live malware/phish feed (5,000 URLs)
- **Real Legitimate Source:** Tranco Top-1M verified live archive (5,000 URLs)
- **Unique Domains:** 7,373
- **Domain Overlap (Train ∩ Test):** 0 (Domain-Disjoint Partitioning Verified)

---

## 1. Empirical Performance on Real-World Unseen Internet Domains

When evaluated directly across domain-disjoint folds on 10,000 live internet URLs:

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | Latency / URL |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 99.85% | 100.00% | 99.71% | 99.86% | 0.9997 | 0.9998 | 0.0008 ms |
| **Decision Tree** | 99.90% | 100.00% | 99.81% | 99.90% | 0.9990 | 0.9991 | 0.0008 ms |
| **Random Forest** | 99.90% | 100.00% | 99.81% | 99.90% | 0.9998 | 0.9998 | 0.0450 ms |
| **XGBoost** | 99.90% | 100.00% | 99.81% | 99.90% | 0.9996 | 0.9997 | 0.0025 ms |

---

## 2. Scientific Disclosure: Synthetic vs. Real-World Holdout Evaluation

When the model trained primarily on synthetic development data was tested against this independent 10,000 live URL holdout:
- **Holdout Precision:** **100.00%** (0 False Positives on 5,000 legitimate enterprise and content domains)
- **Holdout Accuracy:** **93.11%**
- **Holdout Recall:** **86.16%** (detected 4,308 out of 5,000 active malicious URLs)
- **Holdout ROC-AUC:** **0.9865**

### Critical Defense & Methodology Nuance:
> *"A common mistake is claiming 'Zero Leakage' solely because domain overlap is zero. Synthetic generators inherently repeat URL path and parameter skeletons across different generated domains. Therefore, synthetic test splits often yield overly optimistic recall (~99.9%). When evaluated on 10,000 live, independently gathered URLs from URLhaus and Tranco, recall dropped to 86.16%. This ~14% delta accurately documents the boundary of passive structural URL features against diverse zero-day attack infrastructure."*
