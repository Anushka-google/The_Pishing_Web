# Phase 8: Model Experimentation & Comparative Analysis

Comparison of linear and tree-based classifiers evaluated on 9,450 URL feature vectors (stratified 80/20 holdout).

| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC | Accuracy | Train Time | Latency/URL |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Logistic Regression | 92.19% | 93.86% | 93.02% | 0.9780 | 0.9809 | 92.40% | 0.028s | 0.0007 ms |
| Decision Tree | 99.70% | 99.70% | 99.70% | 0.9977 | 0.9965 | 99.67% | 0.016s | 0.0005 ms |
| **Random Forest** | 100.00% | 99.80% | **99.90%** | 1.0000 | 1.0000 | 99.89% | 0.283s | 0.0697 ms |
| XGBoost | 99.90% | 99.80% | 99.85% | 1.0000 | 1.0000 | 99.84% | 0.132s | 0.0020 ms |

## 🏆 Final Model Selection: **Random Forest**

### Selection Rationale (Experimental Evidence vs Popularity):
1. **Evidence-Based Choice:** Rather than selecting XGBoost purely because of its popularity, the decision is driven by measured F1-score, False Negative suppression, and discriminative ranking (ROC-AUC).
2. **Recall Significance:** In cybersecurity, missing actual phishing URLs (False Negatives) is critical. The winning ensemble model captures complex non-linear combinations of Shannon entropy, character counts, and keyword frequencies.
3. **Production Latency:** All candidate models exhibit sub-millisecond inference times per URL, comfortably satisfying real-time REST API budgets.
