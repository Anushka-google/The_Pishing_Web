# Phase 8: Model Experimentation & Comparative Analysis

Comparison of linear and tree-based classifiers evaluated on 9,450 URL feature vectors (stratified 80/20 holdout).

| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC | Accuracy | Train Time | Latency/URL |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 100.00% | 100.00% | **100.00%** | 1.0000 | 1.0000 | 100.00% | 0.011s | 0.0006 ms |
| Decision Tree | 99.90% | 100.00% | 99.95% | 0.9994 | 0.9990 | 99.95% | 0.021s | 0.0004 ms |
| Random Forest | 100.00% | 100.00% | 100.00% | 1.0000 | 1.0000 | 100.00% | 0.269s | 0.0294 ms |
| XGBoost | 100.00% | 100.00% | 100.00% | 1.0000 | 1.0000 | 100.00% | 0.057s | 0.0012 ms |

## 🏆 Final Model Selection: **Logistic Regression**

### Selection Rationale (Experimental Evidence vs Popularity):
1. **Evidence-Based Choice:** Rather than selecting XGBoost purely because of its popularity, the decision is driven by measured F1-score, False Negative suppression, and discriminative ranking (ROC-AUC).
2. **Recall Significance:** In cybersecurity, missing actual phishing URLs (False Negatives) is critical. The winning ensemble model captures complex non-linear combinations of Shannon entropy, character counts, and keyword frequencies.
3. **Production Latency:** All candidate models exhibit sub-millisecond inference times per URL, comfortably satisfying real-time REST API budgets.
