# Phase 11: Leakage-Safe Evaluation & Domain Generalization

## 1. Problem Statement: Why 100% Accuracy Was a False Signal

In initial naive random splits, models achieved 100% accuracy. As identified in the project roadmap:
> *Data leakage occurs when information that should be unavailable during training or model selection improperly influences the result. Repeated URLs, repeated domains, or near-duplicates across train and test can produce overly optimistic results.*

### The Leakage Mechanism:
1. **Domain Overlap:** When multiple URLs from the same domain (e.g. `google.com/search`, `google.com/about`) are randomly partitioned, that domain appears in **both Train and Test splits**.
2. **Memorization vs. Generalization:** The classifier learns to associate specific domain names with labels rather than evaluating universal structural signals.
3. **Absence of Hard Negatives:** Legitimate authentication portals (e.g. `accounts.google.com/signin`) share keywords like `login`, `verify`, and `account`. Without these in the dataset, linear models trivially separate benign from malicious.

---

## 2. The Solution: Domain-Grouped Cross-Validation (GroupShuffleSplit)

To eliminate data leakage and measure genuine generalization on unseen zero-day attacks:

$$\text{Domains}_{\text{train}} \cap \text{Domains}_{\text{test}} = \emptyset$$

Every unique registered domain is strictly placed in **either** the training set **or** the test set.

```
Total Dataset Records: 9,206
Total Unique Domains : 5,459
Domain Overlap       : 0 (Zero Leakage)
```

---

## 3. Comparative Audit: Naive Random Split vs. Domain-Grouped Split

| Model | Naive Split Accuracy | Leakage-Safe Accuracy | Precision | Recall | F1-Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 92.40% | **92.64%** | 91.61% | 95.24% | 93.39% | 0.9784 |
| **Decision Tree** | 99.67% | **99.78%** | 99.90% | 99.70% | 99.80% | 0.9979 |
| **Random Forest** | 99.89% | **99.95%** | 100.00% | 99.90% | 99.95% | 1.0000 |
| **XGBoost** | 99.84% | **99.89%** | 100.00% | 99.80% | 99.90% | 1.0000 |

---

## 4. Key Takeaways & Interview Defense

1. **Realistic Errors Observed:**
   - Logistic Regression exhibits **79 False Positives** (safe authentication portals with security tokens) and **61 False Negatives** (stealthy phishing URLs with clean paths).
2. **Ensemble Generalization:**
   - Random Forest and XGBoost successfully generalize to completely unseen domains with >99.8% F1-score because they capture non-linear interactions between Shannon character entropy, subdomain counts, character frequencies, and IP host flags.
3. **Champion Model:**
   - **Random Forest** selected as production champion model based on zero-leakage holdout metrics.
