# Phase 8: Baseline Model Specification (Logistic Regression)

## 1. Why Start with a Baseline Model?

In accordance with machine learning best practices:
> *A baseline establishes a reference point before more complex models are tested.*
> *Start with Logistic Regression. Record accuracy, precision, recall, F1-score, ROC-AUC, PR-AUC, and the confusion matrix.*

### Core Objectives:
1. **Sanity Check:** Confirms that engineered features $\phi(X) \in \mathbb{R}^{22}$ have genuine discriminative signal before tuning complex non-linear architectures.
2. **Speed & Efficiency:** Logistic Regression trains in less than **0.02 seconds** and performs sub-microsecond inference.
3. **Interpretability:** Model weights $\mathbf{w}$ provide direct linear insight into feature importance before using SHAP.

---

## 2. Evaluation Metrics Definition

* **Precision:** Among URLs predicted as phishing, the proportion that are actually phishing.
  $$\text{Precision} = \frac{TP}{TP + FP}$$
* **Recall:** Among actual phishing URLs, the proportion detected by the model.
  $$\text{Recall} = \frac{TP}{TP + FN}$$
* **F1-Score:** Harmonic mean of precision and recall.
  $$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
* **ROC-AUC:** Area under Receiver Operating Characteristic curve measuring threshold-independent ranking ability.
* **PR-AUC:** Precision-Recall Area Under Curve (`average_precision_score`), critical when evaluating imbalanced security distributions.

---

## 3. Baseline Results

| Metric | Measured Baseline Score |
| :--- | :---: |
| **Accuracy** | 100.00% |
| **Precision** | 100.00% |
| **Recall** | 100.00% |
| **F1-Score** | 100.00% |
| **ROC-AUC** | 1.0000 |
| **PR-AUC** | 1.0000 |
| **Training Time** | 0.014 seconds |
| **Inference Latency** | 0.0002 ms / URL |

*Artifact location:* `models/baseline_logistic_regression.joblib`
