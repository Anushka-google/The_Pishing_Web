# Phase 13: Model Explainability Engine (Global Feature Importance & Local SHAP Attributions)

## Overview
A high classification accuracy or low false-positive rate is insufficient if security operations center (SOC) analysts and end users cannot inspect why a specific URL was flagged. Treating the machine learning classifier as an inscrutable "black box" induces alert fatigue and mistrust.

Phase 13 integrates **SHAP (SHapley Additive exPlanations)** via `shap.TreeExplainer` into the model pipeline. Every inference call produces:
1. **Global Feature Rankings:** Identifying the macro-level indicators the tree ensemble relies upon across the entire URL domain space.
2. **Local Prediction Attribution:** Mathematical decomposition of a specific URL's phishing probability into positive risk drivers ($+ \Delta$) and negative mitigating factors ($- \Delta$).
3. **Actionable Security Guidance:** Translating SHAP value vectors into clear, human-understandable verdicts.

---

## Global Feature Importance

Based on SHAP TreeExplainer computations across background validation samples:

| Rank | Feature | Mean \|SHAP\| Impact | Architectural Purpose |
|------|---------|---------------------|-----------------------|
| **1** | `query_length` | **0.0971** | Measures credential harvesting payload & token parameter bloat |
| **2** | `domain_length` | **0.0891** | Identifies combosquatting, typo-squatting & nested domain deception |
| **3** | `number_of_digits` | **0.0840** | Detects IP-based hosts and random cloud-node subdomains |
| **4** | `path_length` | **0.0440** | Flags deeply nested deceptive path structures |
| **5** | `number_of_dots` | **0.0421** | Flags excessive subdomain hierarchy and host disguises |

Summary exported to: `data/processed/global_shap_importance.json`.

---

## Local Prediction Attribution Mechanics

For any incoming URL $X = [x_1, \dots, x_{22}]$, the model prediction $f(X)$ satisfies the additive Shapley efficiency property:

$$f(X) = \phi_0 + \sum_{i=1}^{22} \phi_i(X)$$

Where:
- $\phi_0 = \mathbb{E}[f(X)]$ is the base expectation (prior probability across training data).
- $\phi_i(X) > 0$ represents **Risk-Increasing Factors** (e.g., brand tokens in subdomain, excessive entropy, query tokens).
- $\phi_i(X) < 0$ represents **Risk-Mitigating Factors** (e.g., standard domain length, absence of digits, clean path).

### Demonstration on Production Examples

#### Example 1: Benign Enterprise Authentication
- **URL:** `https://accounts.google.com/signin/v2/identifier`
- **Probability:** `0.0300` | **Risk Tier:** `LOW` | **Action:** `ALLOW`
- **Mitigating Factors:**
  - `number_of_digits = 1` ($\phi = -0.1431$)
  - `domain_length = 19` ($\phi = -0.0963$)
- **Recommendation:** `URL conforms to expected benign web standards.`

#### Example 2: Deceptive Brand Combosquatting Attack
- **URL:** `https://login.paypal.com.cloud-node-402.cc/session/verify?token=9284`
- **Probability:** `0.8800` | **Risk Tier:** `HIGH` | **Action:** `BLOCK`
- **Risk Drivers:**
  - `domain_length = 34` ($\phi = +0.1385$)
  - `suspicious_keyword_count = 2` ($\phi = +0.0489$)
  - `query_length = 10` ($\phi = +0.0473$)
- **Recommendation:** `Do not submit sensitive credentials or download files from this origin until verified.`

---

## Artifacts & Code
- Implementation: [`src/explanation/shap_explainer.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/src/explanation/shap_explainer.py)
- Global rankings: `data/processed/global_shap_importance.json`
- Test suite: [`tests/test_shap_explainer.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/tests/test_shap_explainer.py) (3 passing tests)
