# Phase 1: Minimum Viable Product (MVP) Definition

## 1. MVP Purpose & Scope

The objective of Phase 1 is to explicitly define the **Minimum Viable Product (MVP)** for the Phishing Detection & Risk Intelligence Platform.

As stated in the project roadmap:
> *Minimum Viable Product (MVP) means the smallest complete version that demonstrates the core problem-solving capability.*
> *Do not begin with React, AWS, or advanced MLOps. First prove that the ML problem can be solved reliably.*

---

## 2. Core MVP Pipeline

The core MVP pipeline executes a deterministic, reproducible, 5-stage inference flow:

```
[ Input: Raw URL String ]
           │
           ▼
┌─────────────────────────────────┐
│ Stage 1: URL Validation & Parse │  ──▶ Rejects invalid/malformed URLs, normalizes scheme/domain
└─────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│ Stage 2: Feature Extraction     │  ──▶ Extracts length, character, structural, & lexical signals
└─────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│ Stage 3: ML Model Scoring       │  ──▶ Computes raw class probability: P(Phishing | Features)
└─────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────┐
│ Stage 4: Risk Classification    │  ──▶ Maps probability to calibrated tiers: LOW, MEDIUM, HIGH
└─────────────────────────────────┘
           │
           ▼
[ Output: Structured Risk Assessment Object ]
```

---

## 3. Data Contracts & Schemas

### 3.1 Input Contract
```json
{
  "url": "https://secure-login.bank-update-auth.com/account/login?id=9281"
}
```

*Requirements:*
- Must be a non-empty string.
- Scheme must be `http` or `https` (auto-prepended if omitted in interactive modes).
- Length must not exceed standard limits (e.g. 2048 characters).

### 3.2 Output Contract
```json
{
  "url": "https://secure-login.bank-update-auth.com/account/login?id=9281",
  "prediction": "phishing",
  "probability": 0.942,
  "risk_level": "HIGH",
  "confidence": 0.942,
  "risk_thresholds": {
    "low_threshold": 0.30,
    "high_threshold": 0.70
  },
  "summary": "High risk detected. Multiple phishing indicators present (suspicious keywords, high subdomain depth, unusual length).",
  "execution_time_ms": 1.45
}
```

---

## 4. Risk Classification Logic

The binary prediction and risk classification are derived from posterior probability $\hat{P}(Y = 1 \mid X)$:

| Probability Range | Risk Level | Primary Action | Default Prediction |
| :---: | :---: | :--- | :---: |
| $0.00 \le P < 0.30$ | **LOW** | Safe to proceed; benign patterns observed. | `legitimate` |
| $0.30 \le P < 0.70$ | **MEDIUM** | Caution advised; anomalous features present. Request verification. | `suspicious / review` |
| $0.70 \le P \le 1.00$ | **HIGH** | Dangerous; strong phishing patterns detected. Proactively block. | `phishing` |

---

## 5. MVP Component Boundaries

1. **`URLParser` / `URLValidator`**:
   - Parses RFC 3986 components (scheme, netloc, path, query, fragment).
   - Validates format and checks for IP-based hosts or missing domains.
2. **`FeatureExtractor`**:
   - Extracts exact numerical vector $\phi(X) \in \mathbb{R}^d$.
   - Must be strictly stateless and reproducible across training and inference.
3. **`PhishingClassifier`**:
   - Encapsulates trained statistical model estimator.
   - Exposes `.predict_proba(X)` interface returning $P(Y=1 \mid X) \in [0, 1]$.
4. **`RiskEngine`**:
   - Evaluates probability against calibrated thresholds $\tau_{\text{low}}$ and $\tau_{\text{high}}$.
   - Generates structured risk assessment and human-readable explanation summary.

---

## 6. Acceptance Criteria for MVP
- [x] Clear data contracts for inputs, feature mappings, and outputs.
- [x] Deterministic mapping from URL to feature representation.
- [x] Probabilistic classification contract with calibrated risk levels.
- [x] Modular testable Python classes decoupling parsing, feature extraction, and risk assignment.
- [x] 100% automated test coverage of MVP pipeline interfaces.
