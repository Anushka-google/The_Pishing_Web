# Phase 2: Research Existing Approaches & Hybrid Architecture

## 1. Executive Overview

Phishing detection mechanisms have evolved through four distinct paradigms. Understanding the technical mechanics, performance characteristics, and failure modes of each paradigm is crucial for architecting a resilient detection engine.

```
Incoming URL
     │
     ├───▶ [ Layer 1: Blacklist / Reputation Check ] ──(Match)──▶ Instant Verdict (P = 1.0, HIGH)
     │
     ├───▶ [ Layer 2: Heuristic Rule Engine ] ────────(Flag)───▶ Heuristic Anomaly Signals
     │
     └───▶ [ Layer 3: ML Feature & Inference Engine ] ─────────▶ Calibrated Posterior P(Phishing | X)
                                                                            │
                                                                            ▼
                                                                  [ Hybrid Risk Engine ]
                                                                            │
                                                                            ▼
                                                               Final Tiered Risk Assessment
```

---

## 2. Comparative Analysis of Detection Paradigms

### 2.1 Blacklist-Based Detection
* **Mechanism:** Queries against centralized databases of verified malicious URLs, IP addresses, or domain reputation lists (e.g., PhishTank, URLhaus, Google Safe Browsing, Spamhaus).
* **Strengths:**
  - Virtually zero false positives for verified entries.
  - Extremely fast lookups (O(1) in hashed bloom filters or Redis/RocksDB).
  - High forensic confidence.
* **Critical Limitations:**
  - **Zero-Day Blindness:** Modern phishing campaigns are transient; median active lifespan of a phishing domain is under **2 to 4 hours**. By the time a URL is reported, verified, and distributed to feeds, the campaign has often completed its harvest.
  - **Bypasses:** Simple query parameter modifications, path padding, or ephemeral subdomains evade exact-string blacklist lookups.

### 2.2 Heuristic-Based Detection
* **Mechanism:** Evaluates handcrafted rule sets and regular expressions checking for known attack signatures:
  - Raw IP address in hostname (e.g., `http://192.168.1.1/login`).
  - Brand keywords in subdomains (`paypal.com.account-update.xyz`).
  - High symbol density (excessive hyphens, dots, percentage encoding).
  - Deceptive protocols or embedded credentials (`user@host`).
* **Strengths:**
  - Completely deterministic and human-interpretable.
  - Instantaneous execution without external network lookups or large ML models.
* **Critical Limitations:**
  - **High False Positive Rate:** Legitimate enterprise Single Sign-On (SSO) systems (e.g., Okta, Ping Identity), AWS S3 pre-signed URLs, and marketing campaign redirectors naturally exhibit high symbol density and brand tokens.
  - **Brittleness:** Attackers easily circumvent static regex rules through novel encoding or alternative token placements.

### 2.3 Machine-Learning-Based Detection
* **Mechanism:** Extracts high-dimensional feature vectors $\phi(X) \in \mathbb{R}^d$ capturing structural, lexical, statistical, and information-theoretic (entropy) dimensions, and trains a statistical classifier (e.g., Logistic Regression, Random Forest, XGBoost) to learn non-linear decision boundaries:
  $$\hat{P}(\text{Phishing} \mid X) = f_\theta(\phi(X))$$
* **Strengths:**
  - **Zero-Day Generalization:** Detects brand new, previously uncataloged phishing URLs by identifying latent structural patterns common to deceptive campaigns.
  - **Calibrated Probabilities:** Yields continuous posterior probabilities rather than hard binary outputs, enabling customized risk thresholds.
* **Critical Limitations:**
  - **Data Leakage & Bias:** Susceptible to training set artifacts (e.g., overfitting to specific TLDs or domains present in training data).
  - **Concept Drift:** Adversaries adapt URL structures over time, requiring systematic retraining and drift monitoring.

### 2.4 Hybrid Detection Architecture
* **Mechanism:** Synthesizes the speed and certainty of blacklists, the deterministic safeguards of heuristics, and the predictive generalization of machine learning into a tiered, hierarchical decision engine.
* **Decision Precedence:**
  1. *Fast-Path Blacklist Match:* If URL exists in verified threat feeds, immediately output $P = 1.0$ (High Risk) with zero model latency.
  2. *Static URL Feature Extraction + ML Scoring:* If not blacklisted, compute $P_{\text{ML}} = f_\theta(\phi(X))$.
  3. *Heuristic & Reputation Adjustment:* Adjust risk confidence when severe structural violations (e.g., IP address + banking keyword) are present.

---

## 3. Technology Trade-Off Matrix

| Metric | Blacklist | Heuristic | Pure ML | Hybrid Engine (Our Target) |
| :--- | :---: | :---: | :---: | :---: |
| **Zero-Day Detection** | ❌ None (0%) | ⚠️ Weak (<40%) | ✅ High (>90%) | ✅ **High (>92%)** |
| **False Positive Rate** | ✅ ~0% | ❌ High (8-15%) | ⚠️ Low-Med (2-5%) | ✅ **Very Low (<1.5%)** |
| **Inference Latency** | < 1 ms | < 0.5 ms | 2 - 10 ms | **< 5 ms** |
| **Offline Capability** | ❌ (requires sync) | ✅ Fully local | ✅ Fully local | ✅ **Fully local / syncable** |
| **Explainability** | High (matched feed) | High (rule triggered) | Requires SHAP | **High (rules + SHAP)** |

---

## 4. Implementation Strategy for Version 1

Following the project roadmap guideline:
> *Version 1 should focus on static URL features plus ML. Hybrid signals can be added later.*

We structure the core engine with a **clean, decoupled interface** where:
- The ML Pipeline remains self-contained and strictly evaluated on its own merits (Phases 5-14).
- The `HybridRiskEngine` abstraction is established so that local blacklist fast-paths and heuristic guardrails seamlessly wrap the ML classifier without altering its inputs or training pipeline.
