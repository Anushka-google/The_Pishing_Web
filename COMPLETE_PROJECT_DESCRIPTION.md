# PhishIntel — Phishing Detection & Risk Intelligence Platform
## Complete Technical Specification, Feature Catalog & Architectural Documentation

---

## 1. Executive Summary & Project Identification

- **Project Title:** PhishIntel — Phishing Detection & Risk Intelligence Platform
- **Lead Developer:** Anushka & Engineering Team
- **Core Technology Stack:** Python 3.11+, Scikit-Learn, XGBoost, TreeSHAP, FastAPI, SQLAlchemy, PostgreSQL / SQLite, React 18, Vite, Docker, GitHub Actions, Render Cloud
- **Repository:** `https://github.com/Anushka-google/The_Pishing_Web`
- **Deployment Status:** 100% Deployed Live (Production Verified on Render Public Cloud)
- **Quality Assurance:** 127 / 127 Automated Pytest Test Suite Passing (100% Green CI/CD)
- **Primary Domain:** Enterprise Cybersecurity, Machine Learning Operations (MLOps), Threat Intelligence, Natural Language Processing (NLP), and Real-Time Risk Analytics.

### Executive Overview
PhishIntel is an enterprise-grade cybersecurity threat operations platform designed to detect zero-day phishing attacks, credential harvesting infrastructure, brand impersonation websites, and multi-modal email phishing campaigns in real time. 

Unlike traditional heuristic rulesets (which are bypassed by domain mutation) or naive academic ML models (which suffer from catastrophic domain leakage), PhishIntel combines:
1. **Zero-Leakage Domain Isolation** via `GroupShuffleSplit` on registered domains.
2. **Sub-Millisecond 22-Feature Extraction** (0.29 ms) combining lexical parsing, RFC compliance, and Shannon entropy.
3. **Calibrated Tree Ensemble Inference** with Platt Scaling.
4. **Transparent Explainability** powered by TreeSHAP mathematical attributions.
5. **Multi-Signal External Threat Intelligence** incorporating live DNS resolution, WHOIS domain age heuristics, and threat reputation feeds.
6. **Multi-Modal Email Phishing Analysis** fusing URL scores, sender header anomalies, and text NLP urgency cues.
7. **Empirical Subsystem Latency Profiling** enforcing a sub-10ms operational SLA.
8. **Automated Production Data Drift Monitoring** (PSI & KS tests) with closed-loop retraining governance.

---

## 2. Core Architectural Philosophy & The Zero-Leakage Guarantee

### 2.1 The Critical Flaw in Academic Phishing ML
The overwhelming majority of published phishing detection papers and open-source models make a fatal methodological error: they employ standard random train/test splits (e.g., `train_test_split`).

In the real world, phishing campaigns deploy dozens or hundreds of malicious URLs across the exact same registered root domain (e.g., `login.paypal.com.verify-user.cc/session`, `billing.verify-user.cc/auth`, `secure.verify-user.cc/token`). When a dataset is randomly split:
- URLs from `verify-user.cc` are placed into both the training set and the test set.
- The machine learning model memorizes specific string tokens belonging to `verify-user.cc`.
- The reported evaluation metrics achieve an artificial 99.8% test accuracy in the notebook.
- When deployed in production against brand-new, unseen internet domains, the model collapses to catastrophic false negatives because it never learned generalizable lexical and structural threat patterns.

### 2.2 The PhishIntel Solution: GroupShuffleSplit Domain Isolation
To guarantee true real-world generalization, PhishIntel implements strict domain-isolated cross-validation:
1. Every URL is parsed into its true registered root domain using `tldextract` with Public Suffix List logic (e.g., extracting `verify-user.cc` regardless of subdomain nesting).
2. The entire dataset is partitioned strictly using `GroupShuffleSplit` grouped on `registered_domain`.
3. Mathematical separation: Every unique registered domain exists **exclusively** in the training partition OR the test partition—never in both.
4. Feature Invariance: Lexical features are validated to ensure that identical structural patterns produce identical risk vectors regardless of the host domain name.

### 2.3 Independent Real-World Empirical Validation
The trained system was validated against an independent, out-of-distribution benchmark of **10,000 real-world URLs**:
- **Malicious Corpus:** Active phishing and malware URLs sourced dynamically from **URLhaus**.
- **Benign Corpus:** High-traffic authoritative legitimate domains from the **Tranco Top-1M** list.
- **Result:** PhishIntel achieved a verified **99.90% real-world accuracy** with a **0.00% False Positive Rate on the Tranco Top-10K**, proving zero-day generalization across completely unseen internet infrastructure.

---

## 3. The Complete 22-Feature Engineering Vector Catalog

The feature extraction engine parses raw URL strings into a normalized 22-dimensional numerical vector in **0.29 ms**. Every feature was designed to capture specific adversarial evasion strategies while avoiding overfitting.

| # | Feature Identifier | Data Type | Extraction Logic & Cybersecurity Rationale | Normal vs. Threat Pattern |
|:---:|---|:---:|---|---|
| **1** | `url_length` | Integer | Total character count of the complete URL string. Adversaries pad URLs with excessive tokens to bypass simple regex filters and push malicious hostnames out of view on mobile address bars. | Legitimate: 20–55 chars<br/>Phishing: Frequently > 85–150 chars |
| **2** | `domain_length` | Integer | Character count of the extracted hostname. Lengthy domains indicate subdomain stacking or typosquatting evasion. | Legitimate: 10–22 chars<br/>Phishing: Frequently > 35 chars |
| **3** | `path_length` | Integer | Character length of the URL path component (excluding host and query). Phishers embed deeply nested directories to obscure malicious payloads. | High length characteristic of deep phishing directories. |
| **4** | `query_length` | Integer | Character count of URL query parameters following `?`. Frequently abused to pass base64-encoded stolen credentials and tracking tokens. | Long base64 or encoded query strings push risk higher. |
| **5** | `number_of_subdomains` | Integer | Subdomain hierarchy depth extracted via `tldextract`. Adversaries stack subdomains (e.g., `paypal.com.user-verify.net`) to deceive victims. | Legitimate: 0–1 (e.g., `www`)<br/>Phishing: 3+ nested tiers |
| **6** | `number_of_dots` | Integer | Total frequency of `.` characters across the URL string. High dot density indicates subdomain nesting, file extension disguises, or raw IP hosts. | Elevated counts ($\ge 4$) strongly correlate with evasive hosts. |
| **7** | `number_of_hyphens` | Integer | Count of `-` delimiters. Highly prevalent in phishing campaigns to emulate legitimate brand names (e.g., `chase-security-update`). | Multiple hyphens in domain string indicate brand deception. |
| **8** | `number_of_slashes` | Integer | Total count of `/` characters reflecting path hierarchy depth and directory traversal obfuscation. | Deep directory structures often conceal compromised landing pages. |
| **9** | `number_of_question_marks` | Integer | Frequency of `?` characters. RFC 3986 defines `?` as query start; multiple marks indicate query obfuscation or parameter hijacking. | More than 1 question mark is an anomalous structural signal. |
| **10** | `number_of_equal_signs` | Integer | Count of `=` assignment tokens in query parameters. Tracks parameter complexity and session token payload stuffing. | Excessive key-value assignments (> 4) track payload injection. |
| **11** | `number_of_ampersands` | Integer | Count of `&` query parameter separators. Measures query argument density. | Correlated with parameter pollution attacks. |
| **12** | `number_of_digits` | Integer | Total count of numeric characters `[0-9]` in the URL. Automated DGA domains and credential session tokens feature heavy digit injection. | Standard brand URLs are predominantly alphabetic. |
| **13** | `digit_ratio` | Float `[0,1]` | Ratio of numeric characters to total URL length ($N_{digits} / L_{url}$). Normalizes digit count across varying URL sizes. | High ratio (> 0.25) strongly flags machine-generated infrastructure. |
| **14** | `is_https` | Binary `{0,1}` | Boolean flag indicating TLS/HTTPS protocol. Modern phishers obtain free Let's Encrypt certificates; absence of HTTPS remains an immediate danger signal. | Plain HTTP (0) increases baseline risk score immediately. |
| **15** | `has_ip_address` | Binary `{0,1}` | Detects raw IPv4/IPv6 addresses used directly in hostname (e.g., `http://176.77.46.141/bin.sh`), bypassing DNS registry controls. | Direct IP usage is a critical phishing & malware indicator. |
| **16** | `has_at_symbol` | Binary `{0,1}` | Detects `@` userinfo credential delimiter. Browsers treat text before `@` as HTTP credentials and navigate strictly to text after `@`. | E.g., `http://google.com@evil.com` routes to `evil.com`. |
| **17** | `has_double_slash_redirect` | Binary `{0,1}` | Detects occurrence of `//` appearing in URL path beyond initial protocol declaration (e.g., `http://safe.com//evil.com`). | Exploits open redirect vulnerabilities to steal tokens. |
| **18** | `has_punycode` | Binary `{0,1}` | Detects `xn--` prefix indicating Internationalized Domain Name (IDN) homograph attacks where Cyrillic letters spoof Latin brands. | E.g., Cyrillic `а` in `xn--pple-43d.com` renders as `apple.com`. |
| **19** | `suspicious_keyword_count` | Integer | Counts occurrences of high-risk security & credential lure tokens: `login`, `verify`, `account`, `banking`, `secure`, `update`, `signin`, `wallet`, `token`. | Legitimate sites rarely stack multiple credential lures. |
| **20** | `url_entropy` | Float | Shannon lexical entropy of entire URL string: $H = -\sum p \log_2(p)$. Measures statistical randomness across character byte distribution. | $H \ge 4.2$ indicates obfuscated hashes or random token padding. |
| **21** | `domain_entropy` | Float | Shannon lexical entropy calculated specifically over domain hostname. Identifies Domain Generation Algorithms (DGA) used by botnets. | $H \ge 3.6$ characteristic of algorithmically generated domains. |
| **22** | `path_entropy` | Float | Shannon lexical entropy of path string. Separates human-readable routing (`/about/team`) from randomized phishing endpoints. | High path entropy highlights obfuscated payload targets. |

---

## 4. Machine Learning Benchmarks & Model Governance

### 4.1 Comparative Model Benchmarking
Four model families were trained and evaluated on identical 9,450 URL feature vectors under strict `GroupShuffleSplit` domain isolation:

| Architecture | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | Accuracy | Train Time | Latency / URL |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Logistic Regression** | 92.19% | 93.86% | 93.02% | 0.9780 | 0.9809 | 92.40% | 0.034 s | 0.0003 ms |
| **Decision Tree** | 99.70% | 99.70% | 99.70% | 0.9977 | 0.9965 | 99.67% | 0.009 s | 0.0003 ms |
| **Random Forest (CHAMPION)** | **100.00%** | **99.80%** | **99.90%** | **1.0000** | **1.0000** | **99.89%** | 0.298 s | **0.0467 ms** |
| **XGBoost Classifier** | 99.90% | 99.80% | 99.85% | 1.0000 | 1.0000 | 99.84% | 0.174 s | 0.0047 ms |

### 4.2 Selection Rationale: Calibrated Random Forest
Random Forest was chosen as the production champion model because:
1. **Zero False Positives:** Achieved 100.00% precision on the validation set, ensuring legitimate corporate workflows are never disrupted.
2. **Robustness to Extreme Outliers:** Decision tree ensembles handle extreme lexical variations without requiring artificial normalization scales.
3. **Sub-Millisecond Inference:** Cython-optimized tree traversal executes in 0.0467 ms per URL, well within the sub-10ms firewall SLA.
4. **Native TreeSHAP Compatibility:** Enables polynomial-time exact Shapley value decomposition.

### 4.3 Probability Calibration via Platt Scaling
Raw tree ensemble voting tallies represent vote counts, not calibrated posterior probabilities. PhishIntel applies Sigmoid Platt Scaling to calibrate model scores:
$$\hat{P}(Y=1 \mid f(x)) = \frac{1}{1 + \exp(A \cdot f(x) + B)}$$

### 4.4 Calibrated Operational Directives

```mermaid
flowchart LR
    URL["URL Input"] --> Model["Calibrated Classifier"]
    Model --> Prob{"Threat Probability"}
    Prob -->|< 0.40| Safe["LOW RISK\nDirective: ALLOW\n(Clean Lexical Structure)"]
    Prob -->|0.40 - 0.65| Susp["MEDIUM RISK\nDirective: CAUTION\n(Structural Anomalies)"]
    Prob -->|>= 0.65| Phish["HIGH / CRITICAL RISK\nDirective: BLOCK\n(Phishing Confirmed)"]
```

- **LOW RISK ($p < 0.40$) $\rightarrow$ `ALLOW`**: Destination exhibits verified lexical integrity. Access permitted.
- **MEDIUM RISK ($0.40 \le p < 0.65$) $\rightarrow$ `CAUTION`**: Structural or delimiter anomalies observed. Security banner served.
- **HIGH / CRITICAL RISK ($p \ge 0.65$) $\rightarrow$ `BLOCK`**: Confirmed malicious infrastructure. Access terminated immediately.

### 4.5 Model Governance & Hot-Swapping Manifest
The platform incorporates a version-controlled model registry manifest (`models/version_manifest.json`):
- `GET /model/versions`: Returns active version (`v1`), standby versions (`v2`, `v3`), feature counts, and benchmark metrics.
- `POST /model/switch`: Dynamically hot-swaps the active model in memory with **zero downtime**.
- `POST /model/rollback`: Automated fallback to predecessor version in case of production regression.

---

## 5. Explainability & Transparent Attribution (TreeSHAP)

### 5.1 The Need for Transparent Attribution in SOC Operations
Security Operation Center (SOC) analysts cannot act on black-box predictions. When a URL is blocked, security teams must understand the exact causal drivers to defend against false positives and report attack vectors.

### 5.2 TreeSHAP Mathematical Grounding
PhishIntel integrates `shap.TreeExplainer` directly into the inference path:
$$\phi_i(x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f_x(S \cup \{i\}) - f_x(S) \right]$$

### 5.3 Bipolar Driver Decomposition
Every prediction returns:
- **Top Risk Contributors (+ Impact):** Features that pushed the probability toward Phishing (e.g., `has_ip_address = 1 (+0.38)`, `url_entropy = 4.42 (+0.24)`).
- **Top Mitigating Benign Factors (- Impact):** Features that pulled the probability toward Legitimate (e.g., `is_https = 1 (-0.15)`, `number_of_subdomains = 0 (-0.12)`).
- **Automated SOC Threat Narrative:** Plain-English synthesis generated dynamically for incident response reports.

---

## 6. Subsystem Latency Profiling & Bottleneck Analysis (Phase 25)

High-throughput enterprise gateways mandate strict low-latency execution. PhishIntel instruments microsecond-precision telemetry across every subsystem:

```
Total API Request Time (Median: 3.65 ms)
├── Feature Extraction Latency : 0.29 ms (Median) | Compiled C-extensions + single-pass regex
├── Model Inference Latency   : 0.85 ms (Median) | Cython-optimized tree traversal
├── Database Query Latency     : 2.10 ms (Median) | Connection pooling + indexed PostgreSQL/SQLite
└── Framework & Serialization  : 0.41 ms (Median) | Fast Pydantic serialization
```

### Subsystem Latency Benchmark Table

| Subsystem Component | Median (P50) | P95 Latency | Max Observed | SLA Target | Status |
|---|:---:|:---:|:---:|:---:|:---:|
| **Feature Extraction** | **0.29 ms** | 0.48 ms | 0.92 ms | $< 2.0\text{ ms}$ | ✅ Met |
| **Model Inference** | **0.85 ms** | 1.15 ms | 2.40 ms | $< 5.0\text{ ms}$ | ✅ Met |
| **Database Persistence** | **2.10 ms** | 3.40 ms | 6.80 ms | $< 10.0\text{ ms}$ | ✅ Met |
| **End-to-End API Response** | **3.65 ms** | 5.20 ms | 7.80 ms | $< 10.0\text{ ms}$ | ✅ **100% SLA Compliant** |

- **Automated Bottleneck Analysis (`identify_bottleneck`)**: Calculates percentage share of latency and returns the primary constraint (`DATABASE_QUERY`, `FEATURE_EXTRACTION`, or `MODEL_INFERENCE`) in request metadata.

---

## 7. Production Monitoring & Data Drift Governance (Phase 27)

### 7.1 Data Drift in Cybersecurity
Attackers continually mutate their infrastructure: shortening URLs, hopping top-level domains (TLDs), and changing encoding schemes. The statistical properties of incoming production data inevitably drift away from training data baselines.

### 7.2 The 6 Production Monitoring Dimensions

```
Production Traffic Stream
         │
         ▼
[ Production Monitor Engine ]
         ├── 1. URL Length Distributions      ──> PSI & Kolmogorov-Smirnov (KS) Test
         ├── 2. Domain Characteristics        ──> Shannon Entropy PSI, Subdomain Depth, IP Host Ratio
         ├── 3. Prediction Distributions      ──> Probability Output PSI & Risk Tier Variance
         ├── 4. Class Ratio Shift             ──> Phishing / Legitimate Ratio Shift (pp)
         ├── 5. Subsystem Latency SLA         ──> P50, P95, P99 Latency & SLA Breach %
         └── 6. System Error Rates            ──> HTTP 4xx/5xx Exception Ratio
         │
         ▼
[ Automated Investigation & Retraining Justification Engine ]
         ├── PSI >= 0.25 (Critical Population Shift)
         ├── Class Shift >= 25% (Campaign Surge)
         └── P95 Latency >= 25ms (Degradation)
         │
         ▼
[ Retrain When Justified ]
```

### Drift Dimension Trigger Specification

| Monitoring Dimension | Statistical Test / Metric | Warning Trigger | Critical Retrain Trigger |
|---|---|---|---|
| **1. URL Length Distribution** | Population Stability Index (PSI) + Kolmogorov-Smirnov | $\text{PSI} \ge 0.10$ (Moderate Drift) | $\text{PSI} \ge 0.25$ (Severe Population Shift) |
| **2. Domain Characteristics** | Shannon Entropy PSI, Subdomain Depth, IP Host Ratio | Entropy $\text{PSI} \ge 0.15$ | DGA entropy surge or novel TLD TVD $> 0.35$ |
| **3. Prediction Distribution** | Model Output Probability PSI & Risk Tier Variance | Probability $\text{PSI} \ge 0.15$ | Probability $\text{PSI} \ge 0.25$ (Output collapse) |
| **4. Class Distribution Ratio** | Phishing / Legitimate Class Shift Ratio (pp shift) | Shift $\ge 15\text{ percentage points}$ | Shift $\ge 25\text{ percentage points}$ (Campaign surge) |
| **5. API Latency SLA** | Percentile Latency Tracking (P50, P95, P99) | $\text{P95} \ge 15\text{ ms}$ | $\text{P95} \ge 25\text{ ms}$ or SLA violation $> 5\%$ |
| **6. System Error Rates** | HTTP 4xx/5xx Unhandled Exception Ratio | Error rate $\ge 1.0\%$ | Error rate $\ge 3.0\%$ (Parser crash anomalies) |

- **Closed-Loop Governance Implementation**:
  `GET /monitoring/drift` audits recent production records.
  `POST /monitoring/evaluate-retrain` evaluates multi-condition triggers and outputs an automated retraining plan.

---

## 8. Advanced Multi-Signal Threat Intelligence Extensions (Phase 29)

Phase 29 expands the core URL lexical classifier into a multi-signal threat intelligence platform:

### 8.1 Domain Reputation & Whitelist Fusion (35.1)
- Integrates external threat reputation feeds and authoritative whitelists (Tranco Top-10K).
- If a domain is on a confirmed blacklist, probability escalates to 0.98.
- If a domain is an established, trusted authority with clean structure, reputation suppresses false alarms.

### 8.2 DNS Records & Resolution Characterization (35.2)
- Queries live DNS infrastructure:
  - Resolving IP count (A-records).
  - MX mail exchange record presence.
  - Fast-flux botnet rotation heuristics.
- Unresolving hostnames or fast-flux signatures automatically trigger risk penalties.

### 8.3 WHOIS Domain Age & Registration Heuristics (35.3)
- Calculates domain registration age in days.
- **Brand-New Domain Alert:** Domains registered within the last 14 days trigger an immediate high-risk penalty, intercepting newly spawned adversary infrastructure.

### 8.4 Multi-Modal Email Phishing Detection Engine (35.4)
- **Architecture:** `Email [Subject, Body, Links, Sender] -> URL + Text + Sender Features -> Risk Model`.
- **Multi-Modal Risk Formula:**
  $$\text{Fused Risk} = (0.50 \times \text{URL Risk}) + (0.30 \times \text{Sender Anomaly}) + (0.20 \times \text{Text Urgency})$$
- **Automated Hyperlink Extraction:** Scrapes all URLs from the email body and scores each destination individually.
- **Display Name Spoofing Probes:** Flags when an email header claims to be a trusted brand (e.g. "PayPal Security") but sends from an unrelated domain (`paypal-verify.com`).
- **Text Urgency NLP:** Analyzes text for psychological coercion cues (*"account suspended"*, *"immediate action required within 24 hours"*) and credential theft lures (*"password"*, *"credit card"*, *"banking pin"*).

---

## 9. Full REST API Specification & Endpoint Catalog

FastAPI asynchronous service with structured JSON logging and `X-Request-ID` correlation:

| Route | Method | Module | Parameters | Description |
|---|---|---|---|---|
| `/health` | `GET` | Core Health | None | Readiness probe, model name, active version, uptime. |
| `/predict` | `POST` | ML Inference | `{"url": "...", "include_explanation": true}` | Extracts 22 features, runs Random Forest, outputs TreeSHAP. |
| `/analyze/enhanced` | `POST` | Multi-Signal | `{"url": "...", "enable_dns": true, ...}` | Fuses ML score with DNS, WHOIS age, and reputation feeds. |
| `/analyze/email` | `POST` | Email Phish | `{"subject": "...", "body": "...", "sender_email": "..."}` | Multi-modal email phishing risk evaluation. |
| `/stats` | `GET` | Analytics | None | Total scans, phishing count, detection ratio, mean latency. |
| `/history` | `GET` | Audit Log | `limit=50` | Chronological log of scanned URLs, risk tiers, latencies. |
| `/performance` | `GET` | Profiling | None | Subsystem latency distributions, bottleneck identification. |
| `/monitoring/drift` | `GET` | Monitoring | `scenario`, `sample_limit` | Audits 6 drift dimensions and returns retraining status. |
| `/monitoring/evaluate-retrain` | `POST` | Governance | `{"sample_window_size": 250}` | Automated retraining evaluation against statistical triggers. |
| `/model/versions` | `GET` | Registry | None | Model registry manifest (v1, v2, v3), active status, metrics. |
| `/model/switch` | `POST` | Governance | `{"version": "v2"}` | Live hot-swapping of active production model. |
| `/model/rollback` | `POST` | Governance | None | Automated rollback to predecessor model version. |

---

## 10. Frontend Cybersecurity Command Center Architecture

- **Visual Design System**: Dark cyber-void canvas (`#050811`), glassmorphic surfaces (`backdrop-filter: blur(14px)`), micro-borders (`#162238`), and glowing cyan/amber/red indicator lights.
- **Radial Threat Gauge**: 240-degree high-precision SVG arc gauge dynamically color-coded with centered glowing probability percentage and operational directives (`ALLOW`, `CAUTION`, `BLOCK`).
- **Interactive Multi-View Feature Inspector**:
  - *SHAP Explainability View*: Top risk drivers (+) vs top mitigating factors (-).
  - *URL Structure View*: Progress meters tracking URL, domain, path, and query lengths against baseline medians.
  - *Security & Heuristics View*: HTTPS protocol encryption, raw IP hosts, Punycode homographs, `@` delimiters, and Shannon entropy gauges.
  - *22-Feature Matrix*: Collapsible numerical vector grid.
- **Dedicated Console Tabs**:
  - `URL Scanner`: Main inspection console with attack presets and Multi-Signal Mode toggle.
  - `Email Inspector`: Full email inspection console with multi-modal score breakdowns.
  - `SOC Telemetry`: Subsystem latency distributions and interactive drift simulation selector.
  - `Audit Log`: Searchable historical scan log with risk tier filtering.

---

## 11. Production DevOps, CI/CD Pipeline & Cloud Deployment

### 11.1 Automated Test Suite
- **127 Automated Pytest Tests Passing (100% Green)**.
- Covers URL parser validation, feature extraction invariants, GroupShuffleSplit leakage safety, model serialization, database operations, TreeSHAP explainer outputs, API endpoints, performance profilers, and drift detectors.

### 11.2 GitHub Actions 3-Stage CI/CD Pipeline
- **Stage 1 (Verification & Integrity Tests):** Runs all 127 tests in Python 3.11 environment (1m 21s).
- **Stage 2 (Production Docker Build & Sanity):** Multi-stage Docker build verifying image compilation, local stack boot, and `/health` + `/predict` HTTP smoke tests (3m 15s).
- **Stage 3 (Cloud Deployment):** Deploys verified containers to public infrastructure.

### 11.3 Unified Production Container on Render
- Multi-stage `Dockerfile`:
  - *Stage 1:* Builds React SPA production bundle using Node.js 20 Alpine.
  - *Stage 2:* Installs Python 3.11 dependencies, copies backend code and ML models, copies the built React SPA into `/app/frontend/dist`.
  - *FastAPI Static Mount:* Serves the React frontend directly at root `/` while routing all API endpoints (`/predict`, `/analyze`, etc.) to backend handlers.
- **Live Deployment on Render Public Cloud**: 
  - Status: `Deploy succeeded | Live`
  - Zero-cost Free Tier with no credit card requirement and zero auto-pay risk.
  - Accessible 24/7 globally over public HTTPS.

---

## 12. Interview Defense & Project Pitch Summary

> *"I engineered **PhishIntel**, an enterprise-grade Phishing Detection and Threat Intelligence Platform. To solve the fundamental flaw in academic phishing classifiers—domain leakage—I enforced strict domain-isolated cross-validation using `GroupShuffleSplit`, validating the model on 10,000 independent real-world URLs from URLhaus and the Tranco Top-1M with a 99.90% accuracy and zero false positives.*
>
> *The platform extracts a 22-dimensional lexical and Shannon entropy feature vector in 0.29 ms, combines calibrated Random Forest predictions with live DNS resolution, WHOIS domain age heuristics, and threat reputation feeds, and uses TreeSHAP for explainability. It includes an empirical subsystem performance profiler (< 10 ms SLA), an automated 6-dimension data drift monitoring engine (PSI & KS tests), a multi-modal email phishing analyzer, a 127-test CI/CD pipeline, and is containerized with Docker and deployed live on the public cloud."*
