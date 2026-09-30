# Phase 0: Understanding the Problem & Threat Modeling

## 1. Executive Summary
This document establishes the theoretical, security, and mathematical foundation for the **Phishing Detection & Risk Intelligence Platform**. Phishing remains one of the primary vectors for initial access, credential harvesting, and enterprise breaches. Rather than treating URL classification as an abstract computer science classification exercise, this project models real-world adversarial tactics and maps them into an engineered machine-learning system.

---

## 2. Threat Landscape & Attack Mechanisms

### 2.1 What is Phishing?
Phishing is a form of social engineering where an adversary impersonates a trustworthy entity (e.g., banks, identity providers, cloud services, internal IT) to manipulate victims into taking harmful actions. These actions include:
- Disclosing confidential credentials (usernames, passwords, 2FA tokens, recovery codes).
- Revealing financial information (credit card numbers, banking PINs).
- Downloading and executing malware, ransomware, or infostealers.

### 2.2 URL-Based Phishing Anatomy
In URL phishing, the hyperlink is the primary vehicle delivering the victim to the attack infrastructure. Adversaries design URLs to defeat both human visual scrutiny and automated security filters:

```
https://login.microsoft.com.account-verification-auth.xyz:8443/auth/v2/login?id=93821#section2
└─┬─┘   └───────────┬───────────┘└─────────────┬────────────┘ └──┬─┘ └───────┬──────┘ └───┬───┘ └───┬────┘
Scheme   Impersonated Brand/Subdomain   Registered Domain       Port        Path          Query   Fragment
```

Key attack techniques include:

#### A. Domain Spoofing & Brand Impersonation
Attackers incorporate well-known brand names into domain names or subdomains to induce false trust.
- *Domain Impersonation*: Registering domains mimicking authentic services (`secure-paypal-login.com`).
- *Subdomain Masquerading*: Exploiting the human habit of reading left-to-right (`login.microsoft.com.attacker.xyz`). The fully qualified domain name (FQDN) is hosted on `attacker.xyz`, but the prefix fools unsuspecting users.

#### B. Typosquatting, Combosquatting, and Bitsquatting
- **Typosquatting**: Registering common misspellings of popular domains (omissions: `gogle.com`, substitutions: `paypa1.com`, duplications: `netflixx.com`, transpositions: `yuotuube.com`).
- **Combosquatting**: Pairing legitimate brand names with security or functional terms (`chase-security.com`, `apple-id-recovery.net`).
- **Bitsquatting**: Exploiting single-bit memory or DNS transfer errors resulting in accidental lookups to adjacent domains (e.g., bit-flip on character 'd' `01100100` to 'e' `01100101`).

#### C. Internationalized Domain Names (IDN) & Homograph Attacks
Adversaries exploit Unicode scripts containing glyphs identical or nearly identical to Latin characters (confusables):
- Latin `a` (`U+0061`) vs Cyrillic `а` (`U+0430`).
- Latin `o` (`U+006F`) vs Greek `ο` (`U+03BF`) or Cyrillic `о` (`U+043E`).
- An attacker registers `xn--pple-43d.com`, which browsers render as `аpple.com`. Automated inspection must inspect both the Punycode format and decoded Unicode strings.

#### D. Malicious Redirects & Open Redirect Vulnerabilities
Attackers frequently leverage open redirect vulnerabilities on legitimate services:
- Example: `https://www.google.com/url?q=https://phishing-site.ru` or `https://login.trusted-site.com/logout?returnUrl=https://evil.net`.
- Intermediate redirects (HTTP 301/302, HTML `<meta http-equiv="refresh">`, or client-side JavaScript `window.location`) bypass static domain reputation lookups before delivering the payload.

#### E. Credential Harvesting Workflows
Modern credential harvesting campaigns employ sophisticated multi-step flows:
1. **Victim Lands on Phishing Page**: Replicated pixel-perfect authentication UI.
2. **Primary Credential Entry**: Username and password captured via asynchronous `fetch`/`POST` to an exfiltration endpoint.
3. **Real-time Relay (Adversary-in-the-Middle / AitM)**: Reverse proxies (e.g., Evilginx) intercept session cookies and OTP tokens, bypassing conventional 2FA.
4. **Post-Harvest Deception**: Victim is redirected to the genuine login page or shown a fake "Session Expired" error to avoid immediate suspicion.

---

## 3. Why Malicious URLs Can Appear Legitimate

A fundamental pitfall in naive security systems is assuming malicious sites have obvious flaws (e.g., broken SSL or crude spelling). Modern phishing infrastructure looks convincingly benign:

1. **Ubiquitous HTTPS (The Green Lock Fallacy)**:
   - Certificate Authorities like Let's Encrypt, Cloudflare, and cPanel issue automated, free SSL/TLS certificates.
   - Over **85% of modern phishing sites serve traffic over HTTPS**. The presence of HTTPS indicates encryption in transit, *never* the legitimacy or benevolence of the destination.
2. **Abuse of Legitimate Public Infrastructure & Serverless Hosting**:
   - Attackers deploy phishing forms directly on legitimate platforms:
     - `https://xyz-portal.web.app` (Google Firebase)
     - `https://auth-recovery.pages.dev` (Cloudflare Pages)
     - `https://verification-step.s3.amazonaws.com/...` (AWS S3)
     - `https://form.typeform.com/to/...` (Typeform / Microsoft Forms)
   - These URLs possess reputable root domains, valid high-trust SSL certificates, and pass IP reputation filters.
3. **URL Shorteners & Obfuscation**:
   - Services like `bit.ly`, `tinyurl.com`, and `t.co` mask malicious parameters and destinations under widely trusted domains.
4. **Delimiter & Credential Parsing Exploits**:
   - RFC 3986 allows user credentials in URIs before the `@` symbol:
     - `http://www.google.com:account-security@phishing-server.com/login`
     - While modern browsers discourage or strip inline credentials, legacy clients and embedded webviews can still be deceived.

---

## 4. Machine Learning Formulation

### 4.1 Problem Definition
URL phishing detection is formulated as a supervised binary classification and probabilistic risk estimation problem:

Let $\mathcal{U}$ be the universe of all valid Uniform Resource Locators.
Given an input URL $X \in \mathcal{U}$, we compute a feature representation using a deterministic feature extraction function:
$$\phi: \mathcal{U} \rightarrow \mathbb{R}^d$$
where $\phi(X) = [x_1, x_2, \dots, x_d]^T$ represents $d$ measurable structural, lexical, length, and information-theoretic features.

### 4.2 Probabilistic Output
The machine learning model $f_\theta: \mathbb{R}^d \rightarrow [0, 1]$ parameterizes the conditional posterior probability that URL $X$ is phishing ($Y = 1$):
$$f_\theta(\phi(X)) = \hat{P}(Y = 1 \mid X)$$

Where:
- $Y = 0$: Legitimate / Benign URL
- $Y = 1$: Phishing / Malicious URL

### 4.3 Classification vs. Risk Scoring
Rather than a naive hard-threshold binary decision ($Y \in \{0, 1\}$ at $\tau = 0.5$), the system outputs a continuous risk score calibrated against security trade-offs:

$$\hat{y} = \begin{cases}
1 & \text{if } f_\theta(\phi(X)) \ge \tau \\
0 & \text{if } f_\theta(\phi(X)) < \tau
\end{cases}$$

---

## 5. Risk Assessment vs. Absolute Proof

### 5.1 The Probabilistic Reality
A statistical classifier estimates probability based on correlations in observed data; **it does not constitute forensic cryptographic proof**.

| Outcome | Reality | Description | Operational Cost |
| :--- | :--- | :--- | :--- |
| **True Positive (TP)** | Actual Phishing | Successfully identified phishing link | Threat mitigated |
| **True Negative (TN)** | Actual Legitimate | Correctly allowed benign URL | Normal operations preserved |
| **False Positive (FP)** | Legitimate flagged as Phishing | Safe internal / marketing / SSO URL blocked | User friction, alert fatigue, broken business flows |
| **False Negative (FN)** | Phishing missed by Model | Attacker evades detection, user visits site | Credential theft, data breach, compromised endpoint |

### 5.2 Asymmetric Costs in Cybersecurity
In security applications, **False Negatives are typically far more dangerous than False Positives**, but excessive False Positives cause alert fatigue and user bypass behavior.
Therefore:
1. **Decision Thresholds Must Be Optimized Based on Risk Tolerance**: We do not use arbitrary 0.5 cutoffs.
2. **Three-Tier Risk Architecture**:
   - **LOW RISK ($P < \tau_{\text{low}}$)**: Standard benign browsing patterns. Minimal threat indicators.
   - **MEDIUM / SUSPICIOUS RISK ($\tau_{\text{low}} \le P < \tau_{\text{high}}$)**: Anomaly detected (e.g., newly observed domain structure, atypical length, mixed character sets). Triggers user warnings, step-up verification, or sandbox inspection.
   - **HIGH RISK ($P \ge \tau_{\text{high}}$)**: Strong statistical alignment with active phishing campaigns. Recommended proactive blocking and credential-entry protection.

---

## 6. Interview-Ready Summary & Technical Defense

1. **Why formulate phishing detection as classification?**
   - URLs present distinct structural and lexical patterns (length, entropy, token presence, subdomain depth). Classification assigns a calibrated probability $P(\text{phishing} \mid X)$ facilitating actionable risk decisions.
2. **Why can a URL look authentic while remaining malicious?**
   - Abuse of free automated SSL certificates, subdomains masking attacker domains, and hosting phishing assets on legitimate multi-tenant cloud platforms (Cloudflare Pages, Firebase, AWS S3).
3. **Why is a prediction a risk score and not absolute proof?**
   - URLs change constantly, zero-day campaigns craft evasive structures, and statistical models map feature correlations rather than verifying server intent. Treating predictions as risk assessments enables defense-in-depth and calibrated security responses.

---

*Phase 0 status: Completed.*
