# Phase 6 & 7: Feature Engineering & Reusable Feature Extractor

## 1. Feature Representation & Security Signals

Machine learning models require numerical representation of raw URL strings. The feature extractor maps raw URL $X \in \mathcal{U}$ into a 22-dimensional feature vector $\phi(X) \in \mathbb{R}^{22}$.

```
Raw URL String
      │
      ▼
┌─────────────────────────────────┐
│   URLParser (RFC 3986 Parsing)  │
└─────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────┐
│ FeatureExtractor (22 Features)  │
├─────────────────────────────────┤
│ • Length Features (4)           │
│ • Character Frequencies (7)     │
│ • Structural Signals (6)        │
│ • Lexical Keyword Signals (2)   │
│ • Shannon Character Entropy (2) │
└─────────────────────────────────┘
      │
      ▼
Vector $\phi(X) \in \mathbb{R}^{22}$ (0 Training/Serving Skew)
```

---

## 2. Feature Schema & Definitions

### 2.1 Length Features
1. `url_length`: Total character count of normalized URL. Phishing URLs tend to be substantially longer due to token stuffing and tracking parameters.
2. `domain_length`: Length of hostname/domain. Attackers use long domains to mimic legitimate entities.
3. `path_length`: Length of URL path component.
4. `query_length`: Length of query string parameters.

### 2.2 Character Features
5. `number_of_digits`: Count of numeric characters `[0-9]`. Elevated by IP addresses, session tokens, and timestamps.
6. `number_of_dots`: Count of period characters `.`. Increased by deep subdomain structures.
7. `number_of_hyphens`: Count of hyphen characters `-`. Frequently present in typosquatting and combosquatting (`paypal-security-update`).
8. `number_of_slashes`: Count of `/` delimiters.
9. `number_of_question_marks`: Count of `?`.
10. `number_of_equals`: Count of `=` parameter assignments.
11. `number_of_special_characters`: Non-alphanumeric, non-URL-standard symbols.

### 2.3 Structural Features
12. `number_of_subdomains`: Depth of subdomain prefixes (`auth.portal.login`).
13. `has_ip_address`: Binary indicator (`1` if host is raw IPv4 or IPv6, `0` otherwise).
14. `has_port`: Binary indicator (`1` if explicit non-standard port like `8080` or `8443` is specified).
15. `has_fragment`: Binary indicator (`1` if `#` fragment exists).
16. `has_query`: Binary indicator (`1` if query parameters exist).
17. `uses_https`: Binary indicator (`1` if scheme is `https`, `0` if `http`).
18. `is_punycode`: Binary indicator (`1` if `xn--` IDN homograph representation is present).

### 2.4 Lexical Features
19. `suspicious_keyword_count`: Cumulative count of high-risk security tokens (`login`, `verify`, `account`, `security`, `update`, `password`, `bank`, `payment`, `confirm`, `wallet`, `signin`, `auth`, `recover`, `billing`, `service`).
20. `brand_in_subdomain`: Binary indicator (`1` if target brand like `paypal` or `microsoft` appears inside subdomain prefix rather than registered root domain).

### 2.5 Information-Theoretic Entropy
21. `url_entropy`: Shannon character entropy of the entire URL.
22. `domain_entropy`: Shannon character entropy of the hostname.

$$\mathcal{H}(X) = -\sum_{i=1}^{k} P(x_i) \log_2 P(x_i)$$

*Security Rationale:* High entropy indicates algorithmic generation (DGA) or cryptographic token obfuscation. Low entropy indicates predictable dictionary keywords.

---

## 3. Prevention of Training/Serving Skew

A major point highlighted in the project roadmap:
> *The feature extractor used during training must be the same logic used during production inference. This prevents training/serving skew.*

In this implementation:
- Offline training scripts import `FeatureExtractor.extract_features_dict()` directly.
- The online FastAPI REST API endpoint imports the exact same `FeatureExtractor.extract_features_vector()` function.
- No transformations or feature definitions are duplicated across training scripts and API routes.
