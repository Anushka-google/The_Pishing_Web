# Phase 5: URL Parsing Component Specification

## 1. Architectural Motivation

A fundamental error in naive phishing classification projects is parsing URLs via manual string splitting:
```python
# ANTI-PATTERN: Brittle, security-vulnerable, breaks on ports, auth, & query parameters
parts = url.split('/')
domain = parts[2]
```

### Why String Splitting Fails in Security:
1. **RFC 3986 Authority Delimiters (`@`):**
   `http://trusted-bank.com@malicious-host.xyz/login`
   Naive string splitting treats `trusted-bank.com` as the hostname. In reality, modern network stacks treat `trusted-bank.com` as HTTP user credentials and route traffic to `malicious-host.xyz`.
2. **Multi-Part Public Suffixes:**
   Domains like `amazon.co.uk`, `bbc.co.uk`, or `tokyo.jp` cannot be determined by taking the last two segments (`.split('.')[-2:]`). The actual registered domain requires Public Suffix List (PSL) resolution via `tldextract`.
3. **Punycode / IDN Homographs:**
   Domains like `xn--pple-43d.com` require decoding and explicit flag attribution.
4. **Non-Standard Ports & Raw IP Identifiers:**
   IP hosts (`http://192.168.1.1:8080`) must be parsed into clean host and port numbers without breaking downstream feature extractors.

---

## 2. Component Design & Interface

The `URLParser` decomposes any input URL into a strictly validated `ParsedURL` data contract:

```
Input URL: https://login.example.com.auth-update.xyz:8443/account/verify?token=123#sec
                     │
                     ▼
             ┌───────────────┐
             │   URLParser   │
             └───────────────┘
                     │
                     ▼
{
  "scheme": "https",
  "netloc": "login.example.com.auth-update.xyz:8443",
  "hostname": "login.example.com.auth-update.xyz",
  "domain": "auth-update.xyz",
  "subdomain": "login.example.com",
  "suffix": "xyz",
  "port": 8443,
  "path": "/account/verify",
  "path_tokens": ["account", "verify"],
  "query": "token=123",
  "query_params": {"token": ["123"]},
  "fragment": "sec",
  "is_ip": false,
  "has_port": true,
  "has_auth": false,
  "is_punycode": false
}
```

---

## 3. Integration with Feature Extraction Pipeline

The `URLParser` acts as the deterministic front-line processor for:
- **Phase 6: Feature Engineering** (calculating lengths, symbol counts, token frequencies, and Shannon entropy directly from clean parsed components).
- **Phase 15: FastAPI Inference** (validating and parsing incoming API requests before scoring).
