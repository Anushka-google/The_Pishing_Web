# Phase 23: Production Model Versioning, Staging & Rollback Registry

## 🎯 Architectural Purpose & Security Context

In production security platforms, machine learning models cannot remain static, nor can changes be pushed without complete auditability. If an adversarial evasion technique emerges, or conversely, if a newly deployed gradient-boosted tree experiences catastrophic forgetting or latency spikes on zero-day traffic, the operations team requires:
1. **Deterministic Prediction Lineage**: Every single inspection record stored in PostgreSQL/SQLite must explicitly persist its `model_version`.
2. **Side-by-Side Model Versions**: Coexistence of multiple model architectures with different feature representations.
3. **Zero-Downtime Hot-Swapping & Dynamic Rollback**: Ability to promote new candidate versions (`v2`, `v3`) and instantaneously rollback (`v3 -> v2 -> v1`) without restarting services.

---

## 🏛️ Model Version Hierarchy

| Version | Model Name | Architecture | Feature Count | Signals Included | Production Role |
| :---: | :--- | :--- | :---: | :--- | :--- |
| **`v1`** | **Random Forest** | `RandomForestClassifier` (100 estimators, max depth 12) | **22** | Length, Character, Structural, Lexical, Shannon Entropy | **Proven Baseline Champion**: Zero false positives on holdouts, robust bagger against extreme outliers. |
| **`v2`** | **XGBoost** | `XGBClassifier` (300 estimators, max depth 6, lr 0.05) | **22** | Identical 22 Base RFC & entropy signals | **Tuned Boosting Champion**: Ultra-low inference latency (`~0.005 ms/URL`), calibrated logloss. |
| **`v3`** | **XGBoost (Improved Features)** | `XGBClassifier` (300 estimators, max depth 6, lr 0.05) | **28** | 22 Base + `digit_ratio`, `path_entropy`, `has_at_symbol`, `suspicious_tld`, `hyphen_ratio`, `is_https_with_ip` | **Extended Security Representation**: Detects second-order ratio anomalies, obfuscated credential auth, and abusive TLDs. |

---

## 🧩 Extended Signal Representation in Version 3

For version `v3`, the platform introduces 6 additional security signals:
1. **`digit_ratio`**: `number_of_digits / url_length` — Captures high-density randomized hexadecimal and numeric token parameters.
2. **`path_entropy`**: Shannon entropy calculated specifically on the URL path — Isolates obfuscated resource paths from benign brand domains.
3. **`has_at_symbol`**: Detection of `@` character in authority/path — Neutralizes RFC 3986 user-info deception (`http://google.com@phishing.site`).
4. **`suspicious_tld`**: High-abuse TLD classification (`.xyz`, `.top`, `.work`, `.buzz`, `.club`, `.cc`, `.icu`, `.cam`, `.tk`, `.ml`, `.ga`, etc.).
5. **`hyphen_ratio`**: `number_of_hyphens / domain_length` — Identifies brand-masquerading combosquatting strings (`paypal-security-update-login`).
6. **`is_https_with_ip`**: Boolean conjunction of HTTPS encryption paired with an IPv4/IPv6 literal — A common adversary evasion indicator.

---

## 🔄 Hot-Swapping & Dynamic Rollback API

The platform exposes RESTful endpoints for model lifecycle governance:

### 1. Query Registered Model Versions
```http
GET /model/versions
```
**Response (200 OK):**
```json
{
  "active_version": "v1",
  "previous_version": "v1",
  "versions": [
    {
      "version": "v1",
      "model_name": "Random Forest",
      "architecture": "RandomForestClassifier",
      "feature_count": 22,
      "description": "Baseline Bagging Ensemble (100 trees, max depth 12)...",
      "is_active": true,
      "metrics": { "f1_score": 0.9990, "accuracy": 0.9989, "latency_ms_per_url": 0.0445 }
    },
    {
      "version": "v2",
      "model_name": "XGBoost",
      "architecture": "XGBClassifier",
      "feature_count": 22,
      "description": "Tuned Gradient Boosting Champion (300 estimators, max depth 6, lr 0.05)...",
      "is_active": false,
      "metrics": { "f1_score": 0.9980, "accuracy": 0.9978, "latency_ms_per_url": 0.0051 }
    },
    {
      "version": "v3",
      "model_name": "XGBoost (Improved Features)",
      "architecture": "XGBClassifier",
      "feature_count": 28,
      "description": "Advanced Gradient Boosting Champion leveraging 28 features...",
      "is_active": false,
      "metrics": { "f1_score": 0.9990, "accuracy": 0.9989, "latency_ms_per_url": 0.0056 }
    }
  ]
}
```

### 2. Live Version Hot-Swap
```http
POST /model/switch
Content-Type: application/json

{
  "version": "v3"
}
```
**Response (200 OK):**
```json
{
  "status": "success",
  "active_version": "v3",
  "model_name": "XGBoost (Improved Features)",
  "feature_count": 28,
  "message": "Production model successfully hot-swapped to v3 (XGBoost (Improved Features))."
}
```

### 3. Immediate Sequential Rollback
```http
POST /model/rollback
```
**Response (200 OK):**
```json
{
  "status": "success",
  "active_version": "v2",
  "model_name": "XGBoost",
  "feature_count": 22,
  "message": "Production model successfully rolled back to v2 (XGBoost)."
}
```

---

## 🗄️ Relational Audit Trail (Database Schema)

Every prediction persisted to the PostgreSQL / SQLite database stores the model version:

```sql
SELECT id, url, prediction, probability, risk_level, model_version, created_at 
FROM prediction 
ORDER BY created_at DESC 
LIMIT 5;
```

| id | url | prediction | probability | risk_level | model_version | created_at |
| :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| `104` | `https://paypal.com.verify-access.xyz/token` | `phishing` | `0.9994` | `HIGH` | **`v3`** | `2026-10-03 11:26:00` |
| `103` | `https://chase.com` | `legitimate` | `0.0012` | `LOW` | **`v2`** | `2026-10-03 11:25:30` |
| `102` | `https://accounts.google.com/signin` | `legitimate` | `0.0000` | `LOW` | **`v1`** | `2026-10-03 11:24:15` |

---

## 🧪 Verification & Test Harness

A complete test suite in [`tests/test_model_versioning.py`](file:///c:/Users/anush/OneDrive/Desktop/Startup/Phishing_web/tests/test_model_versioning.py) verifies:
- `test_version_manifest_integrity`: Validates manifest metadata across `v1`, `v2`, and `v3`.
- `test_version_artifacts_exist_and_loadable`: Validates `.joblib` serialization and feature counts.
- `test_production_predictor_version_binding`: Tests prediction tagging with exact model versions.
- `test_live_hot_swapping_and_rollback`: Tests programmatic switching and multi-step rollback.
- `test_database_persistence_with_model_version`: Verifies database commits and history retrieval.
- `test_api_model_version_endpoints`: Tests `/model/versions`, `/model/switch`, `/model/rollback`, and error handling for invalid version requests.

**Result**: 82 passed tests across all 21 test suites in `35.67s`.
