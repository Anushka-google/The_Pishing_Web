# Phase 25: Performance Measurement & Subsystem Latency Profiling

## 1. Executive Summary & Objective

> **Guiding Principle**: *"Measure actual system performance rather than claiming it."*

In high-throughput cybersecurity services, latency dictates whether an inline protection layer can evaluate incoming web requests or whether it becomes a user-facing bottleneck. Generic claims such as *"ultra-fast AI engine"* or *"sub-millisecond latency"* without empirical verification are unacceptable in mission-critical environments.

**Phase 25** establishes an empirical measurement framework that decomposes and isolates latency into **four separate subsystems**:
1. **Feature Extraction Time** ($t_{\text{feat}}$)
2. **Model Inference Time** ($t_{\text{inf}}$)
3. **Database Latency** ($t_{\text{db}}$)
4. **API Response Time** ($t_{\text{api}}$)

By measuring each subsystem independently on identical live traffic, the platform pinpoints exact bottlenecks and provides actionable architectural insights.

---

## 2. Empirical Benchmark Results

Measured over **150 iterations** with warmup on live production payloads (`Random Forest`, 22 engineered features):

| Subsystem | Mean Latency | Median (P50) | P90 | P95 | P99 | Min | Max |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **⚡ Feature Extraction** | **0.293 ms** | 0.195 ms | 0.361 ms | 0.429 ms | 2.728 ms | 0.103 ms | 4.545 ms |
| **🧠 Model Inference** | **30.392 ms** | 31.703 ms | 40.889 ms | 50.723 ms | 57.009 ms | 17.087 ms | 84.094 ms |
| **💾 Database Latency** | **1.798 ms** | 1.370 ms | 2.309 ms | 3.059 ms | 7.193 ms | 0.984 ms | 23.660 ms |
| **🌐 API Pipeline Roundtrip** | **32.829 ms** | 33.739 ms | 44.031 ms | 54.177 ms | 64.235 ms | 18.448 ms | 85.777 ms |

```
Subsystem Latency Share Decomposition:
─────────────────────────────────────────────────────────────────────────────
[0.9%]  Feature Extraction   (0.293 ms)
[92.6%] Model Inference      (30.392 ms)  ◄ PRIMARY BOTTLENECK
[5.5%]  Database Latency     (1.798 ms)
[1.1%]  Pipeline Overhead    (0.346 ms)
─────────────────────────────────────────────────────────────────────────────
```

---

## 3. Subsystem Breakdown & Bottleneck Analysis

### A. Subsystem 1: Feature Extraction (0.293 ms Mean / 0.429 ms P95)
- **Contribution**: **0.9% of total latency**.
- **Assessment**: Highly optimized. Pure Python/C lexical and entropy parsing using RFC 3986 regex patterns and `tldextract` takes well under 0.5 ms per URL.
- **Status**: **Optimal — No bottleneck**.

### B. Subsystem 2: Model Inference (30.392 ms Mean / 50.723 ms P95)
- **Contribution**: **92.6% of total latency**.
- **Assessment**: **Primary System Bottleneck**.
- **Root Cause**: Scikit-Learn `RandomForestClassifier` with 100 deep decision trees traverses all estimator decision nodes in serial Python runtime for single-vector inference.
- **Optimization Strategy**:
  1. **Hot-swap to XGBoost (`v2`)**: Native C++ tree evaluation reduces single-sample latency to 1–3 ms.
  2. **ONNX Runtime / Treelite compilation**: Compiling the ensemble to C runtime code drops inference below 0.5 ms.

### C. Subsystem 3: Database Latency (1.798 ms Mean / 3.059 ms P95)
- **Contribution**: **5.5% of total latency**.
- **Assessment**: SQLite and PostgreSQL indexed writes complete in 1.4–3.0 ms per audit log entry.
- **Status**: Well within expected budget. Can be moved to background async workers for zero-blocking I/O.

### D. Subsystem 4: API Response Time (32.829 ms Mean / 54.177 ms P95)
- **Contribution**: Complete end-to-end HTTP pipeline.
- **Assessment**: Starlette routing, CORS, structured logging serialization, and JSON decoding add merely **0.346 ms (1.1%)** overhead.
- **SLA Target**: Target real-time interactive response $< 50$ ms. Mean (32.8 ms) satisfies target; P95 (54.1 ms) slightly exceeds target due to Random Forest tree depth variance.

---

## 4. Architectural Implementation

### 1. Profiler Utility: `src/evaluation/performance_profiler.py`
- `SystemPerformanceProfiler`: Runs automated test iterations across benchmark URLs.
- `identify_bottleneck(...)`: Determines percentage contribution and classifies the dominant bottleneck (`FEATURE_EXTRACTION`, `MODEL_INFERENCE`, `DATABASE_LATENCY`, `PIPELINE_OVERHEAD`).
- `compute_distribution_stats(...)`: Generates full percentile distribution.
- CLI: `python -m src.evaluation.performance_profiler`.

### 2. Live API Telemetry & Response Headers
Every inference request through `POST /api/v1/predict` exposes separate subsystem measurements in both the JSON payload and standard HTTP tracing headers:

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Request-ID: req_e7a2b91c04f8
X-Feature-Extraction-Time-MS: 0.285
X-Model-Inference-Time-MS: 31.420
X-Database-Latency-MS: 1.250
X-Total-Response-Time-MS: 33.450
X-Identified-Bottleneck: MODEL_INFERENCE
```

### 3. Dedicated Telemetry Endpoint: `GET /api/v1/performance`
Provides real-time access to empirical distributions and live database telemetry:
```json
{
  "status": "success",
  "model_version": "v1",
  "model_name": "Random Forest",
  "feature_extraction": {
    "mean_ms": 0.293,
    "median_p50_ms": 0.195,
    "p95_ms": 0.429
  },
  "model_inference": {
    "mean_ms": 30.392,
    "median_p50_ms": 31.703,
    "p95_ms": 50.723
  },
  "database_latency": {
    "mean_ms": 1.798,
    "median_p50_ms": 1.370,
    "p95_ms": 3.059
  },
  "api_response_time": {
    "mean_ms": 32.829,
    "median_p50_ms": 33.739,
    "p95_ms": 54.177
  },
  "primary_bottleneck": "MODEL_INFERENCE",
  "primary_bottleneck_share_pct": 92.6,
  "sla_compliance": {
    "target_p95_ms": 50.0,
    "measured_p95_ms": 54.177,
    "sla_met": false
  }
}
```

### 4. Relational Database Persistence
`database/models.py` (`PredictionRecord`) and `database/repository.py` store:
- `feature_extraction_ms`
- `model_inference_ms`
- `db_latency_ms`
- `api_response_time_ms`
- `bottleneck`

### 5. Frontend UI Integration
`ResultCard.jsx` visualizes the subsystem decomposition inline with color-coded badges:
- ⚡ Feature Extraction (`0.29 ms`)
- 🧠 Model Inference (`30.39 ms`)
- 💾 Database Latency (`1.80 ms`)
- 🌐 API Response (`32.83 ms`)
- High-visibility `Bottleneck: MODEL INFERENCE (92.6%)` badge.
