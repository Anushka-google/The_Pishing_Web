# Research Approaches: Empirical Benchmark Comparison

Comparison of Blacklist, Heuristic, Pure ML, and Hybrid paradigms evaluated against 9,450 URLs with a 50% simulated zero-day holdout.

| Detection Paradigm | Accuracy | Precision | Recall (All) | Zero-Day Recall | FPR | FNR | Avg Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Blacklist-based Detection** | 73.6% | 100.0% | 50.0% | **0.0%** | 0.00% | 50.0% | 0.001 ms |
| **2. Heuristic-based Detection** | 57.9% | 100.0% | 20.2% | **20.8%** | 0.00% | 79.8% | 0.005 ms |
| **3. ML-based Detection (Static URL)** | 86.7% | 100.0% | 74.8% | **74.8%** | 0.00% | 25.2% | 0.063 ms |
| **4. Hybrid Detection (Engine Consensus)** | 95.6% | 100.0% | 91.7% | **83.4%** | 0.00% | 8.3% | 0.067 ms |

## Key Engineering Insights:
1. **Blacklists have 0% False Positives, but 0% Zero-Day Recall:** Completely blind to brand new campaigns.
2. **Heuristics are fast, but brittle:** High false negatives on obfuscated or clean-looking phishing.
3. **Machine Learning generalizes:** Achieves strong recall on zero-day phishing through structural and lexical feature learning.
4. **Hybrid is optimal:** Combines instant blacklist verdicts, heuristic safety rules, and ML probabilistic scoring for highest overall resilience.
