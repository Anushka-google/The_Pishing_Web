# Dataset Engineering & Acquisition Handbook

This directory houses the raw and processed data assets for the **Phishing Detection & Risk Intelligence Platform**. The data pipeline adheres to strict reproducibility, integrity, and provenance standards.

---

## 📁 Directory Architecture

```
data/
├── raw/
│   ├── phishing/
│   │   ├── phishtank_raw.csv    # Raw community-verified phishing feeds
│   │   └── urlhaus_raw.csv      # Raw malware/phishing payloads from URLhaus
│   └── legitimate/
│       └── tranco_raw.csv       # Raw ranked top domain benign proxies
├── processed/
│   ├── urls.csv                 # Clean, deduplicated, labelled training dataset
│   ├── eda_report.json          # Statistical EDA profiling output
│   └── approaches_benchmark.json# Detection paradigm performance metrics
└── README.md                    # Data engineering handbook (this file)
```

---

## 🌐 Recommended Data Sources & Purposes

| Source | Category | Purpose & Description | Official Resource |
| :--- | :---: | :--- | :--- |
| **PhishTank** | Phishing | Community-submitted, human-verified active phishing URLs. | [phishtank.org](https://phishtank.org/) |
| **URLhaus** | Malicious | Active malware and credential-harvesting payload distribution URLs run by abuse.ch. | [urlhaus.abuse.ch](https://urlhaus.abuse.ch/) |
| **Tranco List** | Benign Proxy | Research-oriented top 1M domain ranking that hardens against domain manipulation. | [tranco-list.eu](https://tranco-list.eu/) |
| **UCI ML Repository** | Benchmark | Academic benchmark datasets for phishing websites. | [archive.ics.uci.edu](https://archive.ics.uci.edu/) |

---

## ⚠️ Important Dataset Caveat: Benign Proxy Validity

> [!WARNING]
> **Popular-Domain Ranking is a Benign Proxy, Not Absolute Proof:**
> A high domain ranking on the Tranco list indicates substantial web traffic, **not** guaranteed immunity from abuse. 
> 
> Modern phishing campaigns routinely abuse multi-tenant cloud hosting and serverless providers (e.g., `*.web.app`, `*.firebaseapp.com`, `*.pages.dev`, `*.s3.amazonaws.com`, `*.github.io`). Therefore, our pipeline implements **multi-tenant exclusions** to avoid falsely labeling cloud-hosted phishing pages as benign.

---

## 🔄 Ingestion & Cleaning Pipeline

The ingestion lifecycle executes deterministically across five stages:

```
[ Raw Sources: PhishTank, URLhaus, Tranco ]
                   │
                   ▼
       ┌────────────────────────┐
       │     1. Downloader      │ ──▶ Fetches and caches raw CSV feeds in data/raw/
       └────────────────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │       2. Parser        │ ──▶ RFC 3986 parsing & scheme/netloc normalization
       └────────────────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │       3. Cleaner       │ ──▶ Removes invalid formats, nulls, & extreme lengths
       └────────────────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │     4. Deduplicator    │ ──▶ Drops exact duplicate URLs across sources
       └────────────────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │       5. Labeler       │ ──▶ Assigns binary labels and metadata
       └────────────────────────┘
                   │
                   ▼
[ data/processed/urls.csv ]
```

---

## 📊 Processed Dataset Schema

| Column | Type | Allowed Values | Description |
| :--- | :---: | :---: | :--- |
| `url` | String | `http://` / `https://` | Full normalized Uniform Resource Locator |
| `label` | Integer | `0` or `1` | Ground-truth class: `0 = Legitimate`, `1 = Phishing` |
| `source` | String | `PhishTank`, `URLhaus`, `Tranco-TopDomains` | Data provider provenance |
| `collection_date` | String | `YYYY-MM-DD` | Date of feed ingestion |

---

## 📜 Terms of Use & Licensing

- **PhishTank:** Data is provided for security research and operational defence under PhishTank's Developer Terms.
- **URLhaus (abuse.ch):** Licensed under Creative Commons CC0 (Public Domain).
- **Tranco:** Academic research dataset provided under Creative Commons Attribution 4.0 International (CC BY 4.0).

---

## 🚀 How to Reproduce Ingestion

To re-run the entire download, cleaning, deduplication, and labeling pipeline:

```bash
python -m src.preprocessing.ingest_dataset
```
