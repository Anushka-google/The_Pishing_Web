"""
Phishing Detection & Risk Intelligence Platform
Sample Dataset Generator for Reproducible Pipeline Testing and EDA
Generates balanced, diverse, security-grounded phishing and legitimate URL records.
"""

import os
import random
import csv
from datetime import datetime, timezone
from src.preprocessing.dataset_builder import URLDatasetPipeline


def generate_curated_dataset(total_samples: int = 10000, random_seed: int = 42):
    random.seed(random_seed)
    half = total_samples // 2

    # --- Legitimate URL Components ---
    legit_domains = [
        "google.com", "microsoft.com", "github.com", "amazon.com", "wikipedia.org",
        "apple.com", "cloudflare.com", "stackoverflow.com", "python.org", "mozilla.org",
        "nytimes.com", "bbc.co.uk", "mit.edu", "harvard.edu", "nih.gov", "cnn.com",
        "medium.com", "linkedin.com", "salesforce.com", "oracle.com", "adobe.com",
        "dropbox.com", "spotify.com", "netflix.com", "zoom.us", "slack.com",
        "stripe.com", "digitalocean.com", "gitlab.com", "docker.com", "reddit.com",
        "quora.com", "theguardian.com", "reuters.com", "wsj.com", "nature.com"
    ]
    legit_subdomains = ["", "", "", "www", "docs", "api", "support", "developer", "blog", "app"]
    legit_paths = [
        "", "/", "/about", "/explore", "/search", "/articles/2026/technology",
        "/projects/open-source", "/documentation/getting-started", "/blog/post-102",
        "/legal/privacy-policy", "/terms-of-service", "/help/faq", "/pricing",
        "/download/release-v2.0", "/features/security-whitepaper", "/press/announcements"
    ]
    legit_queries = [
        "", "", "", "?q=machine+learning", "?lang=en", "?page=2&sort=recent",
        "?category=engineering", "?view=grid&filter=active", "?id=108274"
    ]

    legitimate_urls = []
    for i in range(half):
        domain = random.choice(legit_domains)
        sub = random.choice(legit_subdomains)
        netloc = f"{sub}.{domain}" if sub else domain
        path = random.choice(legit_paths)
        query = random.choice(legit_queries)
        scheme = "https" if random.random() > 0.05 else "http"
        url = f"{scheme}://{netloc}{path}{query}"
        legitimate_urls.append({
            "url": url,
            "label": 0,
            "source": "Tranco-TopDomains",
            "collection_date": "2026-09-30"
        })

    # --- Phishing URL Components ---
    targeted_brands = ["paypal", "microsoft-security", "appleid-support", "chase-bank", "netflix-billing",
                       "wellsfargo-verify", "amazon-customer-alert", "dhl-tracking-express", "coinbase-auth", "binance-kyc"]
    phish_tlds = [".xyz", ".top", ".club", ".online", ".live", ".ru", ".cc", ".site", ".link", ".info", ".tk"]
    phish_subdomains = [
        "login", "verify-account", "security-alert", "signin.ebay", "account-update",
        "secure.banking", "auth.v2.protection", "portal.idp.recovery", "confirm.identity"
    ]
    phish_paths = [
        "/login.php", "/account/verification", "/security/update.html", "/auth/step2",
        "/webscr?cmd=_login-run", "/session/verify-credentials", "/portal/restore-access",
        "/cgi-bin/secure-auth", "/checkpoint/challenge", "/secure-form/v3"
    ]
    phish_queries = [
        "?token=a9f8e7d6c5b4&session=expired", "?dest=banking_portal",
        "?user_id=89234&retry=1", "?error=reauth_required&redirect=confirm",
        "?client_id=sec_9817294&state=token_revoked"
    ]

    phishing_urls = []
    for i in range(half):
        phish_type = random.random()

        if phish_type < 0.20:
            # IP Address based host
            ip = f"{random.randint(45, 210)}.{random.randint(10, 200)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
            port = f":{random.choice([8080, 8443, 8000, 3000])}" if random.random() > 0.5 else ""
            path = random.choice(phish_paths)
            query = random.choice(phish_queries)
            url = f"http://{ip}{port}{path}{query}"
        elif phish_type < 0.55:
            # Typosquatting / Combosquatting domain
            brand = random.choice(targeted_brands)
            tld = random.choice(phish_tlds)
            domain = f"{brand}-verification{tld}" if random.random() > 0.5 else f"{brand}{tld}"
            sub = random.choice(phish_subdomains)
            path = random.choice(phish_paths)
            query = random.choice(phish_queries)
            scheme = "https" if random.random() > 0.25 else "http"
            url = f"{scheme}://{sub}.{domain}{path}{query}"
        elif phish_type < 0.85:
            # Deep subdomain abuse mimicking legit brand on cheap domain
            brand = random.choice(["login.microsoft.com", "accounts.google.com", "auth.chase.com", "idmsa.apple.com"])
            attacker_domain = f"server-{random.randint(100, 999)}{random.choice(phish_tlds)}"
            path = random.choice(phish_paths)
            query = random.choice(phish_queries)
            scheme = "https" if random.random() > 0.20 else "http"
            url = f"{scheme}://{brand}.{attacker_domain}{path}{query}"
        else:
            # High-entropy tokenized URL
            rand_token = "".join(random.choices("abcdef0123456789", k=24))
            domain = f"gate-{random.randint(1, 99)}{random.choice(phish_tlds)}"
            url = f"http://{domain}/session/{rand_token}/verify?user=victim"

        phishing_urls.append({
            "url": url,
            "label": 1,
            "source": "PhishTank/URLhaus",
            "collection_date": "2026-09-30"
        })

    # Add duplicate and near-duplicate candidates to test deduplication
    phishing_urls.append(phishing_urls[0].copy())
    legitimate_urls.append(legitimate_urls[0].copy())
    legitimate_urls.append({"url": "invalid:::url^^format", "label": 0, "source": "test", "collection_date": "2026-09-30"})

    # Save raw files
    raw_phish_file = "data/raw/phishing/phishing_urls.csv"
    raw_legit_file = "data/raw/legitimate/legitimate_urls.csv"

    def write_csv(filepath, rows):
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "label", "source", "collection_date"])
            writer.writeheader()
            writer.writerows(rows)

    write_csv(raw_phish_file, phishing_urls)
    write_csv(raw_legit_file, legitimate_urls)

    pipeline = URLDatasetPipeline()
    clean_records, metrics = pipeline.process_records(phishing_urls, legitimate_urls)
    processed_path = pipeline.save_processed(clean_records)

    return processed_path, metrics


if __name__ == "__main__":
    path, metrics = generate_curated_dataset(total_samples=10000)
    print("Dataset generation completed:")
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    print(f"Saved to: {path}")
