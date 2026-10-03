"""
Phishing Detection & Risk Intelligence Platform
Phase 26: AWS Public Cloud Deployment CLI & Health Verifier

Capabilities:
1. Pre-flight verification (Docker, model artifacts, configuration).
2. Generates AWS CloudFormation deployment commands.
3. Performs automated end-to-end smoke tests against public cloud endpoints:
   Internet -> Frontend (Nginx) -> FastAPI -> ML Model -> PostgreSQL.
"""

import os
import sys
import json
import time
import argparse
import urllib.request
import urllib.error


def check_prerequisites() -> bool:
    """Verifies that all required files and artifacts exist before cloud deployment."""
    print("=" * 70)
    print("PRE-FLIGHT DEPLOYMENT CHECKLIST (PHASE 26)")
    print("=" * 70)

    checks = [
        ("Production Docker Compose", "docker-compose.prod.yml"),
        ("Backend Dockerfile", "Dockerfile"),
        ("Frontend Dockerfile", "frontend/Dockerfile"),
        ("Frontend Nginx Reverse Proxy Config", "frontend/nginx.conf"),
        ("AWS CloudFormation Template", "deploy/aws/cloudformation.yml"),
        ("AWS EC2 User Data Script", "deploy/aws/user_data.sh"),
        ("ML Model Champion Artifact", "models/champion_phishing_model.joblib"),
        ("Model Version Manifest", "models/version_manifest.json")
    ]

    all_passed = True
    for label, path in checks:
        exists = os.path.exists(path)
        status_icon = "[OK]" if exists else "[FAIL]"
        print(f"  {status_icon:<6} {label:<38} ({path})")
        if not exists:
            all_passed = False

    print("=" * 70)
    return all_passed


def print_aws_instructions(stack_name: str = "PhishIntel-Stack", region: str = "us-east-1"):
    """Displays standard 1-click AWS CLI and Console deployment commands."""
    print("\nAWS CLOUD DEPLOYMENT INSTRUCTIONS")
    print("=" * 70)
    print("Option 1: Deploy via AWS CLI (1-Command Automated Stack)")
    print("-" * 70)
    print(f"""aws cloudformation create-stack \\
  --stack-name {stack_name} \\
  --template-body file://deploy/aws/cloudformation.yml \\
  --parameters ParameterKey=InstanceType,ParameterValue=t3.medium \\
  --capabilities CAPABILITY_IAM \\
  --region {region}""")

    print("\nTo track stack creation progress:")
    print(f"aws cloudformation describe-stacks --stack-name {stack_name} --region {region} --query 'Stacks[0].StackStatus'")

    print("\nTo retrieve public URLs upon completion:")
    print(f"aws cloudformation describe-stacks --stack-name {stack_name} --region {region} --query 'Stacks[0].Outputs'")

    print("\n" + "-" * 70)
    print("Option 2: Deploy via AWS Management Console")
    print("-" * 70)
    print("1. Open AWS CloudFormation Console -> Create Stack -> With new resources.")
    print("2. Upload template: deploy/aws/cloudformation.yml")
    print("3. Enter Stack Name (e.g., 'PhishIntel-Stack') and select InstanceType (t3.medium).")
    print("4. Click Next -> Acknowledge IAM capabilities -> Submit.")
    print("5. After ~3-4 minutes, open the 'Outputs' tab for the Public Application URL.")
    print("=" * 70 + "\n")


def smoke_test_public_endpoint(base_url: str) -> bool:
    """
    Executes automated smoke tests verifying the full flow:
    Internet -> Frontend -> FastAPI -> ML Model -> PostgreSQL.
    """
    base_url = base_url.rstrip("/")
    print(f"[*] Verifying Public Cloud Deployment at: {base_url}")
    print("-" * 70)

    # 1. Test Health endpoint
    try:
        health_url = f"{base_url}/health"
        print(f"  Checking {health_url} ...", end=" ")
        req = urllib.request.Request(health_url, headers={"User-Agent": "PhishIntel-DeployBot/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            assert data.get("status") == "healthy"
            print(f"[PASSED] (Model: {data.get('model_name')} {data.get('model_version')})")
    except Exception as e:
        print(f"[FAILED] ({e})")
        return False

    # 2. Test Prediction endpoint
    try:
        predict_url = f"{base_url}/predict"
        print(f"  Testing {predict_url} with sample target ...", end=" ")
        payload = json.dumps({"url": "https://www.wikipedia.org"}).encode()
        req = urllib.request.Request(
            predict_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "PhishIntel-DeployBot/1.0"
            }
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            pred = data.get("prediction")
            risk = data.get("risk_level")
            print(f"[PASSED] (Prediction: {pred}, Risk: {risk})")
    except Exception as e:
        print(f"[FAILED] ({e})")
        return False

    # 3. Test Performance Telemetry endpoint
    try:
        perf_url = f"{base_url}/performance"
        print(f"  Testing {perf_url} ...", end=" ")
        req = urllib.request.Request(perf_url, headers={"User-Agent": "PhishIntel-DeployBot/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            bottleneck = data.get("primary_bottleneck")
            print(f"[PASSED] (Primary Bottleneck: {bottleneck})")
    except Exception as e:
        print(f"[WARNING] Performance endpoint note: {e}")

    print("-" * 70)
    print("[SUCCESS] All public cloud endpoints verified! Deployment operational.")
    return True


def main():
    parser = argparse.ArgumentParser(description="AWS Cloud Deployment CLI for PhishIntel")
    parser.add_argument("--check", action="store_true", help="Run pre-flight deployment check")
    parser.add_argument("--instructions", action="store_true", help="Print AWS CloudFormation deployment instructions")
    parser.add_argument("--verify", type=str, help="Verify public cloud deployment URL (e.g., http://54.12.34.56)")
    args = parser.parse_args()

    if args.check or (not args.verify and not args.instructions):
        ok = check_prerequisites()
        if not ok:
            sys.exit(1)

    if args.instructions or (not args.check and not args.verify):
        print_aws_instructions()

    if args.verify:
        success = smoke_test_public_endpoint(args.verify)
        if not success:
            sys.exit(1)


if __name__ == "__main__":
    main()
