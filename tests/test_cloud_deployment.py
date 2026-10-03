"""
Phishing Detection & Risk Intelligence Platform
Phase 26: Test Suite for AWS Cloud Deployment & Container Orchestration

Verifies:
1. Production Docker Compose specification (public Nginx entry, internal isolation).
2. Backend and Frontend multi-stage Dockerfiles.
3. Nginx reverse proxy endpoint mappings (/predict, /health, /stats, /performance, etc.).
4. AWS CloudFormation template syntax and resource definitions (VPC, SG, EC2, Elastic IP).
5. AWS EC2 user data cloud-init script integrity.
6. Deployment pre-flight checklist verification.
7. GitHub Actions CI/CD deployment workflow.
"""

import os
import yaml
import pytest
from scripts.deploy_aws import check_prerequisites


def test_preflight_deployment_checklist():
    """Verifies that all required cloud deployment artifacts exist."""
    assert check_prerequisites() is True


def test_docker_compose_prod_configuration():
    """Verifies the production Docker Compose architecture conforms to cloud requirements."""
    compose_path = "docker-compose.prod.yml"
    assert os.path.exists(compose_path)

    with open(compose_path, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    assert "services" in compose
    services = compose["services"]

    # 1. Three core services present
    assert "postgres" in services
    assert "backend" in services
    assert "frontend" in services

    # 2. Security isolation: only frontend exposes public ports (80/443)
    frontend_ports = services["frontend"].get("ports", [])
    assert "80:80" in frontend_ports

    # Backend and PostgreSQL must NOT expose public host ports in production
    assert "ports" not in services["backend"] or not services["backend"]["ports"]
    assert "ports" not in services["postgres"] or not services["postgres"]["ports"]

    # 3. Healthcheck dependency chain
    assert services["backend"]["depends_on"]["postgres"]["condition"] == "service_healthy"
    assert services["frontend"]["depends_on"]["backend"]["condition"] == "service_healthy"

    # 4. Shared network
    assert "phishintel-cloud-network" in compose["networks"]


def test_dockerfiles_integrity():
    """Verifies backend and frontend Dockerfiles have required stages and directives."""
    # Backend Dockerfile
    with open("Dockerfile", "r", encoding="utf-8") as f:
        backend_df = f.read()
    assert "FROM python:3.11-slim" in backend_df
    assert "EXPOSE 8000" in backend_df
    assert "uvicorn" in backend_df
    assert "HEALTHCHECK" in backend_df

    # Frontend Multi-Stage Dockerfile
    with open("frontend/Dockerfile", "r", encoding="utf-8") as f:
        frontend_df = f.read()
    assert "FROM node:20-alpine AS builder" in frontend_df
    assert "FROM nginx:alpine" in frontend_df
    assert "EXPOSE 80" in frontend_df


def test_frontend_nginx_reverse_proxy_routes():
    """Verifies Nginx routes traffic to backend for all required API routes."""
    nginx_path = "frontend/nginx.conf"
    assert os.path.exists(nginx_path)

    with open(nginx_path, "r", encoding="utf-8") as f:
        content = f.read()

    required_routes = [
        "location / {",
        "location /predict",
        "location /health",
        "location /history",
        "location /stats",
        "location /performance",
        "location /model/",
        "location /api/"
    ]

    for route in required_routes:
        assert route in content, f"Missing route mapping in Nginx: {route}"


def test_aws_cloudformation_template():
    """Verifies the AWS CloudFormation template contains valid resources and outputs."""
    cf_path = "deploy/aws/cloudformation.yml"
    assert os.path.exists(cf_path)

    with open(cf_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify key AWS resource declarations
    assert "Type: AWS::EC2::VPC" in content
    assert "Type: AWS::EC2::InternetGateway" in content
    assert "Type: AWS::EC2::Subnet" in content
    assert "Type: AWS::EC2::SecurityGroup" in content
    assert "Type: AWS::EC2::Instance" in content
    assert "Type: AWS::EC2::EIP" in content

    # Verify outputs
    assert "PublicIP:" in content
    assert "ApplicationURL:" in content
    assert "APIHealthCheck:" in content


def test_ec2_user_data_script():
    """Verifies the cloud-init bootstrap script contains automated setup steps."""
    ud_path = "deploy/aws/user_data.sh"
    assert os.path.exists(ud_path)

    with open(ud_path, "r", encoding="utf-8") as f:
        script = f.read()

    assert "docker" in script
    assert "docker-compose" in script or "docker compose" in script
    assert "git clone" in script
    assert "docker-compose.prod.yml" in script
    assert "phishintel.service" in script


def test_github_actions_workflow_syntax():
    """Verifies the GitHub Actions CI/CD deployment workflow."""
    wf_path = ".github/workflows/deploy.yml"
    assert os.path.exists(wf_path)

    with open(wf_path, "r", encoding="utf-8") as f:
        wf = yaml.safe_load(f)

    assert "jobs" in wf
    assert "test" in wf["jobs"]
    assert "build-and-verify-containers" in wf["jobs"]
    assert "deploy-to-aws" in wf["jobs"]
