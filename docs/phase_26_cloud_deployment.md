# Phase 26: Public Cloud Deployment (AWS-Oriented Architecture)

## 1. Architectural Philosophy & Overview

> **Roadmap Specification**:
> *"Deploy the application publicly. An AWS-oriented deployment can demonstrate cloud skills without turning the project into an infrastructure project.*  
> *Docker plus a practical cloud deployment is sufficient for the initial project. Kubernetes, Kafka, service meshes, and complex microservices are not required."*

```
                              PUBLIC INTERNET
                                     │
                                     ▼ (Port 80 HTTP / 443 HTTPS)
                   ┌───────────────────────────────────┐
                   │    Frontend & Reverse Proxy       │
                   │    (React Vite SPA + Nginx)       │
                   │    - Public Ingress               │
                   │    - Static Asset Caching         │
                   │    - Request Proxying             │
                   └─────────────────┬─────────────────┘
                                     │ (Isolated Docker Bridge Network)
                                     ▼
                   ┌───────────────────────────────────┐
                   │        FastAPI Application        │
                   │    - REST Endpoints (/predict)    │
                   │    - 22-Feature Extractor         │
                   │    - Calibrated ML Inferences     │
                   │    - Structured Logging (JSON)    │
                   └───────┬───────────────────┬───────┘
                           │                   │
                           ▼                   ▼
                 ┌──────────────────┐ ┌──────────────────┐
                 │  ML Model Bundle │ │  PostgreSQL 16   │
                 │  - Champion (v1) │ │  - Audit History │
                 │  - Candidate (v2)│ │  - Latency Stats │
                 │  - SHAP Explainer│ │  - Auto Migrated │
                 └──────────────────┘ └──────────────────┘
```

### Why Practical Cloud Deployment Over Kubernetes / Kafka?
- **Cost Effectiveness**: Runs comfortably on AWS Free Tier or a single `t3.small` / `t3.medium` instance ($\sim \$15$/month) instead of a \$150+/month managed EKS cluster with NAT gateways.
- **Maintainability & Zero-Drift**: Clean Docker Compose orchestration eliminates Kubernetes manifest sprawl and service mesh overhead.
- **Fast Startup & Deterministic Boot**: Container stack boots in under 30 seconds with automatic health checks and systemd failure recovery.

---

## 2. Infrastructure Specifications

| Component | AWS Resource | Port / Protocol | Security Ingress |
| :--- | :--- | :--- | :--- |
| **Public Entry** | AWS Elastic IP (EIP) | 80 (HTTP), 443 (HTTPS) | `0.0.0.0/0` (Public) |
| **Frontend** | Nginx Container | 80, 443 | Routed from Host |
| **Backend** | FastAPI Container (Uvicorn) | 8000 (Internal) | **Internal only** (`phishintel-cloud-network`) |
| **Database** | PostgreSQL 16 Alpine | 5432 (Internal) | **Internal only** (`phishintel-cloud-network`) |
| **Host VM** | EC2 `t3.medium` (Amazon Linux 2023) | 22 (SSH) | Restrict to Admin IP |

> [!IMPORTANT]
> **Network Security Best Practice**: Neither the FastAPI backend (port 8000) nor the PostgreSQL database (port 5432) expose host ports to the public internet. All public web traffic must enter through the Nginx reverse proxy.

---

## 3. AWS Deployment Options

### Method A: Automated 1-Click AWS CloudFormation (Recommended)

The repository provides a complete Infrastructure-as-Code template at [`deploy/aws/cloudformation.yml`](../deploy/aws/cloudformation.yml).

#### Option 1: Via AWS CLI
```bash
aws cloudformation create-stack \
  --stack-name PhishIntel-Production \
  --template-body file://deploy/aws/cloudformation.yml \
  --parameters ParameterKey=InstanceType,ParameterValue=t3.medium \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

To monitor stack deployment:
```bash
aws cloudformation describe-stacks \
  --stack-name PhishIntel-Production \
  --query 'Stacks[0].StackStatus'
```

To retrieve the live public endpoints:
```bash
aws cloudformation describe-stacks \
  --stack-name PhishIntel-Production \
  --query 'Stacks[0].Outputs'
```

#### Option 2: Via AWS Management Console
1. Log in to the [AWS CloudFormation Console](https://console.aws.amazon.com/cloudformation/).
2. Click **Create Stack** $\rightarrow$ **With new resources (standard)**.
3. Choose **Upload a template file** and select `deploy/aws/cloudformation.yml`.
4. Enter Stack Name (`PhishIntel-Production`) and select instance size (`t3.medium`).
5. Click **Next** through default options, check the IAM acknowledgment, and click **Submit**.
6. Within 3–4 minutes, navigate to the **Outputs** tab to view your live **ApplicationURL** and **APIHealthCheck**.

---

### Method B: Manual EC2 Launch with Cloud-Init Script

If launching an EC2 instance manually from the AWS Console:
1. Launch an EC2 Instance with **Amazon Linux 2023** or **Ubuntu 22.04 LTS**.
2. Select Instance Type: `t3.small` or `t3.medium`.
3. In **Network Settings**, allow:
   - HTTP (port 80) from `0.0.0.0/0`
   - HTTPS (port 443) from `0.0.0.0/0`
   - SSH (port 22) from your IP
4. Expand **Advanced Details** $\rightarrow$ **User Data**, and paste the contents of [`deploy/aws/user_data.sh`](../deploy/aws/user_data.sh).
5. Click **Launch Instance**. The server will automatically install Docker, clone the repository, and start the production stack on boot.

---

### Method C: AWS App Runner / ECS Fargate Serverless

For teams requiring managed serverless container infrastructure:
- Task Definition: [`deploy/aws/ecs-task-definition.json`](../deploy/aws/ecs-task-definition.json).
- Connects containerized backend and frontend to an **Amazon RDS PostgreSQL** instance within a private VPC subnet.

---

## 4. Production Orchestration Files

1. **[`docker-compose.prod.yml`](../docker-compose.prod.yml)**:
   - Configures `postgres`, `backend`, and `frontend` with `restart: always`.
   - Uses health check dependency chaining (`service_healthy`).
   - Mounts persistent Docker volumes (`postgres_prod_data` and `app_logs`).
2. **[`frontend/nginx.conf`](../frontend/nginx.conf)**:
   - Serves built React Vite SPA with client-side HTML5 history routing (`try_files $uri /index.html`).
   - Reverse proxies `/predict`, `/health`, `/stats`, `/history`, `/performance`, `/model/` to `http://backend:8000`.
3. **[`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml)**:
   - Automated CI/CD pipeline:
     - Stage 1: Quality Assurance & Pytest Suite.
     - Stage 2: Production Docker image build & container smoke test.
     - Stage 3: Automated SSH deployment to AWS EC2 instance.
4. **[`scripts/deploy_aws.py`](../scripts/deploy_aws.py)**:
   - Python CLI utility to verify pre-flight checklists and perform automated public health verification.

---

## 5. Live Public Verification & Testing

Once deployed on AWS, run the automated verification CLI:

```bash
python scripts/deploy_aws.py --verify http://<YOUR_AWS_PUBLIC_IP>
```

Or verify manually via curl:

```bash
# 1. Verify Public Health Endpoint
curl -s http://<YOUR_AWS_PUBLIC_IP>/health

# 2. Test Real-Time Public Inference
curl -s -X POST http://<YOUR_AWS_PUBLIC_IP>/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'

# 3. Test Subsystem Performance Telemetry
curl -s http://<YOUR_AWS_PUBLIC_IP>/performance

# 4. View Interactive OpenAPI Documentation
open http://<YOUR_AWS_PUBLIC_IP>/docs
```
