# Phase 21: Multi-Container Docker Orchestration

## Overview
Phase 21 packages the complete platform into isolated, reproducible container images orchestrated via **Docker Compose**:
1. **`postgres`:** Relational database storage with persistent named volumes and health monitoring.
2. **`backend`:** FastAPI machine learning engine (running with Python 3.11, SHAP TreeExplainer, and C-accelerated tree ensembles).
3. **`frontend`:** Production-optimized React SPA compiled into static assets and served via Alpine Nginx with automated reverse-proxying.

---

## Architectural Topology

```
                  Client Browser
                        │
                        ▼ (Port 3000)
            ┌───────────────────────┐
            │   frontend (Nginx)    │
            └───────────┬───────────┘
                        │
       Reverse Proxy    │ (Proxy pass internal port 8000)
                        ▼
            ┌───────────────────────┐
            │   backend (FastAPI)   │
            └───────────┬───────────┘
                        │
      SQLAlchemy ORM    │ (Internal port 5432)
                        ▼
            ┌───────────────────────┐
            │ postgres:16-alpine   │
            │ (Volume: postgres_data│
            └───────────────────────┘
```

---

## Services Specification

| Service | Base Image | Internal Port | Host Port | Healthcheck |
| :--- | :--- | :---: | :---: | :--- |
| **`postgres`** | `postgres:16-alpine` | `5432` | `5432` | `pg_isready -U postgres -d phishing_db` |
| **`backend`** | `python:3.11-slim` | `8000` | `8000` | `curl -f http://localhost:8000/health` |
| **`frontend`** | `node:20-alpine` (builder)<br>`nginx:alpine` (serve) | `80` | `3000` | Process state |

---

## Single-Command Local Launch

To run the entire system reproducibly anywhere:

```bash
docker compose up --build -d
```

### Verification & Endpoints
- **Frontend Dashboard:** [http://localhost:3000](http://localhost:3000)
- **FastAPI OpenAPI Swagger:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **FastAPI Health Verification:** [http://localhost:8000/health](http://localhost:8000/health)

### Teardown
```bash
docker compose down
```
To also purge database volumes:
```bash
docker compose down -v
```
