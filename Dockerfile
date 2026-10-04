# Phishing Detection & Risk Intelligence Platform
# Production Unified Container Image (FastAPI Backend + React Frontend Bundle)

# Stage 1: Build Frontend React Bundle
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Production Python Backend + Embedded Static Frontend
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies for networking and postgres
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code and models
COPY api/ /app/api/
COPY src/ /app/src/
COPY database/ /app/database/
COPY models/ /app/models/
COPY data/processed/ /app/data/processed/

# Copy built frontend bundle from Stage 1
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# Expose default port (Render will inject dynamic $PORT)
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Start unified production server (respects Render's dynamic $PORT)
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
