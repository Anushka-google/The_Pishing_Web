# Phishing Detection & Risk Intelligence Platform
# Production Backend Container Image (FastAPI + ML Engine)

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies for networking and healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application directories
COPY api/ /app/api/
COPY src/ /app/src/
COPY database/ /app/database/
COPY models/ /app/models/
COPY data/processed/ /app/data/processed/

# Expose FastAPI port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start production server
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
