# Sentinel Gateway Dockerfile
# Multi-stage build for optimized production image

# ==================== Builder Stage ====================
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip wheel setuptools && \
    pip install --no-cache-dir -r requirements.txt


# Download spaCy model for PII detection via pip (more reliable)
RUN pip install --no-cache-dir https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl

# ==================== Production Stage ====================
FROM python:3.11-slim as production

LABEL maintainer="Sentinel Team"
LABEL version="1.0.0"
LABEL description="Sentinel: Enterprise AI Governance Gateway"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH" \
    SENTINEL_HOST="0.0.0.0" \
    SENTINEL_PORT="8000"

# Create non-root user for security
RUN groupadd --gid 1000 sentinel && \
    useradd --uid 1000 --gid sentinel --shell /bin/bash --create-home sentinel

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy spaCy model
# COPY --from=builder /opt/venv/lib/python3.11/site-packages/en_core_web_sm /opt/venv/lib/python3.11/site-packages/en_core_web_sm

# Copy application code
COPY --chown=sentinel:sentinel app/ ./app/

# Switch to non-root user
USER sentinel

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
