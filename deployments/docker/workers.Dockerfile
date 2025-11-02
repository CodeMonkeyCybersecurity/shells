# Shells Python Worker Service Dockerfile
# Builds Docker image for Python-based scanners (IDORD, GraphCrawler)
# with Redis Queue (RQ) integration

FROM python:3.12-slim

LABEL maintainer="Code Monkey Cybersecurity"
LABEL description="Shells Python Worker Service with IDORD and GraphCrawler scanners"
LABEL version="2.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Git submodules (IDORD and GraphCrawler)
# These are already cloned via git submodule
COPY workers/tools/idord /app/tools/idord
COPY workers/tools/graphcrawler /app/tools/graphcrawler

# Copy worker service code
COPY workers/service /app/service
COPY workers/requirements.txt /app/requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Install IDORD dependencies
RUN if [ -f /app/tools/idord/requirements.txt ]; then \
        pip install --no-cache-dir -r /app/tools/idord/requirements.txt; \
    fi

# Install GraphCrawler dependencies
RUN if [ -f /app/tools/graphcrawler/requirements.txt ]; then \
        pip install --no-cache-dir -r /app/tools/graphcrawler/requirements.txt; \
    fi

# Create directory for scan outputs
RUN mkdir -p /tmp/scan-outputs && chmod 777 /tmp/scan-outputs

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose API port
EXPOSE 8000

# Set Python path to include service directory
ENV PYTHONPATH=/app:$PYTHONPATH

# Default command: Run FastAPI server
# For RQ workers, override with: rq worker shells-scanners
CMD ["uvicorn", "service.main_rq:app", "--host", "0.0.0.0", "--port", "8000"]
