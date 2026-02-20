# SecureFlow AI — Multi-stage Dockerfile
# Python 3.12 + Semgrep (SAST) + Node.js (MCP servers)

# ── Stage 1: Dependencies ──────────────────────────────────────
FROM python:3.12-slim AS deps

WORKDIR /app

# System deps for Semgrep and Node.js (for MCP)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir ".[dashboard]" \
    && pip install --no-cache-dir semgrep

# ── Stage 2: Runtime ───────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Labels
LABEL maintainer="SecureFlow AI" \
      description="AI-powered multi-agent DevSecOps intelligence platform" \
      version="0.1.0"

WORKDIR /app

# System deps for runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r secureflow \
    && useradd -r -g secureflow -d /app -s /sbin/nologin secureflow

# Copy installed packages from deps stage
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

# Copy application code (NO .env or secrets)
COPY src/ ./src/
COPY pyproject.toml README.md ./

# Install the project itself (deps already copied from build stage)
RUN pip install --no-cache-dir --no-deps .

# Create npm cache dir for non-root user (needed for MCP server via npx)
RUN mkdir -p /app/.npm /tmp/semgrep \
    && chown -R secureflow:secureflow /app /tmp/semgrep

# Non-root user
USER secureflow

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
