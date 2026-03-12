# ═══════════════════════════════════════════════════════
#  MAESTRIA-Lite — Multi-Stage Docker Build
#  IEC 62304 Compliant | Minimal Attack Surface
# ═══════════════════════════════════════════════════════

# ── Stage 1: Builder ──
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY maestria/ maestria/

RUN pip install --no-cache-dir --prefix=/install .

# ── Stage 2: Production ──
FROM python:3.12-slim AS production

LABEL maintainer="MAESTRIA-Lite Contributors"
LABEL org.opencontainers.image.title="maestria-lite"
LABEL org.opencontainers.image.description="Industrial Diagnostic Middleware"
LABEL org.opencontainers.image.version="2.4.1"

# Security: run as non-root
RUN groupadd -r maestria && useradd -r -g maestria -d /app maestria

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local
COPY config/ config/
COPY scripts/ scripts/

# Set ownership
RUN chown -R maestria:maestria /app

USER maestria

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Expose ports
EXPOSE 8080 9090

# Environment
ENV MAESTRIA_ENV=production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["maestria-lite"]
CMD ["start", "--config", "config/maestria.yaml"]
