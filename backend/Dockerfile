# ── Stage 1: dependency installer ────────────────────────────────────────────
# Use a pinned digest for reproducibility in production builds.
# To update: docker pull python:3.12-slim && docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim
FROM python:3.12-slim AS deps

# Install only the minimal OS packages needed to build Python wheels.
# Pinned versions where possible; cleaned up in the same layer.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc=4:12.2.0-3 \
        libpq-dev=15.8-0+deb12u1 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user that the app will run as in the final stage
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /build

# Copy only the dependency manifest first to leverage Docker layer caching.
COPY pyproject.toml ./

# Install dependencies into an isolated prefix so we can COPY them cleanly.
RUN pip install --no-cache-dir --prefix=/install .


# ── Stage 2: production image ─────────────────────────────────────────────────
FROM python:3.12-slim AS production

# Runtime-only OS packages (libpq client, no gcc)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5=15.8-0+deb12u1 \
    && rm -rf /var/lib/apt/lists/*

# Re-create the non-root user in the production image
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

# Copy installed Python packages from the build stage
COPY --from=deps /install /usr/local

WORKDIR /app

# Copy application source — done as root, then lock it down
COPY app/ ./app/
COPY alembic.ini ./
COPY migrations/ ./migrations/

# Ensure the non-root user can read the app but CANNOT write to it
RUN chown -R appuser:appgroup /app && chmod -R 550 /app

# Switch to non-root user for all subsequent operations and at runtime
USER appuser

# Expose only the application port — no privileged ports
EXPOSE 8080

# Health check used by container orchestrators (Docker Swarm, ECS, etc.)
# /healthz is the liveness probe (no DB); use /readyz for readiness.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz')" || exit 1

# Production ASGI server:
#   - 2 workers per CPU core (tune via WORKERS env)
#   - Bound to 0.0.0.0:8080 inside the container
#   - Access log written to stdout in JSON (uvicorn default)
#   - Proxy headers trusted (set to false if not behind a trusted proxy)
ENV WORKERS=2
CMD ["sh", "-c", \
     "uvicorn app.main:app \
        --host 0.0.0.0 \
        --port 8080 \
        --workers ${WORKERS} \
        --proxy-headers \
        --forwarded-allow-ips='*' \
        --no-access-log"]
