# SecureVault — Production Deployment & Operations Guide

This guide details the requirements, configuration, containerization, and orchestration steps to deploy the **SecureVault API** and background infrastructure into production high-security environments.

---

## 1. Architecture Overview

```
                        ┌────────────────────────────────────────────────────────┐
                        │              Internet / Client Traffic                 │
                        │    (Android Client, Desktop Client, Emergency Portal)  │
                        └──────────────────────────┬─────────────────────────────┘
                                                   │ HTTPS (TLS 1.3 only, HSTS)
                                                   ▼
                        ┌────────────────────────────────────────────────────────┐
                        │             Edge / Ingress / Load Balancer             │
                        │    (Cloudflare / AWS ALB / NGINX / Caddy / Traefik)    │
                        │     - TLS Termination & Strict Certificate Pinning     │
                        │     - DDoS Mitigation & WAF                            │
                        │     - Request Size Limiting (Max 15MB for Encrypted)   │
                        └──────────────────────────┬─────────────────────────────┘
                                                   │ HTTP/2 (Private VPC)
                                                   ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Kubernetes Cluster / Container VPC                                                               │
│                                                                                                 │
│  ┌───────────────────────────────────┐               ┌───────────────────────────────────────┐  │
│  │   SecureVault FastAPI (Pod 1..N)  │               │      Alembic Migration Job            │  │
│  │   - Non-root user (UID 10001)     │               │      (Runs prior to rollout)          │  │
│  │   - Read-only root filesystem     │               └───────────────────┬───────────────────┘  │
│  │   - Structured JSON logging       │                                   │                      │
│  │   - Real-time health probes       │                                   │                      │
│  └─────────────────┬─────────────────┘                                   │                      │
│                    │                                                     │                      │
│                    ├─────────────────────────────────────────────────────┤                      │
│                    │                                                     │                      │
│                    ▼                                                     ▼                      │
│  ┌───────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │               Managed PostgreSQL 15+ (AWS RDS / GCP Cloud SQL / HA Cluster)               │  │
│  │               - asyncpg pool (Max 20 conns per pod, 30s timeout)                          │  │
│  │               - TLS encrypted in transit (sslmode=verify-full)                            │  │
│  │               - Encrypted at rest (AES-256)                                               │  │
│  └───────────────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Environment Variables & Secrets

All production settings are configured via environment variables. **SecureVault deliberately rejects starting with default or weak secrets in production (`ENVIRONMENT=production`).**

### Required Environment Variables

| Variable | Description | Production Requirement |
|---|---|---|
| `SECUREVAULT_ENVIRONMENT` | Environment mode (`production`, `staging`, `development`) | Must be set to `production`. |
| `SECUREVAULT_DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://user:pass@host:5432/securevault?ssl=require` |
| `SECUREVAULT_JWT_SECRET` | 256-bit+ HMAC secret for session access tokens | High entropy random string (min 32 bytes). |
| `SECUREVAULT_REFRESH_TOKEN_HASH_SECRET` | HMAC secret for hashing refresh tokens at rest | Independent high entropy secret. Never reuse `JWT_SECRET`. |
| `SECUREVAULT_STEP_UP_HASH_SECRET` | HMAC secret for step-up challenge tokens | Independent high entropy secret. |
| `SECUREVAULT_GOOGLE_WEB_CLIENT_ID` | OAuth 2.0 Web Client ID from Google Cloud Console | Pinned to your production Google Cloud project ID. |
| `SECUREVAULT_JWT_ISSUER` | JWT issuer claim (`iss`) | `securevault-api` |
| `SECUREVAULT_JWT_AUDIENCE` | JWT audience claim (`aud`) | `securevault-android` |
| `WORKERS` | Number of Uvicorn worker processes | Recommended: `2` to `4` per CPU core. |

### Generating Cryptographic Secrets

Use the helper script to generate all three secrets in one step:

```bash
python scripts/gen_secrets.py
```

This prints three fresh 48-byte (384-bit) URL-safe random secrets labelled with
their environment variable names. Copy them directly into your `backend/.env`.

Alternatively, generate each one manually:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Run this command separately for:
1. `SECUREVAULT_JWT_SECRET`
2. `SECUREVAULT_REFRESH_TOKEN_HASH_SECRET`
3. `SECUREVAULT_STEP_UP_HASH_SECRET`

---

## 3. Production Security Guardrails

The application enforces strict defense-in-depth controls:
1. **Startup Secret Verification (`assert_production_secrets`):**
   - The application inspects all secrets during boot.
   - If `SECUREVAULT_ENVIRONMENT=production`, any default strings (`CHANGE_ME`, `REPLACE_WITH_...`, `secret`, `test`) or secrets shorter than 32 characters abort the process immediately with an exit code of `1`.
   - SQLite databases are forbidden in production; an explicit PostgreSQL async connection is mandatory.
2. **Interactive Documentation Disabled:**
   - Swagger UI (`/docs`) and ReDoc (`/redoc`) endpoints are set to `None` in production to prevent schema disclosure to unauthorized actors.
3. **Least Privilege Container Runtime:**
   - Runs under dedicated non-root user `appuser` (UID 10001, GID 10001).
   - Application code is mounted read-only (`chmod 550`).
   - Container root filesystem is mounted read-only (`readOnlyRootFilesystem: true`).
4. **Zero-Knowledge Architecture:**
   - The backend stores **only opaque encrypted ciphertext envelopes**, salt values, public identity signatures, and nonces.
   - The server never receives Master Passwords, Vault Root Keys (VRKs), user PINs, or biometric secrets.

---

## 4. Docker Deployment

### Building the Production Image

The multi-stage `Dockerfile` minimizes attack surface by compiling wheels in a builder stage and excluding build toolchains (`gcc`, `make`) from the final runtime image:

```bash
cd backend
docker build -t securevault-api:latest .
```

### Running with Docker Compose

Create a `docker-compose.prod.yml` file:

```yaml
version: "3.8"

services:
  db:
    image: postgres:15-alpine
    restart: always
    environment:
      POSTGRES_DB: securevault
      POSTGRES_USER: securevault_app
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - internal_net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U securevault_app -d securevault"]
      interval: 10s
      timeout: 5s
      retries: 5

  api:
    image: securevault-api:latest
    restart: always
    depends_on:
      db:
        condition: service_healthy
    env_file:
      - .env.production
    ports:
      - "127.0.0.1:8080:8080"
    networks:
      - internal_net
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

volumes:
  postgres_data:

secrets:
  db_password:
    file: ./secrets/db_password.txt

networks:
  internal_net:
    internal: true
```

---

## 5. Kubernetes Orchestration

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: securevault-api
  namespace: securevault
  labels:
    app.kubernetes.io/name: securevault-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: securevault-api
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        app.kubernetes.io/name: securevault-api
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
      containers:
        - name: api
          image: securevault-api:0.1.0
          imagePullPolicy: IfNotPresent
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
          envFrom:
            - secretRef:
                name: securevault-secrets
            - configMapRef:
                name: securevault-config
          ports:
            - containerPort: 8080
              name: http
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 15
            timeoutSeconds: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 512Mi
```

### Pre-Deployment Database Migration Job

Run database migrations automatically as part of the CI/CD deployment pipeline before traffic shifts to the new pods:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: securevault-migration
  namespace: securevault
spec:
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: OnFailure
      containers:
        - name: alembic
          image: securevault-api:0.1.0
          command: ["alembic", "upgrade", "head"]
          envFrom:
            - secretRef:
                name: securevault-secrets
            - configMapRef:
                name: securevault-config
```

---

## 6. Zero-Downtime Migration Policy

1. **Additive Schema Changes:**
   - All migrations must be backward-compatible (e.g. adding nullable columns, creating new tables).
   - Never drop or rename columns in the same release that stops using them.
2. **Two-Phase Deployments:**
   - **Phase 1:** Apply migration with Alembic (`alembic upgrade head`). Old application pods continue running.
   - **Phase 2:** Roll out new application image (`kubectl rollout restart deployment/securevault-api`).
   - **Phase 3:** Drop unused legacy columns in a subsequent release.

---

## 7. Health Checks, Probes & Observability

### Endpoints
- **Liveness Probe: `GET /healthz`**
  - Returns HTTP 200 `{"status": "ok"}` without database queries.
  - Used by orchestrators to restart deadlocked workers.
- **Readiness Probe: `GET /readyz`**
  - Executes a ping query against PostgreSQL (`SELECT 1`).
  - Returns HTTP 200 `{"status": "ready"}` if healthy; HTTP 503 if the database is unreachable.
  - Removes failing instances from traffic routing without killing the container.

### Structured Logging
All logs are emitted to `stdout` as single-line JSON objects with timestamps, log level, event name, and contextual attributes:
```json
{"timestamp": "2026-10-25T09:00:00.000Z", "level": "INFO", "event": "securevault_api_started", "environment": "production"}
```
Ensure log ingestion pipelines (Datadog, FluentBit, Grafana Loki, AWS CloudWatch) parse these structured events.

---

## 8. Backup & Disaster Recovery

1. **Continuous PostgreSQL WAL Archiving:**
   - Point-in-time recovery (PITR) enabled via pgBackRest, WAL-G, or managed cloud snapshots (30-day retention).
2. **Nightly Encrypted Logical Dumps:**
   ```bash
   pg_dump -Fc -U securevault_app securevault | gpg --encrypt -r backup-key@securevault.app > securevault_backup_$(date +%F).dump.gpg
   ```
3. **Disaster Recovery Drill:**
   - Perform test restores from backup once every quarter into an isolated test namespace to verify database integrity.
